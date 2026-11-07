"""Runs llama-server and talks to it. All model access goes through here."""
import os
import signal
import subprocess
import threading
import time

import httpx

from .config import (CALL_TIMEOUT, CONTEXT_SIZE, DATA_DIR, LLAMA_BIN, LLAMA_PORT, MODEL_DIR,
                     MODELS, THREADS)


class ModelError(Exception):
    """A model call failed in a way that's worth retrying."""


class LlamaServer:
    def __init__(self, model_key):
        self.model_key = model_key
        self.process = None
        self.url = f"http://127.0.0.1:{LLAMA_PORT}"
        self.http = httpx.Client(timeout=30)
        self.ready = threading.Event()  # set once the first start attempt is over

    def start(self):
        model_path = MODEL_DIR / MODELS[self.model_key]["file"]
        if not model_path.exists():
            self.ready.set()
            raise ModelError(f"Model file missing: {model_path.name}. Run scripts/setup.sh first.")

        command = [
            str(LLAMA_BIN), "-m", str(model_path),
            "--host", "127.0.0.1", "--port", str(LLAMA_PORT),
            "-c", str(CONTEXT_SIZE),   # the 2048 limit, enforced by the server too
            "-np", "1",                # one slot, one call at a time
            "-t", str(THREADS), "-tb", str(THREADS),
            "--jinja", "--no-webui",
            "--cache-ram", "0",        # no prompt cache kept in RAM
            "--ctx-checkpoints", "0",
            "--reasoning", "off",      # no thinking output, it would eat the reply budget
        ]
        DATA_DIR.mkdir(exist_ok=True)
        log_file = open(DATA_DIR / "llama-server.log", "ab")
        self.process = subprocess.Popen(command, stdout=log_file, stderr=log_file, cwd=LLAMA_BIN.parent,
                                        env={**os.environ, "LD_LIBRARY_PATH": str(LLAMA_BIN.parent)})
        try:
            self.wait_until_ready()
        finally:
            self.ready.set()

    def wait_until_ready(self, seconds=120):
        deadline = time.time() + seconds
        while time.time() < deadline:
            if self.process.poll() is not None:
                raise ModelError("llama-server exited while starting, see data/llama-server.log")
            try:
                if self.http.get(f"{self.url}/health").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        raise ModelError("llama-server took too long to start")

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process = None

    def restart(self):
        self.stop()
        self.start()

    def switch_model(self, model_key):
        self.model_key = model_key
        self.restart()

    def is_running(self):
        return self.process is not None and self.process.poll() is None

    def memory_mb(self):
        """Current and peak memory of the server process, from /proc."""
        if not self.is_running():
            return 0, 0
        return read_memory_mb(self.process.pid)

    def post(self, path, payload, timeout=30):
        """Sends a request to llama-server, starting it again first if it died."""
        if not self.is_running():
            self.start()
        try:
            response = self.http.post(f"{self.url}{path}", json=payload, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except httpx.TimeoutException as error:
            # it may still be busy with the old call, so start clean
            self.restart()
            raise ModelError("model call timed out") from error
        except httpx.ConnectError as error:
            self.restart()
            raise ModelError("could not reach llama-server") from error
        except (httpx.HTTPError, ValueError) as error:
            raise ModelError(f"llama-server error: {error}") from error

    def count_tokens(self, text):
        """Real token count from the model's own tokenizer."""
        return len(self.post("/tokenize", {"content": text, "add_special": False})["tokens"])

    def build_prompt(self, system, user):
        """Applies the model's chat template so we can count the exact prompt."""
        return self.post("/apply-template", {
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "chat_template_kwargs": {"enable_thinking": False},
        })["prompt"]

    def complete(self, prompt, grammar, max_tokens, temperature=0.0):
        """One model call. Returns the text plus token counts and timing."""
        started = time.time()
        data = self.post("/completion", {
            "prompt": prompt,
            "n_predict": max_tokens,
            "temperature": temperature,
            "grammar": grammar,
            "cache_prompt": True,
        }, timeout=CALL_TIMEOUT)
        return {
            "text": data.get("content", ""),
            "prompt_tokens": data.get("tokens_evaluated", 0),
            "reply_tokens": data.get("tokens_predicted", 0),
            "seconds": round(time.time() - started, 1),
            "cut_off": bool(data.get("truncated")) or data.get("stop_type") == "limit",
        }


def read_memory_mb(pid):
    current = peak = 0
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    current = int(line.split()[1]) // 1024
                elif line.startswith("VmHWM:"):
                    peak = int(line.split()[1]) // 1024
    except OSError:
        pass
    return current, peak
