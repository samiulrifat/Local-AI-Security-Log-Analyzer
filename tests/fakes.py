"""A stand-in for llama-server so tests run in a second with no model."""
import threading

from app.llm import ModelError


class FakeServer:
    """replies is a list of things to return, in order. A string is used as the
    model's text, an exception is raised. When it runs out it answers empty."""

    model_key = "fake"

    def __init__(self, replies=None):
        self.replies = list(replies or [])
        self.prompts = []
        self.ready = threading.Event()
        self.ready.set()

    def memory_mb(self):
        return 100, 200

    def is_running(self):
        return True

    def switch_model(self, key):
        self.model_key = key

    def count_tokens(self, text):
        # close enough for tests, roughly one token per four characters
        return max(1, len(text) // 4)

    def build_prompt(self, system, user):
        return system + "\n" + user

    def complete(self, prompt, grammar, max_tokens, temperature=0.0):
        self.prompts.append(prompt)
        reply = self.replies.pop(0) if self.replies else '{"groups":[]}'
        if isinstance(reply, Exception):
            raise reply
        return {"text": reply, "prompt_tokens": self.count_tokens(prompt), "reply_tokens": 10,
                "seconds": 0.1, "cut_off": False}


TIMEOUT = ModelError("model call timed out")
