"""The background job that runs an analysis from start to finish."""
import json
import os
import queue
import threading
import time
import traceback

from . import db, prompts, report, tracker
from .config import CONTEXT_SIZE, MAX_ATTEMPTS, REPLY_TOKENS, SAFETY_TOKENS, SAVED_FACTS_TOKENS, USE_RULES
from .llm import ModelError, read_memory_mb
from .logfile import actor_of, group_for_prompt, read_entries
from .replies import check_events, parse_json
from .splitter import split_log

RUNNING_STATES = ("queued", "splitting", "analyzing", "reporting")


class Cancelled(Exception):
    pass


class Worker:
    def __init__(self, server):
        self.server = server
        self.jobs = queue.Queue()
        self.current = None
        threading.Thread(target=self.loop, daemon=True).start()

    def add(self, job_id):
        self.jobs.put(job_id)

    def resume_unfinished(self):
        """Anything still marked as running when we start was interrupted by a restart."""
        for job_id in db.jobs_with_status("cancelling"):
            db.update_job(job_id, status="cancelled")
        for job_id in db.jobs_with_status(*RUNNING_STATES):
            db.update_job(job_id, status="queued")
            self.add(job_id)

    def loop(self):
        while True:
            job_id = self.jobs.get()
            self.current = job_id
            try:
                self.run(job_id)
            except Cancelled:
                db.update_job(job_id, status="cancelled", finished=time.time())
            except Exception as error:
                traceback.print_exc()
                db.update_job(job_id, status="failed", error=str(error), finished=time.time())
            self.current = None

    def run(self, job_id):
        job = db.get_job(job_id)
        if job and job["status"] == "cancelling":
            raise Cancelled()
        if not job or job["status"] != "queued":
            return

        # the model might still be loading if someone clicks Analyze right away
        self.server.ready.wait(timeout=180)
        if job["model"] != self.server.model_key or not self.server.is_running():
            self.server.switch_model(job["model"])

        if not job["started"]:
            db.update_job(job_id, started=time.time())

        parts = db.get_parts(job_id)
        if not parts:
            parts = self.plan_parts(job)

        db.update_job(job_id, status="analyzing")
        job = db.get_job(job_id)
        state = json.loads(job["state"]) if job["state"] else tracker.new_state()

        for part in parts:
            self.stop_if_cancelled(job_id)
            if part["status"] == "done":
                continue
            self.analyze_part(job, part, state)

        self.stop_if_cancelled(job_id)
        db.update_job(job_id, status="reporting")
        final = self.make_report(job, state)
        db.update_job(job_id, status="done", report=json.dumps(final), finished=time.time())

    def stop_if_cancelled(self, job_id):
        if db.get_job(job_id)["status"] == "cancelling":
            raise Cancelled()

    def plan_parts(self, job):
        db.update_job(job["id"], status="splitting")
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                return self.split_job(job)
            except ModelError:
                if attempt == MAX_ATTEMPTS:
                    raise
                time.sleep(2 * attempt)

    def split_job(self, job):
        # measure the fixed part of the prompt with an empty log, whatever is
        # left over after the reply and saved facts is the room for log text
        empty = self.server.build_prompt(prompts.PART_SYSTEM, prompts.part_user_message(""))
        fixed = self.server.count_tokens(empty)
        log_budget = CONTEXT_SIZE - fixed - SAVED_FACTS_TOKENS - REPLY_TOKENS - SAFETY_TOKENS

        parts, total_lines, total_tokens = split_log(job["path"], self.server.count_tokens, log_budget)
        db.save_parts(job["id"], parts)
        db.update_job(job["id"], total_lines=total_lines, total_tokens=total_tokens, log_budget=log_budget)
        return db.get_parts(job["id"])

    def analyze_part(self, job, part, state):
        job_id = job["id"]
        db.update_part(job_id, part["idx"], status="running")

        entries = list(read_entries(job["path"], part["offset"], part["first_line"], part["last_line"]))
        current_ids = {actor_of(e) for e in entries}
        use_rules = bool(job["use_rules"])
        reply = result = None
        attempts = 0

        try:
            # facts come from earlier parts only, so build them before this part is counted
            facts = tracker.facts_for_model(state, current_ids, self.server.count_tokens,
                                            SAVED_FACTS_TOKENS, use_rules)
            log_text, line_map = group_for_prompt(entries, facts)
            for entry in entries:
                tracker.note_entry(state, entry)

            # a part with nothing but routine page views doesn't need the model at all
            if line_map:
                reply, result, attempts = self.ask(job_id, "part", f"part {part['idx'] + 1}", prompts.PART_SYSTEM,
                                                   prompts.part_user_message(log_text), prompts.part_grammar(list(line_map)))
        except ModelError as error:
            # keep going. the rule checks still see this part and it can be retried later
            for entry in entries:
                tracker.note_entry(state, entry)
            db.save_part_result(job_id, part["idx"], [], state, status="failed", error=str(error),
                                attempts=MAX_ATTEMPTS)
            return

        result = result or {"prompt_tokens": 0, "reply_tokens": 0, "seconds": 0}
        events, rejected = check_events(reply, entries, line_map) if reply else ([], 0)
        tracker.note_model_events(state, events)
        db.save_part_result(job_id, part["idx"], events, state, status="done", error=None,
                            prompt_tokens=result["prompt_tokens"], reply_tokens=result["reply_tokens"],
                            seconds=result["seconds"], attempts=attempts, events=len(events), rejected=rejected)

    def ask(self, job_id, kind, label, system, user_message, grammar, max_reply=REPLY_TOKENS):
        """One model question with retries. Returns (parsed reply, result, attempts)."""
        last_error = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            # same prompt and temperature 0 gives the same bad answer, so loosen it on retries
            temperature = 0.0 if attempt == 1 else 0.3
            try:
                prompt = self.server.build_prompt(system, user_message)
                room = CONTEXT_SIZE - self.server.count_tokens(prompt) - SAFETY_TOKENS
                max_tokens = min(max_reply, room)
                if max_tokens < 64:
                    raise ModelError("prompt too large for the context window")
                result = self.server.complete(prompt, grammar, max_tokens, temperature)
            except ModelError as error:
                last_error = str(error)
                db.log_call(job_id, kind, label, ok=False, note=last_error)
                time.sleep(2 * attempt)
                continue

            reply = parse_json(result["text"])
            if reply is not None:
                note = "reply was cut off, kept the complete items" if result["cut_off"] else None
                db.log_call(job_id, kind, label, result, note=note)
                return reply, result, attempt

            last_error = "reply was not valid JSON"
            db.log_call(job_id, kind, label, result, ok=False, note=last_error)

        raise ModelError(last_error or "model call failed")

    def make_report(self, job, state):
        job_id = job["id"]
        use_rules = bool(job["use_rules"])
        parts = db.get_parts(job_id)
        count = self.server.count_tokens

        findings = []
        reviewed = []
        for actor in report.actors_to_review(state, use_rules):
            self.stop_if_cancelled(job_id)
            stages = report.build_stages(actor, parts, use_rules)
            if not stages:
                continue
            verdict = self.get_verdict(job, actor, stages, count, use_rules)
            finding = report.build_finding(actor, verdict, stages, use_rules)
            if finding:
                findings.append(finding)
            else:
                reviewed.append({"label": f"{actor['id']}: flagged during analysis, cleared on review",
                                 "lines": [n for stage in stages for n in stage["lines"]],
                                 "reason": (verdict or {}).get("reason") or "No supporting evidence."})
        findings.sort(key=report.finding_sort_key)

        reviewed += self.review_errors(job_id, state, findings)
        for actor in state["actors"].values():
            if actor["model"] and report.looks_like_typo(actor):
                lines = actor["signals"].get("failed_login", []) + actor["signals"].get("login_success", [])
                reviewed.append({"label": f"{actor['id']}: a few failed logins, then normal use",
                                 "lines": lines, "reason": "Looks like a mistyped password, not an attack."})

        failed = [p for p in parts if p["status"] == "failed"]
        return {
            "summary": report.write_summary(findings),
            "findings": findings,
            "reviewed": reviewed,
            "coverage": {
                "parts": len(parts),
                "failed_parts": [{"part": p["idx"] + 1, "first_line": p["first_line"], "last_line": p["last_line"],
                                  "error": p["error"]} for p in failed],
            },
            "rules_used": use_rules,
            "peak_ram_mb": self.server.memory_mb()[1] + read_memory_mb(os.getpid())[1],
        }

    def get_verdict(self, job, actor, stages, count, use_rules):
        job_id = job["id"]
        key = f"verdict:{actor['id']}"
        saved = db.get_answer(job_id, key)
        if saved:
            return saved

        facts = report.describe_actor(actor, stages, use_rules)
        fixed = count(self.server.build_prompt(prompts.VERDICT_SYSTEM,
                                               prompts.verdict_user_message(actor["id"], facts, "")))
        budget = CONTEXT_SIZE - fixed - 200 - SAFETY_TOKENS
        samples = report.sample_lines(job["path"], stages, count, budget)
        try:
            verdict, _, _ = self.ask(job_id, "verdict", actor["id"], prompts.VERDICT_SYSTEM,
                                     prompts.verdict_user_message(actor["id"], facts, samples),
                                     prompts.VERDICT_GRAMMAR, max_reply=200)
        except ModelError:
            return None
        db.save_answer(job_id, key, verdict)
        return verdict

    def review_errors(self, job_id, state, findings):
        """One call to sort the normal looking errors. If it fails they are still listed."""
        groups = report.top_error_groups(state, findings)
        if not groups:
            return []
        answers = {}
        saved = db.get_answer(job_id, "errors")
        if saved is None:
            try:
                reply, _, _ = self.ask(job_id, "errors", "error groups", prompts.ERRORS_SYSTEM,
                                       report.errors_message(groups, state["notes"]),
                                       prompts.errors_grammar(len(groups)), max_reply=320)
                saved = reply
                db.save_answer(job_id, "errors", saved)
            except ModelError:
                saved = {}
        for item in saved.get("groups", []):
            if isinstance(item, dict):
                answers[item.get("n")] = item

        reviewed = []
        for number, group in enumerate(groups, start=1):
            answer = answers.get(number, {})
            reviewed.append({"label": group["label"], "lines": group["lines"],
                             "reason": report.error_reason(answer)})
        return reviewed


def new_job_options(model):
    return {"model": model, "use_rules": int(USE_RULES)}
