#!/usr/bin/env python
"""Runs an analysis from the command line, handy for testing prompts without the
web page. Usage: .venv/bin/python scripts/analyze.py file.log [--model qwen-2b]"""
import argparse
import json
import shutil
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import db  # noqa: E402
from app.config import DEFAULT_MODEL, UPLOAD_DIR, USE_RULES  # noqa: E402
from app.llm import LlamaServer  # noqa: E402
from app.worker import Worker  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("file")
parser.add_argument("--model", default=DEFAULT_MODEL)
parser.add_argument("--out", help="save the report json here")
args = parser.parse_args()

db.init()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
job_id = uuid.uuid4().hex[:12]
path = UPLOAD_DIR / f"{job_id}.log"
shutil.copy(args.file, path)
db.add_job(job_id, Path(args.file).name, path, path.stat().st_size)
db.update_job(job_id, status="queued", model=args.model, use_rules=int(USE_RULES))

server = LlamaServer(args.model)
server.start()
worker = Worker(server)
worker.add(job_id)

started = time.time()
done_parts = -1
while True:
    time.sleep(2)
    job = db.get_job(job_id)
    parts = db.get_parts(job_id)
    finished = [p for p in parts if p["status"] in ("done", "failed")]
    if len(finished) != done_parts:
        done_parts = len(finished)
        print(f"[{time.time() - started:6.0f}s] {job['status']} {done_parts}/{len(parts)} parts", flush=True)
    if job["status"] in ("done", "failed", "cancelled"):
        break

peak = server.memory_mb()[1]
server.stop()

print(f"status={job['status']} error={job['error']}")
print(f"seconds={time.time() - started:.0f} model_peak_mb={peak} tokens={job['total_tokens']} parts={len(parts)}")
print("stats", db.call_stats(job_id))
for part in parts:
    print(f"part {part['idx'] + 1}: L{part['first_line']}-L{part['last_line']} "
          f"prompt={part['prompt_tokens']} reply={part['reply_tokens']} {part['seconds']}s "
          f"events={part['events']} rejected={part['rejected']} {part['status']}")
for event in db.get_events(job_id):
    print("  event", event["part_idx"] + 1, event["actor"], event["type"], event["lines"], event["reason"])

if job["report"]:
    final = json.loads(job["report"])
    print("\nSUMMARY:", final["summary"])
    for f in final["findings"]:
        print(f"\n[{f['severity']}] {f['actor']} {f['attack_type']} ({f['found_by']}, {f['certainty']}) parts {f['parts']}")
        print("  reason:", f["reason"])
        print("  action:", f["action"])
        for stage in f["evidence"]:
            print(f"  - {stage['label']}: {stage['lines']}")
    print("\nREVIEWED, NOT FLAGGED:")
    for item in final["reviewed"]:
        print(f"  {item['label']} {item['lines'][:6]}: {item['reason']}")
    if args.out:
        Path(args.out).write_text(json.dumps(final, indent=2))
