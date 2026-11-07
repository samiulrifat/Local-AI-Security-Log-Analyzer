"""Compares a saved report against the answers I worked out by hand from the log.
This file is only for measuring accuracy. The app never reads expected.json.

Usage: python eval/score.py report.json Cultive8_Workspace_Agrigen_Server.log
"""
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
expected = json.loads((Path(__file__).parent / "expected.json").read_text())[sys.argv[2]]
findings = {f["actor"]: f for f in report["findings"]}

hits = 0
for actor, want in expected["attackers"].items():
    found = findings.get(actor)
    if not found:
        print(f"MISSED     {actor}")
        continue
    hits += 1
    notes = []
    if want["must_mention"].lower() not in found["attack_type"].lower():
        notes.append(f"named '{found['attack_type']}'")
    if found["severity"] not in want["severity"]:
        notes.append(f"severity {found['severity']}, wanted {want['severity']}")
    all_lines = {n for stage in found["evidence"] for n in stage["lines"]}
    missing = [n for n in want["lines"] if n not in all_lines]
    if missing:
        notes.append(f"missing lines {missing}")
    print(f"FOUND      {actor} [{found['found_by']}] {'; '.join(notes) or 'all good'}")

false_alarms = [a for a in findings if a in expected["not_attackers"]]
extra = [a for a in findings if a not in expected["attackers"] and a not in expected["not_attackers"]]
for actor in false_alarms:
    print(f"FALSE ALARM {actor}")
for actor in extra:
    print(f"EXTRA      {actor}: {findings[actor]['attack_type']}")

print(f"\nfound {hits}/{len(expected['attackers'])} attackers, {len(false_alarms) + len(extra)} false alarms")
