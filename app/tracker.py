"""Keeps a running record per IP (or user, or session) across the whole file.

The model only sees one part at a time, so this is its memory. Facts from
earlier parts get passed into later calls, and at the end this is what lets us
join a failed login on line 5 to a successful one on line 240.

The patterns here describe attack techniques in general. Nothing in this file
knows about any specific log, IP or username.
"""
import re
from datetime import datetime

from .logfile import decode_url

SQLI_RE = re.compile(r"('|\")\s*(or|and)\s+\d+\s*=\s*\d+|union\s+(all\s+)?select|;\s*(select|drop|insert|update|delete)\b"
                     r"|sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|information_schema|xp_cmdshell", re.I)
TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini", re.I)
PROBE_RE = re.compile(r"/\.env|/\.git|/\.aws|/\.ssh|wp-admin|wp-login|phpmyadmin|/actuator|/server-status"
                      r"|/backup\.|\.sql$|\.bak$|/config\.(json|php|yml|yaml)|/admin\.php|/cgi-bin", re.I)
XSS_RE = re.compile(r"<script|onerror\s*=|javascript:", re.I)
PROMPT_INJECTION_RE = re.compile(r"ignore (all |any )?(previous|prior|above) (instructions|prompts?)"
                                 r"|disregard .{0,30}instructions|you are now|system prompt"
                                 r"|report (all|every)\w* .{0,30}(safe|benign)", re.I)
ADMIN_RE = re.compile(r"/admin\b", re.I)
LOGIN_RE = re.compile(r"/(auth|login|signin|session)", re.I)

BULK_DOWNLOAD_BYTES = 1_000_000
BURST_SIZE = 30      # this many requests inside BURST_SECONDS counts as a burst
BURST_SECONDS = 10
REPORTED_RATE = 100  # for logs that record their own request counter

MANY_NOT_FOUND = 10  # a browser hits the odd dead link, a scanner hits lots of them

MAX_LINES_KEPT = 300  # per signal, so a huge attack can't eat all the memory


def new_state():
    return {"actors": {}, "errors": {}, "notes": [], "last_line_seen": 0}


def new_actor(actor_id):
    return {"id": actor_id, "signals": {}, "requests": 0, "users": [], "sessions": [], "agents": [],
            "statuses": {}, "first_line": None, "last_line": None, "recent": [], "model": {}, "not_found": 0}


def add_unique(items, value, limit=10):
    if value and value not in items and len(items) < limit:
        items.append(value)


def note_entry(state, entry):
    """Update the record with one log entry."""
    if entry["line"] <= state["last_line_seen"]:
        return  # already counted, this one is in the overlap between two parts
    state["last_line_seen"] = entry["end_line"]

    note_errors_and_context(state, entry)

    actor_id = entry["ip"] or entry["user"] or entry["session"]
    if not actor_id:
        return

    actor = state["actors"].setdefault(actor_id, new_actor(actor_id))
    actor["requests"] += 1
    actor["first_line"] = actor["first_line"] or entry["line"]
    actor["last_line"] = entry["end_line"]
    add_unique(actor["users"], entry["user"])
    add_unique(actor["sessions"], entry["session"])
    add_unique(actor["agents"], entry["agent"], limit=5)
    if entry["status"]:
        code = str(entry["status"])
        actor["statuses"][code] = actor["statuses"].get(code, 0) + 1

    for signal in find_signals(entry, actor):
        lines = actor["signals"].setdefault(signal, [])
        if len(lines) < MAX_LINES_KEPT:
            lines.append(entry["line"])


def find_signals(entry, actor):
    signals = []
    status = entry["status"] or 0
    # look at the decoded path too, otherwise encoded payloads slip past
    path = decode_url(str(entry["path"])) if entry["path"] else ""
    # the whole line matters for free text fields and for formats we couldn't parse
    text = decode_url(entry["full"])

    if SQLI_RE.search(path or text):
        signals.append("sql_injection")
    if TRAVERSAL_RE.search(path or text):
        signals.append("path_traversal")
    if XSS_RE.search(path or text):
        signals.append("xss")
    if PROMPT_INJECTION_RE.search(text):
        signals.append("prompt_injection")
    if path and PROBE_RE.search(path):
        signals.append("probe")
    if status == 404:
        actor["not_found"] += 1
        if actor["not_found"] >= MANY_NOT_FOUND:
            signals.append("many_not_found")

    is_login = bool(LOGIN_RE.search(path)) or entry["auth"] is not None
    failed = entry["auth"] == "fail" or (is_login and entry["method"] == "POST" and status in (401, 403))
    worked = entry["auth"] == "ok" or (is_login and entry["method"] == "POST" and status == 200)
    if failed:
        signals.append("failed_login")
    if worked:
        signals.append("login_success")
        if len(actor["signals"].get("failed_login", [])) >= 3:
            signals.append("login_after_failures")

    if path and ADMIN_RE.search(path):
        if status in (401, 403):
            signals.append("admin_denied")
        elif 200 <= status < 300:
            signals.append("admin_access")

    if isinstance(entry["bytes"], int) and entry["bytes"] >= BULK_DOWNLOAD_BYTES:
        signals.append("bulk_download")

    if status == 429:
        signals.append("rate_limited")
    if is_burst(entry, actor):
        signals.append("high_rate")

    return signals


def is_burst(entry, actor):
    counter = entry["extra"].get("requests_in_window")
    if isinstance(counter, int) and counter >= REPORTED_RATE:
        return True

    when = to_seconds(entry["time"])
    if when is None:
        return False
    recent = actor["recent"]
    recent.append(when)
    del recent[:-BURST_SIZE]
    return len(recent) == BURST_SIZE and when - recent[0] <= BURST_SECONDS


def to_seconds(value):
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        pass
    try:
        return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None


def note_errors_and_context(state, entry):
    """Groups normal looking errors so the report can explain them separately,
    and keeps deploy/config messages because they explain some of those errors."""
    level = (entry["level"] or "").upper()
    status = entry["status"] or 0

    if entry["service"] and re.search(r"deploy|config|ops", entry["service"]) and entry["message"]:
        if len(state["notes"]) < 8:
            state["notes"].append(f"L{entry['line']} {entry['service']}: {entry['text'][:140]}")

    if level in ("ERROR", "WARN", "WARNING", "CRITICAL", "FATAL") or status >= 500:
        if entry["message"]:
            label = f"{entry['service'] or 'app'}: {entry['message']}"
        else:
            label = f"HTTP {status} on {str(entry['path']).split('?')[0]}"
        group = state["errors"].setdefault(label, {"label": label, "lines": [], "sample": entry["text"][:200]})
        if len(group["lines"]) < MAX_LINES_KEPT:
            group["lines"].append(entry["line"])


def note_model_events(state, events):
    """Save what the model reported, so later calls can see it."""
    for event in events:
        actor = state["actors"].setdefault(event["actor"], new_actor(event["actor"]))
        seen = actor["model"].setdefault(event["type"], {"lines": [], "reason": event["reason"]})
        for line in event["lines"]:
            if line not in seen["lines"]:
                seen["lines"].append(line)


def is_suspicious(actor):
    """Does this actor have enough evidence to deserve a closer look at the end?"""
    s = actor["signals"]
    return bool(
        s.get("sql_injection") or s.get("path_traversal") or s.get("xss") or s.get("prompt_injection")
        or s.get("login_after_failures")
        or len(s.get("failed_login", [])) >= 3
        or len(s.get("probe", [])) >= 2
        or s.get("many_not_found")
        or len(s.get("rate_limited", [])) >= 3
        or s.get("high_rate")
    )


def line_list(lines, limit=5):
    """Short form of a list of lines: L5,L13,L23..L125"""
    if len(lines) <= limit:
        return ",".join(f"L{n}" for n in lines)
    return ",".join(f"L{n}" for n in lines[:limit - 1]) + f"..L{lines[-1]}"


def fact_line(actor, use_rules=True):
    """One short line about what an actor has done so far."""
    bits = []
    if use_rules:
        for name, lines in actor["signals"].items():
            if name == "login_success" and "failed_login" not in actor["signals"]:
                continue
            bits.append(f"{name} x{len(lines)} {line_list(lines, 3)}")
    for name, seen in actor["model"].items():
        if not use_rules or name not in actor["signals"]:
            bits.append(f"{name} {line_list(seen['lines'], 3)}")
    return "; ".join(bits)


def facts_for_model(state, current_ids, count_tokens, limit, use_rules=True):
    """The saved facts for one call, as {actor: facts}, kept under the token limit.

    Only actors in the part being analysed get a line. Facts about anyone else
    can't be linked to anything in this call, so they'd just waste tokens.
    The worst offenders go first in case the limit is reached.
    """
    known = [state["actors"][i] for i in current_ids if i in state["actors"] and i != "other"]
    known.sort(key=lambda a: -sum(len(v) for v in a["signals"].values()))

    facts = {}
    used = 0
    for actor in known:
        line = fact_line(actor, use_rules)
        if not line:
            continue
        tokens = count_tokens(line + "\n")
        if used + tokens > limit:
            continue
        facts[actor["id"]] = line
        used += tokens
    return facts
