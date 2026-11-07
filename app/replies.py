"""Reading the model's JSON answers, including broken or cut off ones."""
import json
import re

from .logfile import IP_RE, decode_url

ATTACK_TYPES = ["failed_login", "login_after_failures", "sql_injection", "path_traversal",
                "scanning", "unauthorized_access", "rate_abuse", "data_theft",
                "prompt_injection", "other"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]


def parse_json(text):
    """Returns a dict, or None if nothing usable could be recovered. Never raises."""
    if not text:
        return None
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    text = text.replace("```json", "").replace("```", "").strip()

    start = text.find("{")
    if start < 0:
        return None
    text = text[start:]

    try:
        data = json.loads(text)
    except ValueError:
        data = repair_json(text)
    return data if isinstance(data, dict) else None


def repair_json(text):
    """A reply cut off at the token limit is valid up to some point. Find the
    last place where an object or list closed, and close whatever is still open."""
    stack = []
    in_string = False
    escaped = False
    good_spots = []

    for i, ch in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]":
            if not stack:
                break
            stack.pop()
            good_spots.append((i, list(stack)))

    # try the latest spot first so we keep as much as possible
    for position, still_open in reversed(good_spots):
        attempt = text[:position + 1] + "".join(reversed(still_open))
        try:
            return json.loads(attempt)
        except ValueError:
            continue
    return None


def line_supports(kind, entry):
    """Does this log line even look like what the model says it is?

    The model will sometimes call a plain GET /login an SQL injection. These
    checks are loose on purpose, they only catch claims the line can't back up.
    """
    status = entry["status"] or 0
    text = decode_url(entry["text"]).lower()
    path = decode_url(str(entry["path"] or "")).lower()

    if kind == "sql_injection":
        return bool(re.search(r"['\";]|select|union|sleep\(|drop table", text))
    if kind == "path_traversal":
        return ".." in text or "/etc/" in text
    if kind == "failed_login":
        return entry["auth"] == "fail" or status in (401, 403) or (not status and "fail" in text)
    if kind == "login_after_failures":
        # has to be a real login, opening the login page with GET doesn't count
        return entry["auth"] == "ok" or (entry["method"] == "POST" and status == 200
                                         and bool(re.search(r"login|auth|signin", path)))
    if kind == "scanning":
        return 400 <= status < 500 or bool(re.search(r"\.env|\.git|admin|config|backup|\.sql|\.php", path))
    if kind == "unauthorized_access":
        return status in (401, 403) or "admin" in path or "denied" in text or "unauthorized" in text
    if kind == "rate_abuse":
        return status == 429 or "requests_in_window" in text or (not status and "rate" in text)
    if kind == "data_theft":
        return "bytes=" in text or "export" in path or "dump" in path
    if kind == "prompt_injection":
        return bool(re.search(r"ignore|disregard|instruction|prompt", text))
    return True


def check_events(reply, entries, line_map):
    """Turns a reply into events, keeping only what the log text backs up.

    The model says what a group is, the evidence is whichever of that group's
    lines actually fit that claim. If none do, the claim is thrown out.
    Returns (good events, number rejected).
    """
    good = []
    rejected = 0
    by_line = {entry["line"]: entry for entry in entries}
    # the same cleaning the grammar uses, so ids match even for odd usernames
    actors = {re.sub(r"[^\w.:@-]", "_", actor): actor for actor in line_map}

    groups = reply.get("groups") if isinstance(reply, dict) else None
    if not isinstance(groups, list):
        return [], 0

    for group in groups:
        if not isinstance(group, dict) or group.get("type") == "normal":
            continue
        actor = actors.get(group.get("id"))
        if actor is None:
            rejected += 1
            continue
        kind = group.get("type")
        if kind not in ATTACK_TYPES:
            kind = "other"
        reason = str(group.get("saw") or "")[:200]
        # a note about some other IP means the answer got attached to the wrong group
        if set(IP_RE.findall(reason)) - {actor}:
            rejected += 1
            continue
        lines = [n for n in line_map[actor] if n in by_line and line_supports(kind, by_line[n])]
        if not lines:
            rejected += 1
            continue
        good.append({"actor": actor, "type": kind, "lines": lines, "reason": reason})
    return good, rejected
