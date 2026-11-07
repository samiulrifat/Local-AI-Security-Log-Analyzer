"""Checks uploads and turns raw log lines into short entries for the model.

Log lines are long and most of each line is useless to the model (request ids,
hostnames, browser strings). Shortening them means fewer parts and fewer calls.
The original file stays on disk and is what the report links back to.
"""
import json
import re
from urllib.parse import unquote

from .config import MAX_ENTRY_CHARS, MAX_UPLOAD_BYTES

ALLOWED_EXTENSIONS = (".log", ".txt")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ACCESS_LOG_RE = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+)(?: "[^"]*" "([^"]*)")?'
)
SSH_FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
SSH_OK_RE = re.compile(r"Accepted \S+ for (\S+) from (\S+)")

SIMPLE_PATH_RE = re.compile(r"[\w/.\-?=&]*")
SENSITIVE_WORDS_RE = re.compile(r"admin|auth|login|export|backup|config|\.env|\.git|\.sql|\.php", re.I)

# fields that don't help find attacks, dropped from what the model reads
SKIP_FIELDS = {"time", "timestamp", "ts", "@timestamp", "host", "request_id", "level", "service",
               "app", "method", "path", "url", "uri", "status", "status_code", "user_agent",
               "client_ip", "ip", "remote_addr", "src_ip", "source_ip", "message", "msg",
               "response_bytes", "duration_ms"}


def check_upload(filename, path):
    """Raises ValueError with a readable message if the file can't be used."""
    if not filename or not filename.lower().endswith(ALLOWED_EXTENSIONS):
        raise ValueError("Only .log and .txt files are accepted.")

    size = path.stat().st_size
    if size == 0:
        raise ValueError("The file is empty.")
    if size > MAX_UPLOAD_BYTES:
        raise ValueError("The file is too big (limit is 20 MB).")

    with open(path, "rb") as f:
        sample = f.read(64 * 1024)
    if b"\0" in sample:
        raise ValueError("This looks like a binary file, not a text log.")
    bad = sample.decode("utf-8", errors="replace").count("\ufffd")
    if bad > len(sample) * 0.1:
        raise ValueError("This file doesn't look like text.")
    if not sample.strip():
        raise ValueError("The file only contains blank lines.")


def clean_text(text):
    """Log text goes into the prompt, so it can't contain model control tokens.

    Without this a line holding <|im_end|> could end our prompt early and let
    the rest of the line act like real instructions.
    """
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", text)
    text = re.sub(r"</?(log|facts|think)\b[^>]*>", "[tag]", text, flags=re.I)
    text = re.sub(r"<\|?/?(im_|start_of|end_of|turn|bos|eos|pad)[^>]*\|?>", "[tag]", text, flags=re.I)
    return text.replace("<|", "< |").replace("|>", "| >")


def decode_url(path):
    # twice, because attackers double encode things like %252e
    for _ in range(2):
        path = unquote(path)
    return path


def parse_line(raw):
    """Pulls the common fields out of a line. Handles JSON logs, nginx/apache
    access logs and ssh auth logs. Anything else still gets its IP picked up."""
    entry = {"ip": None, "user": None, "session": None, "method": None, "path": None,
             "status": None, "agent": None, "time": None, "level": None, "service": None,
             "message": None, "bytes": None, "duration": None, "auth": None, "extra": {}}

    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except ValueError:
            data = None
        if isinstance(data, dict):
            fill_from_json(entry, data)
            return tidy_fields(entry)

    match = ACCESS_LOG_RE.match(raw)
    if match:
        ip, user, when, method, path, status, size, agent = match.groups()
        entry.update(ip=ip, time=when, method=method, path=path, status=int(status), agent=agent)
        if user != "-":
            entry["user"] = user
        if size.isdigit():
            entry["bytes"] = int(size)
        return tidy_fields(entry)

    entry["message"] = raw
    match = SSH_FAILED_RE.search(raw)
    if match:
        entry.update(user=match.group(1), ip=match.group(2), auth="fail")
        return tidy_fields(entry)
    match = SSH_OK_RE.search(raw)
    if match:
        entry.update(user=match.group(1), ip=match.group(2), auth="ok")
        return tidy_fields(entry)

    found_ip = IP_RE.search(raw)
    if found_ip:
        entry["ip"] = found_ip.group(0)
    return entry


def tidy_fields(entry):
    """A log can put anything in any field, a number for the IP or control tokens
    in the username. Everything after this can rely on these being clean strings."""
    for key in ("ip", "user", "session", "agent", "level", "service", "message", "method"):
        if entry[key] is not None:
            entry[key] = clean_text(str(entry[key]))[:300]
    for key in ("ip", "user", "session"):
        if entry[key] is not None:
            entry[key] = entry[key][:60]
    return entry


def fill_from_json(entry, data):
    def first(*keys):
        for key in keys:
            if data.get(key) not in (None, ""):
                return data[key]
        return None

    entry["time"] = first("time", "timestamp", "ts", "@timestamp")
    entry["level"] = first("level", "severity")
    entry["service"] = first("service")
    entry["ip"] = first("client_ip", "ip", "remote_addr", "src_ip", "source_ip")
    entry["method"] = first("method")
    entry["path"] = first("path", "url", "uri")
    entry["agent"] = first("user_agent")
    entry["message"] = first("message", "msg")
    entry["user"] = first("username", "user")
    entry["session"] = first("session_id", "session")
    entry["bytes"] = first("response_bytes")
    entry["duration"] = first("duration_ms")
    status = first("status", "status_code")
    if str(status).isdigit():
        entry["status"] = int(status)

    result = str(data.get("auth_result", "")).lower()
    if result:
        entry["auth"] = "ok" if result == "success" else "fail"

    entry["extra"] = {k: v for k, v in data.items() if k not in SKIP_FIELDS}
    entry["app"] = str(data["app"]) if data.get("app") else None


def short_time(value):
    if not value:
        return ""
    # the lookbehind stops 02/Mar/2026:14:00:33 being read as 26:14:00
    match = re.search(r"(?<!\d)\d\d:\d\d:\d\d", str(value))
    return match.group(0) if match else str(value)[:19]


def short_agent(agent):
    if not agent:
        return ""
    return "browser" if agent.startswith("Mozilla") else agent[:40]


def to_text(entry, raw, line_label):
    """The one line the model actually reads."""
    if entry["path"] is None and not entry["extra"] and entry["message"] == raw:
        # not a format we know, send it as it is
        body = raw
    else:
        bits = [short_time(entry["time"])]
        if entry.get("app"):
            bits.append(entry["app"].replace(" ", "-"))
        if entry["level"] in ("ERROR", "WARN", "WARNING", "CRITICAL", "FATAL"):
            bits.append(entry["level"])
        if entry["service"] and entry["service"] != "gateway":
            bits.append(entry["service"])
        if entry["ip"]:
            bits.append(entry["ip"])
        if entry["method"]:
            bits.append(entry["method"])
        if entry["path"]:
            bits.append(decode_url(str(entry["path"])))
        if entry["status"]:
            bits.append(str(entry["status"]))
        if entry["agent"]:
            bits.append(short_agent(entry["agent"]))
        if entry["message"]:
            bits.append(entry["message"])
        # sizes and timings only matter when they stand out
        if isinstance(entry["bytes"], int) and entry["bytes"] >= 1_000_000:
            # written as MB because the model misread 2841056 as 284KB
            bits.append(f"bytes={entry['bytes'] / 1_000_000:.1f}MB")
        if isinstance(entry["duration"], int) and entry["duration"] >= 3000:
            bits.append(f"ms={entry['duration']}")
        for key, value in entry["extra"].items():
            bits.append(f"{key}={value}")
        body = " ".join(b for b in bits if b)

    text = f"{line_label} {clean_text(body)}"
    if len(text) > MAX_ENTRY_CHARS:
        text = text[:MAX_ENTRY_CHARS] + " ...[cut]"
    return text


def is_continuation(raw):
    # stack traces and similar belong with the line above them
    return raw[:1] in (" ", "\t") or raw.startswith(("Traceback", "Caused by", "at "))


def read_entries(path, offset=0, first_line=1, last_line=None):
    """Reads the file one entry at a time so we never hold the whole log in memory.

    Yields dicts with line numbers, the byte offset, the parsed fields and the
    short text. Exact repeats of the previous line are merged into one entry.
    """
    current = None
    line_no = first_line - 1
    with open(path, "rb") as f:
        f.seek(offset)
        while True:
            start = f.tell()
            data = f.readline()
            if not data:
                break
            line_no += 1
            raw = data.decode("utf-8", errors="replace").rstrip("\r\n")

            if not raw.strip():
                continue

            if current and raw == current["raw"]:
                current["end_line"] = line_no
                current["repeats"] += 1
                continue

            if current and is_continuation(raw):
                current["raw_extra"] += " | " + raw.strip()
                current["end_line"] = line_no
                continue

            if current:
                yield finish_entry(current)
                current = None

            if last_line and line_no > last_line:
                return

            current = parse_line(raw.strip())
            current.update(raw=raw, raw_extra="", line=line_no, end_line=line_no,
                           offset=start, repeats=0)
    if current:
        yield finish_entry(current)


def finish_entry(entry):
    raw = entry["raw"].strip()
    label = f"L{entry['line']}"
    if entry["repeats"]:
        label += f"(repeated to L{entry['end_line']})"
    elif entry["end_line"] != entry["line"]:
        label += f"-L{entry['end_line']}"
    entry["text"] = to_text(entry, raw, label) + clean_text(entry["raw_extra"])[:MAX_ENTRY_CHARS]
    # keep the full line for the rule checks, then it can be thrown away
    entry["full"] = raw + entry["raw_extra"]
    return entry


def is_routine(entry):
    """Plain page views that can't tell the model anything, including the odd
    404 from a browser. They get replaced by one short note in the prompt, which
    cuts the number of model calls a lot and stops the model hunting for something
    in boring traffic. The tracker still sees every one of them, this only changes
    what goes in the prompt."""
    if entry["method"] != "GET" or entry["status"] not in (200, 304, 404, 422):
        return False
    if entry["extra"] or entry["user"] or entry["session"]:
        return False
    path = str(entry["path"])
    if not SIMPLE_PATH_RE.fullmatch(path) or SENSITIVE_WORDS_RE.search(path):
        return False
    if isinstance(entry["bytes"], int) and entry["bytes"] >= 1_000_000:
        return False
    is_browser = str(entry["agent"] or "").startswith("Mozilla")
    return is_browser or (path in ("/health", "/ready") and entry["status"] == 200)


def actor_of(entry):
    """Who this line is about. "other" is for lines with no IP, user or session."""
    return entry["ip"] or entry["user"] or entry["session"] or "other"


def group_for_prompt(entries, facts=None):
    """Builds the log text for a prompt, with lines grouped under each actor.

    Small models do much better with this than with lines in time order, the
    pattern from one IP is right there together, along with what earlier parts
    found about it. Returns the text and {actor: [line numbers]}.
    """
    facts = facts or {}
    groups = {}
    routine_count = 0
    for entry in entries:
        if is_routine(entry):
            routine_count += 1
        else:
            groups.setdefault(actor_of(entry), []).append(entry)

    # biggest groups first, that's where attacks usually are. the model answers in
    # this order, and with lots of one line groups up front it tends to attach what
    # it noticed to the wrong number
    groups = dict(sorted(groups.items(), key=lambda item: (item[0] == "other", -len(item[1]))))

    blocks = []
    if routine_count:
        blocks.append(f"({routine_count} normal page views left out)")
    for number, (actor, members) in enumerate(groups.items(), start=1):
        header = f"#{number} {actor}"
        if actor in facts:
            header += f" EARLIER: {facts[actor]}"
        blocks.append(header)
        for entry in members:
            # the IP is already in the header, no need to pay for it on every line
            blocks.append(entry["text"].replace(f" {actor} ", " ", 1))

    line_map = {actor: [e["line"] for e in members] for actor, members in groups.items()}
    return "\n".join(blocks), line_map


def read_lines(path, wanted):
    """Original text for specific line numbers, used by the report page."""
    wanted = set(wanted)
    found = {}
    with open(path, "rb") as f:
        for number, data in enumerate(f, start=1):
            if number in wanted:
                found[number] = data.decode("utf-8", errors="replace").rstrip("\r\n")
                if len(found) == len(wanted):
                    break
    return found
