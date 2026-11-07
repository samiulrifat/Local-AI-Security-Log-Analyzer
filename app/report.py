"""Turns the facts and model answers into the one final report."""
import re

from .logfile import read_entries
from .replies import SEVERITIES
from .splitter import part_for_line
from .tracker import fact_line, is_suspicious, line_list

# how each signal reads in the report
STAGES = {
    "failed_login": "Failed logins",
    "login_after_failures": "Login succeeded after the failures",
    "admin_access": "Admin area accessed",
    "bulk_download": "Large data download",
    "sql_injection": "SQL injection attempts",
    "xss": "Script injection attempts",
    "probe": "Probing for sensitive files",
    "many_not_found": "Lots of pages not found",
    "path_traversal": "Path traversal attempts",
    "admin_denied": "Admin access denied",
    "rate_limited": "Hit the rate limit",
    "high_rate": "Unusual request rate",
    "prompt_injection": "Text trying to instruct an AI reader",
}

ACTIONS = {
    "login_after_failures": "Disable the account, end its sessions, reset the password and review what it accessed.",
    "failed_login": "Block the IP and add login rate limiting or MFA for the targeted account.",
    "sql_injection": "Block the IP and check the affected endpoint uses parameterized queries.",
    "path_traversal": "Block the IP and confirm file paths are validated on the server.",
    "probe": "Block the IP and make sure no sensitive files are publicly reachable.",
    "many_not_found": "Block the IP and make sure no sensitive files are publicly reachable.",
    "high_rate": "Throttle or block the IP and check whether the client is a known integration.",
    "rate_limited": "Throttle or block the IP and check whether the client is a known integration.",
    "prompt_injection": "Keep the rejection in place and treat log text as untrusted in any AI tooling.",
    "xss": "Block the IP and confirm output encoding on the affected page.",
}
# the same advice, looked up by the type names the model uses
MODEL_TYPE_ACTIONS = {
    "login_after_failures": "login_after_failures", "data_theft": "login_after_failures",
    "unauthorized_access": "probe", "failed_login": "failed_login", "sql_injection": "sql_injection",
    "path_traversal": "path_traversal", "scanning": "probe", "rate_abuse": "rate_limited",
    "prompt_injection": "prompt_injection",
}
# "successfully blocked" is fine, "successfully bypassed" is not
CLAIMS_SUCCESS_RE = re.compile(r"bypass|compromis|gained|stole|exfiltrat"
                               r"|succeed|successful(ly)? (inject|access|exploit|log|authenticat|sql|attack)", re.I)
UNSUPPORTED_CLAIMS = [
    (r"traversal", ["path_traversal"]),
    (r"sql", ["sql_injection"]),
    (r"brute.?force|password", ["failed_login", "login_success"]),
    (r"\.env|\.git|scan", ["probe", "many_not_found", "scanning"]),
]
DEFAULT_ACTION = "Review the listed lines and block the source if it isn't recognised."


def attack_name(signals):
    """A consistent name for the finding, based on the evidence."""
    if signals.get("login_after_failures"):
        name = "Brute-force login followed by account compromise"
        if signals.get("bulk_download"):
            name += " and data theft"
        return name

    names = []
    if signals.get("sql_injection"):
        names.append("SQL injection")
    if signals.get("xss"):
        names.append("Script injection")
    if len(signals.get("failed_login", [])) >= 3:
        names.append("Brute-force login attempts")
    if signals.get("probe") or signals.get("many_not_found"):
        names.append("Scanning")
    if signals.get("path_traversal"):
        names.append("path traversal")
    if signals.get("admin_denied"):
        names.append("unauthorized access attempts")
    if signals.get("high_rate") or signals.get("rate_limited"):
        names.append("Unusual request rate")
    if signals.get("prompt_injection"):
        names.append("Prompt injection attempt")

    if not names:
        return "Suspicious activity"
    joined = ", ".join(names[:-1]) + " and " + names[-1] if len(names) > 1 else names[0]
    return joined[0].upper() + joined[1:]


def model_as_signals(actor):
    """With rules switched off, treat the model's event types like signals so the
    same naming and severity code works for both modes."""
    names = {"failed_login": "failed_login", "login_after_failures": "login_after_failures",
             "sql_injection": "sql_injection", "path_traversal": "path_traversal", "scanning": "probe",
             "unauthorized_access": "admin_denied", "rate_abuse": "rate_limited", "data_theft": "bulk_download",
             "prompt_injection": "prompt_injection"}
    return {names[kind]: seen["lines"] for kind, seen in actor["model"].items() if kind in names}


def severity_range(signals):
    """Small models are inconsistent about severity, so the evidence sets the
    lowest and highest level a finding can have. The model picks within that."""
    took_over = bool(signals.get("login_after_failures"))
    if took_over and (signals.get("bulk_download") or signals.get("admin_access")):
        return "Critical", "Critical"
    if took_over:
        return "High", "Critical"
    if signals.get("sql_injection") or signals.get("path_traversal") or signals.get("xss"):
        return "Medium", "High"
    if len(signals.get("failed_login", [])) >= 3 or signals.get("probe") or signals.get("many_not_found"):
        return "Medium", "High"
    if signals.get("high_rate") or signals.get("rate_limited"):
        return "Medium", "Medium"
    if signals.get("prompt_injection"):
        return "Low", "Medium"
    return "Low", "Medium"


def fit_severity(model_choice, low, high):
    rank = SEVERITIES.index(model_choice) if model_choice in SEVERITIES else 0
    rank = max(rank, SEVERITIES.index(low))
    rank = min(rank, SEVERITIES.index(high))
    return SEVERITIES[rank]


def build_stages(actor, parts, use_rules=True):
    stages = []
    if not use_rules:
        # rules switched off, so the evidence is only what the model reported
        for name, seen in actor["model"].items():
            stages.append(make_stage(name.replace("_", " ").capitalize(), seen["lines"], parts))
        stages.sort(key=lambda stage: stage["lines"][0])
        return stages

    for name, lines in actor["signals"].items():
        if name not in STAGES:
            continue
        # a single failed login isn't worth listing on its own
        if name == "failed_login" and len(lines) < 3:
            continue
        stages.append(make_stage(STAGES[name], lines, parts))
    used = {line for stage in stages for line in stage["lines"]}
    model_lines = {n for seen in actor["model"].values() for n in seen["lines"]}
    extra = sorted(model_lines - used)
    if extra:
        stages.append(make_stage("Other lines flagged by the model", extra, parts))
    stages.sort(key=lambda stage: stage["lines"][0])
    return stages


def make_stage(label, lines, parts):
    in_parts = sorted({part_for_line(parts, line) for line in lines} - {None})
    return {"label": label, "lines": lines, "parts": [p + 1 for p in in_parts]}


def all_refused(actor):
    """Every response was a 4xx. A 5xx doesn't count as refused, a payload that
    crashes the server may well have reached the database."""
    return bool(actor["statuses"]) and all(code.startswith("4") for code in actor["statuses"])


def caused_server_errors(actor):
    return any(code.startswith("5") for code in actor["statuses"])


def lower_first(label):
    # "SQL injection" should stay as it is
    return label if label[1:2].isupper() else label[0].lower() + label[1:]


def fallback_reason(actor, stages):
    steps = [f"{lower_first(s['label'])} ({line_list(s['lines'], 3)})" for s in stages]
    text = "Seen in the log: " + ", then ".join(steps) + "."
    if all_refused(actor):
        text += " The server refused all of these requests."
    elif caused_server_errors(actor):
        text += " Some of these requests caused server errors, so check whether they reached the backend."
    return text


def tidy_reason(text):
    """The grammar limits the length, so a reply can stop mid sentence. Cut back
    to the last full stop, or failing that the last comma or whole word."""
    text = text.strip()
    if text.endswith((".", "!")):
        return text
    if ". " in text:
        return text[:text.rfind(". ") + 1]
    if len(text) < 70:
        return text
    return text[:text.rfind(",")] if "," in text else text.rsplit(" ", 1)[0]


def reason_is_usable(text, actor):
    """Throws away answers the facts contradict. Better a plain factual sentence
    from our own records than a confident wrong one from the model."""
    if not text or len(text) < 15 or "{" in text or "}" in text:
        return False
    # names an IP that has nothing to do with this actor
    if set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)) - {actor["id"]}:
        return False
    # claims the attack worked when nothing shows it did
    if not actor["signals"].get("login_after_failures") and "login_after_failures" not in actor["model"]:
        if CLAIMS_SUCCESS_RE.search(text):
            return False
    # says it was blocked when the server actually fell over
    if caused_server_errors(actor) and re.search(r"blocked|refused|rejected", text, re.I):
        return False
    # talks about an attack this actor never tried, usually copied from the prompt example
    for words, evidence in UNSUPPORTED_CLAIMS:
        if re.search(words, text, re.I) and not any(actor["signals"].get(e) or e in actor["model"] for e in evidence):
            return False
    return True


def actors_to_review(state, use_rules):
    chosen = []
    for actor in state["actors"].values():
        if use_rules and is_suspicious(actor):
            chosen.append(actor)
        elif actor["model"] and not looks_like_typo(actor):
            chosen.append(actor)
    return chosen


def looks_like_typo(actor):
    """One or two bad passwords and then a normal login. The model sometimes
    flags these even though the prompt says not to."""
    failed = actor["signals"].get("failed_login", [])
    only_login_types = set(actor["model"]) <= {"failed_login", "login_after_failures"}
    other_signals = set(actor["signals"]) - {"failed_login", "login_success"}
    return bool(failed) and only_login_types and len(failed) < 3 and not other_signals


def sample_lines(path, stages, count_tokens, budget):
    """Pick the first and last few lines of each stage, as many as fit."""
    wanted = []
    for stage in stages:
        lines = stage["lines"]
        picks = lines if len(lines) <= 4 else lines[:2] + lines[-2:]
        wanted.extend(n for n in picks if n not in wanted)
    wanted.sort()

    texts = []
    used = 0
    for entry in read_entries(path):
        if entry["line"] in wanted:
            tokens = count_tokens(entry["text"] + "\n")
            if used + tokens > budget:
                break
            texts.append(entry["text"])
            used += tokens
    return "\n".join(texts)


def describe_actor(actor, stages, use_rules):
    lines = []
    facts = fact_line(actor, use_rules)
    if facts:
        lines.append(facts)
    statuses = " ".join(f"{code}x{n}" for code, n in sorted(actor["statuses"].items()))
    lines.append(f"requests {actor['requests']}, status codes {statuses}")
    if all_refused(actor):
        lines.append("the server refused every request from this actor")
    elif caused_server_errors(actor):
        lines.append("some requests caused server errors (5xx), these were not refused")
    if actor["agents"]:
        lines.append("clients: " + ", ".join(a[:30] for a in actor["agents"]))
    spread = sorted({p for stage in stages for p in stage["parts"]})
    lines.append(f"seen across parts {spread} of the file")
    return "\n".join(lines)


def build_finding(actor, verdict, stages, use_rules):
    signals = actor["signals"] if use_rules else model_as_signals(actor)
    low, high = severity_range(signals)
    has_rule_evidence = use_rules and is_suspicious(actor)

    said_attack = bool(verdict and verdict.get("is_attack"))
    model_involved = bool(actor["model"]) or said_attack

    if not has_rule_evidence and not said_attack:
        return None  # only the model flagged it, and on review the model dropped it

    reason = tidy_reason((verdict or {}).get("reason", ""))
    # if the model thinks it's nothing but the evidence says otherwise, its reason
    # would argue against the finding, so use the plain facts instead
    disagreed = has_rule_evidence and verdict is not None and not said_attack
    if disagreed or not reason_is_usable(reason, actor):
        reason = fallback_reason(actor, stages)

    name = attack_name(signals if has_rule_evidence or not use_rules else model_as_signals(actor))

    lines = [line for stage in stages for line in stage["lines"]]
    parts = sorted({p for stage in stages for p in stage["parts"]})
    return {
        "attack_type": name,
        "severity": fit_severity((verdict or {}).get("severity"), low, high),
        "certainty": "Confirmed by evidence" if has_rule_evidence and said_attack else "Needs review",
        "actor": actor["id"],
        "users": actor["users"],
        "reason": reason,
        "action": pick_action(signals, actor["model"]),
        "evidence": stages,
        "parts": parts,
        "first_line": min(lines),
        "last_line": max(lines),
        "found_by": "model + rules" if has_rule_evidence and model_involved
                    else "rules only" if has_rule_evidence else "model only",
        "model_disagreed": disagreed,
    }


def pick_action(signals, model_types):
    """Fixed advice for each kind of evidence. The model's own suggestions kept
    naming accounts and tokens that weren't in the log, so it no longer writes these."""
    for name in ACTIONS:
        if signals.get(name):
            return ACTIONS[name]
    for kind in model_types:
        if kind in MODEL_TYPE_ACTIONS:
            return ACTIONS[MODEL_TYPE_ACTIONS[kind]]
    return DEFAULT_ACTION


def write_summary(findings):
    if not findings:
        return "No attacks were found in this log."
    worst = findings[0]
    return (f"Most serious is {worst['actor']}: {lower_first(worst['attack_type'])} "
            f"({worst['severity'].lower()}). Start there: {lower_first(worst['action'])}")


def finding_sort_key(finding):
    return (-SEVERITIES.index(finding["severity"]), finding["first_line"])


def top_error_groups(state, findings):
    """The biggest groups of ordinary errors. Errors that are part of a finding are
    left out, otherwise an attack could show up under "not attacks" as well."""
    used = {line for finding in findings for stage in finding["evidence"] for line in stage["lines"]}
    groups = [g for g in state["errors"].values() if not used.intersection(g["lines"])]
    groups.sort(key=lambda g: -len(g["lines"]))
    return groups[:12]


def error_reason(answer):
    reason = tidy_reason(answer.get("reason", ""))
    # small models sometimes spill JSON or chatter into this field
    if len(reason) < 8 or "{" in reason or "}" in reason or "#" in reason:
        return "Operational error with no sign of malicious input."
    return reason


def errors_message(groups, notes):
    lines = [f"{i + 1}. x{len(g['lines'])} {g['sample']}" for i, g in enumerate(groups)]
    text = "<log>\n" + "\n".join(lines) + "\n</log>"
    if notes:
        text = "<facts>\nNOTES:\n" + "\n".join(notes) + "\n</facts>\n" + text
    return text
