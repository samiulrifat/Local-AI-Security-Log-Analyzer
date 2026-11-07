"""Splits a log into parts that fit the model's token budget."""
from .config import OVERLAP_ENTRIES
from .logfile import actor_of, is_routine, read_entries

# rough cost of a "#3 203.0.113.44" group header, and the "normal page views" note
HEADER_TOKENS = 20
ROUTINE_NOTE_TOKENS = 12


def split_log(path, count_tokens, max_tokens):
    """Fills each part with whole entries until the next one wouldn't fit.

    Only line numbers and a byte offset are saved for each part. The text is
    read back from disk when the part is analysed, so there's no second copy
    of the log sitting in memory or in the database.
    """
    parts = []
    current = []
    total_lines = 0
    total_tokens = 0

    for entry in read_entries(path):
        item = measure_entry(entry, count_tokens)
        total_lines = entry["end_line"]
        total_tokens += item["tokens"]

        if current and part_cost(current + [item]) > max_tokens:
            parts.append(make_part(len(parts), current))
            # start the next part with the last couple of entries again so
            # events on the boundary are seen together
            current = current[-OVERLAP_ENTRIES:] if OVERLAP_ENTRIES else []
            while current and part_cost(current + [item]) > max_tokens:
                current.pop(0)

        current.append(item)

    if current:
        parts.append(make_part(len(parts), current))

    return parts, total_lines, total_tokens


def measure_entry(entry, count_tokens):
    actor = actor_of(entry)
    tokens = 0
    # routine lines become part of one short note, they don't cost anything each
    if not is_routine(entry):
        tokens = count_tokens(entry["text"].replace(f" {actor} ", " ", 1) + "\n")
    return {"line": entry["line"], "end_line": entry["end_line"], "offset": entry["offset"],
            "tokens": tokens, "actor": None if is_routine(entry) else actor}


def part_cost(items):
    actors = {item["actor"] for item in items if item["actor"]}
    return sum(item["tokens"] for item in items) + len(actors) * HEADER_TOKENS + ROUTINE_NOTE_TOKENS


def make_part(index, items):
    return {"idx": index, "first_line": items[0]["line"], "last_line": items[-1]["end_line"],
            "offset": items[0]["offset"], "log_tokens": part_cost(items)}


def part_for_line(parts, line):
    # lines in an overlap belong to the earlier part
    for part in parts:
        if part["first_line"] <= line <= part["last_line"]:
            return part["idx"]
    return None
