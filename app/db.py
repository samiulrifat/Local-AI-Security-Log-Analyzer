"""SQLite storage. Results are saved after every model call, so a crash or a
restart loses at most the call that was running."""
import json
import sqlite3
import time

from .config import DATA_DIR, DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    status TEXT NOT NULL,
    model TEXT,
    total_lines INTEGER DEFAULT 0,
    total_tokens INTEGER DEFAULT 0,
    log_budget INTEGER DEFAULT 0,
    use_rules INTEGER DEFAULT 1,
    state TEXT,
    report TEXT,
    error TEXT,
    created REAL,
    started REAL,
    finished REAL
);
CREATE TABLE IF NOT EXISTS parts (
    job_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    first_line INTEGER,
    last_line INTEGER,
    offset INTEGER,
    log_tokens INTEGER,
    status TEXT DEFAULT 'pending',
    prompt_tokens INTEGER DEFAULT 0,
    reply_tokens INTEGER DEFAULT 0,
    seconds REAL DEFAULT 0,
    attempts INTEGER DEFAULT 0,
    events INTEGER DEFAULT 0,
    rejected INTEGER DEFAULT 0,
    error TEXT,
    PRIMARY KEY (job_id, idx)
);
CREATE TABLE IF NOT EXISTS events (
    job_id TEXT NOT NULL,
    part_idx INTEGER NOT NULL,
    actor TEXT,
    type TEXT,
    lines TEXT,
    reason TEXT
);
CREATE TABLE IF NOT EXISTS calls (
    job_id TEXT NOT NULL,
    kind TEXT,
    label TEXT,
    prompt_tokens INTEGER,
    reply_tokens INTEGER,
    seconds REAL,
    ok INTEGER,
    note TEXT,
    at REAL
);
CREATE TABLE IF NOT EXISTS answers (
    job_id TEXT NOT NULL,
    key TEXT NOT NULL,
    data TEXT,
    PRIMARY KEY (job_id, key)
);
"""


def connect():
    db = sqlite3.connect(DB_PATH, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    return db


def init():
    DATA_DIR.mkdir(exist_ok=True)
    with connect() as db:
        db.executescript(SCHEMA)


def add_job(job_id, filename, path, size):
    with connect() as db:
        db.execute("INSERT INTO jobs (id, filename, path, size, status, created) VALUES (?,?,?,?,?,?)",
                   (job_id, filename, str(path), size, "uploaded", time.time()))


def update_job(job_id, **fields):
    names = ", ".join(f"{name} = ?" for name in fields)
    with connect() as db:
        db.execute(f"UPDATE jobs SET {names} WHERE id = ?", (*fields.values(), job_id))


def get_job(job_id):
    with connect() as db:
        row = db.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    return dict(row) if row else None


def list_jobs():
    with connect() as db:
        rows = db.execute("SELECT id, filename, status, created FROM jobs ORDER BY created DESC LIMIT 20")
        return [dict(row) for row in rows]


def jobs_with_status(*statuses):
    marks = ",".join("?" * len(statuses))
    with connect() as db:
        rows = db.execute(f"SELECT id FROM jobs WHERE status IN ({marks}) ORDER BY created", statuses)
        return [row["id"] for row in rows]


def save_parts(job_id, parts):
    with connect() as db:
        db.execute("DELETE FROM parts WHERE job_id = ?", (job_id,))
        db.executemany(
            "INSERT INTO parts (job_id, idx, first_line, last_line, offset, log_tokens) VALUES (?,?,?,?,?,?)",
            [(job_id, p["idx"], p["first_line"], p["last_line"], p["offset"], p["log_tokens"]) for p in parts])


def get_parts(job_id):
    with connect() as db:
        rows = db.execute("SELECT * FROM parts WHERE job_id = ? ORDER BY idx", (job_id,))
        return [dict(row) for row in rows]


def update_part(job_id, idx, **fields):
    names = ", ".join(f"{name} = ?" for name in fields)
    with connect() as db:
        db.execute(f"UPDATE parts SET {names} WHERE job_id = ? AND idx = ?", (*fields.values(), job_id, idx))


def save_part_result(job_id, idx, found, state, **part_fields):
    """Findings, the running facts and the part status all go in one transaction,
    so a crash can't leave them out of step with each other."""
    names = ", ".join(f"{name} = ?" for name in part_fields)
    with connect() as db:
        db.execute("DELETE FROM events WHERE job_id = ? AND part_idx = ?", (job_id, idx))
        db.executemany("INSERT INTO events (job_id, part_idx, actor, type, lines, reason) VALUES (?,?,?,?,?,?)",
                       [(job_id, idx, e["actor"], e["type"], json.dumps(e["lines"]), e["reason"]) for e in found])
        db.execute(f"UPDATE parts SET {names} WHERE job_id = ? AND idx = ?", (*part_fields.values(), job_id, idx))
        db.execute("UPDATE jobs SET state = ? WHERE id = ?", (json.dumps(state), job_id))


def log_call(job_id, kind, label, result=None, ok=True, note=None):
    result = result or {}
    with connect() as db:
        db.execute("INSERT INTO calls (job_id, kind, label, prompt_tokens, reply_tokens, seconds, ok, note, at) "
                   "VALUES (?,?,?,?,?,?,?,?,?)",
                   (job_id, kind, label, result.get("prompt_tokens", 0), result.get("reply_tokens", 0),
                    result.get("seconds", 0), int(ok), note, time.time()))


def call_stats(job_id):
    with connect() as db:
        row = db.execute(
            "SELECT COUNT(*) AS calls, COALESCE(SUM(ok), 0) AS ok_calls, COALESCE(SUM(seconds), 0) AS seconds, "
            "COALESCE(MAX(prompt_tokens + reply_tokens), 0) AS biggest_call, "
            "COALESCE(SUM(reply_tokens), 0) AS reply_tokens FROM calls WHERE job_id = ?", (job_id,)).fetchone()
    return dict(row)


def recent_calls(job_id, limit=40):
    with connect() as db:
        rows = db.execute("SELECT kind, label, prompt_tokens, reply_tokens, seconds, ok, note FROM calls "
                          "WHERE job_id = ? ORDER BY at DESC LIMIT ?", (job_id, limit))
        return [dict(row) for row in rows]


def get_events(job_id):
    with connect() as db:
        rows = db.execute("SELECT * FROM events WHERE job_id = ? ORDER BY part_idx", (job_id,))
        return [{**dict(row), "lines": json.loads(row["lines"])} for row in rows]


def save_answer(job_id, key, data):
    with connect() as db:
        db.execute("INSERT OR REPLACE INTO answers (job_id, key, data) VALUES (?,?,?)",
                   (job_id, key, json.dumps(data)))


def get_answer(job_id, key):
    with connect() as db:
        row = db.execute("SELECT data FROM answers WHERE job_id = ? AND key = ?", (job_id, key)).fetchone()
    return json.loads(row["data"]) if row else None


def clear_answers(job_id):
    with connect() as db:
        db.execute("DELETE FROM answers WHERE job_id = ?", (job_id,))
