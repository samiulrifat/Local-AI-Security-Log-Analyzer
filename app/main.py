"""Web routes for the dashboard."""
import json
import os
import shutil
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import db
from .config import CONTEXT_SIZE, DEFAULT_MODEL, MAX_UPLOAD_BYTES, MODEL_DIR, MODELS, UPLOAD_DIR
from .llm import LlamaServer, ModelError, read_memory_mb
from .logfile import check_upload, read_lines
from .worker import RUNNING_STATES, Worker, new_job_options

STATIC_DIR = Path(__file__).parent / "static"

server = LlamaServer(DEFAULT_MODEL)
worker = Worker(server)


def boot():
    try:
        server.start()
    except ModelError as error:
        print(f"could not start the model: {error}")
    worker.resume_unfinished()


@asynccontextmanager
async def lifespan(app):
    db.init()
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=boot, daemon=True).start()
    yield
    server.stop()


app = FastAPI(title="Logsift", lifespan=lifespan)


def need_job(job_id):
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found.")
    return job


@app.post("/api/jobs")
def upload(file: UploadFile = File(...)):
    job_id = uuid.uuid4().hex[:12]
    # stored under our own name, never the name the browser sent
    path = UPLOAD_DIR / f"{job_id}.log"

    written = 0
    with open(path, "wb") as out:
        while chunk := file.file.read(256 * 1024):
            written += len(chunk)
            if written > MAX_UPLOAD_BYTES:
                out.close()
                path.unlink()
                raise HTTPException(400, "The file is too big (limit is 20 MB).")
            out.write(chunk)

    try:
        check_upload(file.filename, path)
    except ValueError as error:
        path.unlink()
        raise HTTPException(400, str(error))

    db.add_job(job_id, Path(file.filename).name, path, written)
    return {"id": job_id}


class StartRequest(BaseModel):
    model: str = DEFAULT_MODEL


@app.post("/api/jobs/{job_id}/start")
def start(job_id: str, request: StartRequest):
    job = need_job(job_id)
    if request.model not in MODELS:
        raise HTTPException(400, "Unknown model.")
    if job["status"] != "uploaded":
        raise HTTPException(409, "This job has already been started.")
    db.update_job(job_id, status="queued", **new_job_options(request.model))
    worker.add(job_id)
    return {"ok": True}


@app.post("/api/jobs/{job_id}/cancel")
def cancel(job_id: str):
    job = need_job(job_id)
    if job["status"] in RUNNING_STATES:
        db.update_job(job_id, status="cancelling")
    return {"ok": True}


@app.post("/api/jobs/{job_id}/retry")
def retry(job_id: str):
    """Runs failed or unfinished parts again, keeping everything already done."""
    job = need_job(job_id)
    if job["status"] in RUNNING_STATES:
        raise HTTPException(409, "This job is still running.")
    with db.connect() as conn:
        conn.execute("UPDATE parts SET status = 'pending' WHERE job_id = ? AND status != 'done'", (job_id,))
    db.clear_answers(job_id)
    db.update_job(job_id, status="queued", report=None, error=None, finished=None)
    worker.add(job_id)
    return {"ok": True}


@app.get("/api/jobs")
def jobs():
    return db.list_jobs()


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str):
    job = need_job(job_id)
    job.pop("state", None)
    report = job.pop("report", None)
    job["path"] = None
    return {
        "job": job,
        "parts": db.get_parts(job_id),
        "events": db.get_events(job_id),
        "calls": db.recent_calls(job_id),
        "stats": db.call_stats(job_id),
        "report": json.loads(report) if report else None,
    }


@app.get("/api/jobs/{job_id}/lines")
def lines(job_id: str, numbers: str):
    """Original log lines for the evidence view, for example ?numbers=5,13,23"""
    job = need_job(job_id)
    try:
        wanted = [int(n) for n in numbers.split(",")][:300]
    except ValueError:
        raise HTTPException(400, "Line numbers must be numbers.")
    return read_lines(job["path"], wanted)


@app.get("/api/system")
def system():
    backend_now, backend_peak = read_memory_mb(os.getpid())
    model_now, model_peak = server.memory_mb()
    return {
        "models": [{"key": key, "label": item["label"], "installed": (MODEL_DIR / item["file"]).exists()}
                   for key, item in MODELS.items()],
        "active_model": server.model_key,
        "model_ready": server.is_running(),
        "context_size": CONTEXT_SIZE,
        "ram_mb": backend_now + model_now,
        "peak_ram_mb": backend_peak + model_peak,
        "model_ram_mb": model_now,
        "backend_ram_mb": backend_now,
        "disk_free_gb": shutil.disk_usage(UPLOAD_DIR.parent).free // (1024 ** 3),
    }


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
