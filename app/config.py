"""All the settings in one place."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", ROOT / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "app.db"
MODEL_DIR = ROOT / "models"
LLAMA_BIN = ROOT / "bin" / "llama" / "llama-server"

LLAMA_PORT = int(os.getenv("LLAMA_PORT", "8081"))
THREADS = int(os.getenv("LLAMA_THREADS", "2"))

MODELS = {
    "qwen-2b": {"label": "Qwen3.5 2B (Q4_K_M)", "file": "Qwen3.5-2B-Q4_K_M.gguf"},
    "qwen-0.8b": {"label": "Qwen3.5 0.8B (Q4_0)", "file": "Qwen3.5-0.8B-Q4_0.gguf"},
}
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "qwen-2b")

# token budget for one model call. everything has to fit in CONTEXT_SIZE
CONTEXT_SIZE = 2048
REPLY_TOKENS = 340      # room left for the answer
SAVED_FACTS_TOKENS = 200  # facts carried over from earlier parts
SAFETY_TOKENS = 32      # small gap so we never touch the limit

# how many log lines to repeat at the start of the next part
OVERLAP_ENTRIES = 2

CALL_TIMEOUT = int(os.getenv("CALL_TIMEOUT", "300"))
MAX_ATTEMPTS = 3

MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_ENTRY_CHARS = 1200

# set to 0 to see what the model finds with no help from the signature rules
USE_RULES = os.getenv("USE_RULES", "1") == "1"
