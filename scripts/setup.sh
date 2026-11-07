#!/usr/bin/env bash
# Downloads everything the app needs. After this runs once the app works offline.
set -e
cd "$(dirname "$0")/.."

LLAMA_BUILD=b12182
MODEL_2B_URL="https://huggingface.co/unsloth/Qwen3.5-2B-GGUF/resolve/main/Qwen3.5-2B-Q4_K_M.gguf"
MODEL_08B_URL="https://huggingface.co/ggml-org/Qwen3.5-0.8B-GGUF/resolve/main/Qwen3.5-0.8B-Q4_0.gguf"

mkdir -p bin models data

# python packages
if python3 -m venv .venv 2>/dev/null && [ -x .venv/bin/pip ]; then
    .venv/bin/pip install -q -r requirements.txt
else
    # some distros ship python without pip, uv gets around that
    rm -rf .venv
    if ! command -v uv >/dev/null && [ ! -x bin/uv ]; then
        echo "pip not available, downloading uv"
        curl -fsSL https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-unknown-linux-gnu.tar.gz \
            | tar -xz -C bin --strip-components=1
    fi
    UV=$(command -v uv || echo bin/uv)
    "$UV" venv -q .venv
    "$UV" pip install -q --python .venv/bin/python -r requirements.txt
fi

# llama.cpp server
if [ ! -x bin/llama/llama-server ]; then
    echo "downloading llama.cpp $LLAMA_BUILD"
    mkdir -p bin/llama
    curl -fL "https://github.com/ggml-org/llama.cpp/releases/download/$LLAMA_BUILD/llama-$LLAMA_BUILD-bin-ubuntu-x64.tar.gz" \
        | tar -xz -C bin/llama --strip-components=1
fi

# models. downloaded to a .part file first so an interrupted download can continue
# and a finished one doesn't get fetched again when this script is rerun
download_model() {
    if [ -f "models/$2" ]; then
        echo "$2 already downloaded"
        return
    fi
    echo "downloading $2"
    curl -fL -C - -o "models/$2.part" "$1"
    mv "models/$2.part" "models/$2"
}
download_model "$MODEL_2B_URL" Qwen3.5-2B-Q4_K_M.gguf
download_model "$MODEL_08B_URL" Qwen3.5-0.8B-Q4_0.gguf

echo "done. start the app with ./scripts/run.sh"
