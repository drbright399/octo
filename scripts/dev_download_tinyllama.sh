#!/usr/bin/env bash
# scripts/dev_download_tinyllama.sh — download TinyLlama 1.1B Q4 for
# local dev validation of the LlamaCppBackend (slice 7b).
#
# This is a DEV-ONLY shortcut. Production model installation flows
# through the slice 5d-4 download broker (provenance + signature
# verification). TinyLlama is small (~670MB) + fast enough on CPU to
# iterate on prompt templates without waiting on Granite/Qwen
# load times.
#
# Usage:
#   ./scripts/dev_download_tinyllama.sh
#
# After:
#   OCTO_LLM_DEV=1 \
#   OCTO_LLM_BACKEND=llama-cpp \
#   OCTO_LLM_MODEL_PATH="$HOME/.octo-dev/data/octo-llm-models/tinyllama-1.1b-chat.gguf" \
#   ./scripts/dev.sh

set -euo pipefail

MODELS_DIR="${OCTO_LLM_DEV_MODELS_DIR:-$HOME/.octo-dev/data/octo-llm-models}"
OUT_FILE="$MODELS_DIR/tinyllama-1.1b-chat.gguf"

# URL in a variable so no shell wrapping can mangle it on paste.
URL="https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"

mkdir -p "$MODELS_DIR"

if [[ -f "$OUT_FILE" ]]; then
  SIZE_BYTES=$(stat -c%s "$OUT_FILE" 2>/dev/null || stat -f%z "$OUT_FILE")
  SIZE_MB=$(( SIZE_BYTES / 1024 / 1024 ))
  if (( SIZE_BYTES > 600000000 )); then
    echo "TinyLlama already at $OUT_FILE (${SIZE_MB}MB) — skipping."
    exit 0
  fi
  echo "Partial download detected (${SIZE_MB}MB) — resuming."
fi

echo "Downloading TinyLlama 1.1B Chat Q4_K_M (~670MB) to:"
echo "  $OUT_FILE"
echo

curl -L --progress-bar -f -C - -o "$OUT_FILE" "$URL"

# Verify it's a real GGUF (magic bytes = "GGUF").
MAGIC=$(head -c 4 "$OUT_FILE" 2>/dev/null || echo "")
SIZE_BYTES=$(stat -c%s "$OUT_FILE" 2>/dev/null || stat -f%z "$OUT_FILE")
SIZE_MB=$(( SIZE_BYTES / 1024 / 1024 ))
if [[ "$MAGIC" != "GGUF" ]]; then
  echo
  echo "ERROR: downloaded file isn't a GGUF (got ${SIZE_BYTES} bytes, first 4: '${MAGIC}')."
  rm -f "$OUT_FILE"
  exit 2
fi
echo
echo "Done. ${SIZE_MB}MB at $OUT_FILE — GGUF magic verified."
echo
echo "Next:"
echo "  OCTO_LLM_DEV=1 \\"
echo "  OCTO_LLM_BACKEND=llama-cpp \\"
echo "  OCTO_LLM_MODEL_PATH=\"$OUT_FILE\" \\"
echo "  ./scripts/dev.sh"
