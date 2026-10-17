#!/usr/bin/env bash
# scripts/dev_download_qwen3b.sh — download Qwen 2.5 3B Instruct
# Q4_K_M for local dev. Much better instruction-follower than
# TinyLlama 1.1B; recommended swap when TinyLlama responses are
# generic.
#
# ~1.9GB. Bartowski's GGUF repo on Hugging Face.
#
# Usage:
#   ./scripts/dev_download_qwen3b.sh
#
# After: dev.sh auto-picks the first .gguf alphabetically. If you
# want Qwen as default, remove or rename tinyllama-1.1b-chat.gguf
# so qwen-2.5-3b-q4.gguf wins the sort. Then restart dev.sh.

set -euo pipefail

MODELS_DIR="${OCTO_LLM_DEV_MODELS_DIR:-$HOME/.octo-dev/data/octo-llm-models}"
OUT_FILE="$MODELS_DIR/qwen-2.5-3b-q4.gguf"
URL="https://huggingface.co/bartowski/Qwen2.5-3B-Instruct-GGUF/resolve/main/Qwen2.5-3B-Instruct-Q4_K_M.gguf"

mkdir -p "$MODELS_DIR"

if [[ -f "$OUT_FILE" ]]; then
  SIZE_BYTES=$(stat -c%s "$OUT_FILE" 2>/dev/null || stat -f%z "$OUT_FILE")
  SIZE_MB=$(( SIZE_BYTES / 1024 / 1024 ))
  if (( SIZE_BYTES > 1700000000 )); then
    echo "Qwen 2.5 3B already at $OUT_FILE (${SIZE_MB}MB) — skipping."
    exit 0
  fi
  echo "Partial download detected (${SIZE_MB}MB) — resuming."
fi

echo "Downloading Qwen 2.5 3B Instruct Q4_K_M (~1.9GB) to:"
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
echo "To swap to Qwen, restart dev.sh after removing or renaming"
echo "tinyllama-1.1b-chat.gguf (auto-detect picks first GGUF"
echo "alphabetically — 'q' > 't' isn't guaranteed across locales)."
echo "Or set OCTO_LLM_MODEL_PATH=$OUT_FILE explicitly."
