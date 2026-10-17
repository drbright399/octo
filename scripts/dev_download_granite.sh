#!/usr/bin/env bash
# scripts/dev_download_granite.sh — download Granite 3.1 8B Instruct
# Q4_K_M for local dev. Uses Bartowski's GGUF repo (mirrors the
# Qwen download pattern) — IBM's own GGUF repo path was unreliable.
#
# Note: we use the 8B variant because IBM doesn't publish a
# straight "Granite 3B Instruct" GGUF — the 3B-A800M is an MoE.
# 8B Q4_K_M is ~4.5GB but runs comparably on CPU.
#
# Usage:
#   ./scripts/dev_download_granite.sh

set -euo pipefail

MODELS_DIR="${OCTO_LLM_DEV_MODELS_DIR:-$HOME/.octo-dev/data/octo-llm-models}"
OUT_FILE="$MODELS_DIR/granite-3.1-8b-q4.gguf"
URL="https://huggingface.co/bartowski/granite-3.1-8b-instruct-GGUF/resolve/main/granite-3.1-8b-instruct-Q4_K_M.gguf"

mkdir -p "$MODELS_DIR"

if [[ -f "$OUT_FILE" ]]; then
  SIZE_BYTES=$(stat -c%s "$OUT_FILE" 2>/dev/null || stat -f%z "$OUT_FILE")
  SIZE_MB=$(( SIZE_BYTES / 1024 / 1024 ))
  if (( SIZE_BYTES > 4000000000 )); then
    echo "Granite 8B already at $OUT_FILE (${SIZE_MB}MB) — skipping."
    exit 0
  fi
  echo "Partial / bad download detected (${SIZE_MB}MB) — removing + redownloading."
  rm -f "$OUT_FILE"
fi

echo "Downloading Granite 3.1 8B Instruct Q4_K_M (~4.5GB) to:"
echo "  $OUT_FILE"
echo "(Give it a few minutes.)"
echo

curl -L --progress-bar -f -o "$OUT_FILE" "$URL"

# Verify it's a real GGUF (magic bytes = "GGUF") + reasonable size.
# Without this check a 404 / redirect from HF gets silently saved as
# a few bytes of error text — exactly what bit us 2026-05-22 morning.
MAGIC=$(head -c 4 "$OUT_FILE" 2>/dev/null || echo "")
SIZE_BYTES=$(stat -c%s "$OUT_FILE" 2>/dev/null || stat -f%z "$OUT_FILE")
SIZE_MB=$(( SIZE_BYTES / 1024 / 1024 ))

if [[ "$MAGIC" != "GGUF" ]]; then
  echo
  echo "ERROR: downloaded file isn't a GGUF (got ${SIZE_BYTES} bytes, first 4: '${MAGIC}')."
  echo "Removing the bad file. The URL may have changed — check Hugging Face."
  rm -f "$OUT_FILE"
  exit 2
fi
if (( SIZE_BYTES < 1000000000 )); then
  echo
  echo "ERROR: file is only ${SIZE_MB}MB — expected ~4.5GB. Likely a partial download."
  echo "Removing the bad file."
  rm -f "$OUT_FILE"
  exit 2
fi

echo
echo "Done. ${SIZE_MB}MB at $OUT_FILE"
echo "GGUF magic bytes verified."
