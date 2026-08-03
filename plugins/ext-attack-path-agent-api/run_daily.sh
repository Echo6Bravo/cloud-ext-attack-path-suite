#!/usr/bin/env bash
# Headless daily driver for the External Attack-Path Agent (API-token edition, reduced fidelity).
#
# Full unattended pipeline (no model context needed): pull -> assemble -> render.
#   1. scripts/fetch_all.sh      cursor-paginate the GraphQL API -> data/raw/gql_*.json
#   2. scripts/assemble_api.py   reduced gates -> assembled.json (B empty; component=Software.Name)
#   3. scripts/render_report.py  --no-endpoint reduced-mode HTML report
#
# Required env: TENABLE_CS_API_URL, TENABLE_CS_API_TOKEN
# Optional env: DATA_DIR (default ./data), OUT_DIR (default ./output), PAGE, IDS_PER_BATCH,
#               MAX_CARDS (default 150), MAX_CVES (default 25)
set -euo pipefail

# All executable pieces live together in the skill's scripts/ dir (bundled by build.sh).
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="$PLUGIN_DIR/skills/ext-attack-path-api/scripts"
DATA_DIR="${DATA_DIR:-./data}"
OUT_DIR="${OUT_DIR:-./output}"
TODAY="$(date +%F)"

: "${TENABLE_CS_API_URL:?set TENABLE_CS_API_URL}"
: "${TENABLE_CS_API_TOKEN:?set TENABLE_CS_API_TOKEN}"
mkdir -p "$DATA_DIR" "$OUT_DIR"

echo "[$(date +%FT%T)] verifying detection spec..."
python3 "$SCRIPTS/attack_path_spec.py" >/dev/null && echo "  spec self-tests passed"

echo "[$(date +%FT%T)] 1/3 pulling data (headless, cursor-paginated)..."
RAW_DIR="$DATA_DIR/raw" bash "$SCRIPTS/fetch_all.sh"

echo "[$(date +%FT%T)] 2/3 assembling (reduced-fidelity gates)..."
python3 "$SCRIPTS/assemble_api.py" --raw "$DATA_DIR/raw" --out "$DATA_DIR/assembled.json"

OUT="$OUT_DIR/attack-paths-report-api-$TODAY.html"
echo "[$(date +%FT%T)] 3/3 rendering $OUT ..."
python3 "$SCRIPTS/render_report.py" --data "$DATA_DIR" --date "$TODAY" --no-endpoint \
  --max-cards "${MAX_CARDS:-150}" --max-cves-per-host "${MAX_CVES:-25}" --out "$OUT"
echo "[$(date +%FT%T)] done -> $OUT  (reduced-fidelity; see report banner)"
