#!/usr/bin/env bash
# Headless daily driver for the External Attack-Path Agent (API-token edition).
#
# This is a THIN scheduling wrapper. It verifies the detection spec and prepares the
# working directory; the actual data pull (GraphQL introspection + the three dataset
# queries) is performed by an agent following skills/ext-attack-path-api/SKILL.md, which
# writes assembled.json into $DATA_DIR. If assembled.json is already present (e.g. a
# prior agent step wrote it), this script renders straight away.
#
# Required env: TENABLE_CS_API_URL, TENABLE_CS_API_TOKEN
# Optional env: DATA_DIR (default ./data), OUT_DIR (default ./output)
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SKILL_DIR/../.." && pwd)"
DATA_DIR="${DATA_DIR:-$REPO_ROOT/data}"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/output}"
# Use a fixed, sortable date; GNU/BSD date both support +%F.
TODAY="$(date +%F)"

: "${TENABLE_CS_API_URL:?set TENABLE_CS_API_URL}"
: "${TENABLE_CS_API_TOKEN:?set TENABLE_CS_API_TOKEN}"

mkdir -p "$DATA_DIR" "$OUT_DIR"

echo "[$(date +%FT%T)] verifying detection spec..."
python3 "$REPO_ROOT/attack_path_spec.py" >/dev/null
echo "  spec self-tests passed"

if [ ! -f "$DATA_DIR/assembled.json" ]; then
  cat >&2 <<EOF
[$(date +%FT%T)] no $DATA_DIR/assembled.json found.
This wrapper does not itself call the GraphQL API — run the agent skill
(skills/ext-attack-path-api/SKILL.md) to introspect the schema, pull datasets A/B/C,
and write assembled.json to $DATA_DIR. Then re-run this script (or schedule the agent
step ahead of it). Exiting without a report.
EOF
  exit 2
fi

OUT="$OUT_DIR/attack-paths-report-$TODAY.html"
echo "[$(date +%FT%T)] rendering $OUT ..."
python3 "$REPO_ROOT/render_report.py" --data "$DATA_DIR" --date "$TODAY" --out "$OUT"
echo "[$(date +%FT%T)] done -> $OUT"
