#!/usr/bin/env bash
# run_chunked.sh -- large-environment driver for the MCP edition (Option 2: measured, not guessed).
#
# The MCP edition pulls data THROUGH the model's context, so a whole large tenant may not fit
# one run. This driver keeps FULL MCP fidelity and chooses the pull strategy DETERMINISTICALLY
# from measured CVE-row counts (the quantity that actually drives context cost):
#
#   1. SIZE:  an agent runs build_account_sizing_query() (a cheap grouped call) and writes the
#             per-account (and per-region) CVE-row counts to a sizes.json.
#   2. PLAN:  `attack_path_spec.py plan sizes.json <budget>` picks the mode deterministically:
#               total <= budget            -> ONE tenant run     (cheapest; no per-run overhead xN)
#               every account <= budget    -> one run per account (full fidelity, minimal chunks)
#               an account > budget         -> that account split by region
#               a region still > budget     -> reported as "oversized" (caller must narrow/accept)
#   3. PULL:  one fresh headless `claude -p` per chunk, scoped via build_*_query(account=,region=),
#             each writing account/region-tagged raw pages to a shared raw/ dir.
#   4. MERGE: one assemble.py + render_report.py across all pages -> a single report.
#
# Why this beats "always chunk by account": for a tenant that fits, it does ONE run instead of N,
# avoiding N x (skill load + udm_get_instructions ~10-15k tokens + tool schemas) of overhead.
#
# Prereqs: Claude Code CLI (`claude`) with the tcs MCP connector; python3.
# Usage:
#   ./run_chunked.sh --sizes sizes.json [--budget 4000] [--data ./data] [--date YYYY-MM-DD]
# sizes.json shape:
#   {"accounts":{"<id>":<cve_row_count>,...}, "regions":{"<id>|<region>":<count>,...}}
# (regions optional; needed only to split an over-budget account.)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="./data"; DATE="$(date +%F)"; SIZES=""; BUDGET=4000
while [ $# -gt 0 ]; do
  case "$1" in
    --sizes) SIZES="$2"; shift 2;;
    --budget) BUDGET="$2"; shift 2;;
    --data) DATA_DIR="$2"; shift 2;;
    --date) DATE="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
if [ -z "$SIZES" ] || [ ! -f "$SIZES" ]; then
  cat >&2 <<EOF
Need a sizes.json. First have an agent run the sizing query and tally it:
  - build_account_sizing_query(by="account")  -> per-account CVE-row counts
  - build_account_sizing_query(by="region")   -> per (account,region) counts (for oversized accts)
Write {"accounts":{...},"regions":{...}} to sizes.json, then re-run with --sizes sizes.json.
EOF
  exit 2
fi

RAW_DIR="$DATA_DIR/raw"; mkdir -p "$RAW_DIR"; rm -f "$RAW_DIR"/raw_*.json 2>/dev/null || true
# clear any stale coverage-gap marker from a prior run so a clean run isn't mis-flagged
rm -f "$DATA_DIR/_coverage_gap.txt" 2>/dev/null || true

# --- 2. PLAN (deterministic) ---
# Human-readable plan (for the log/_plan.json) and a machine-readable TSV (for the loop).
python3 "$ROOT/attack_path_spec.py" plan "$SIZES" "$BUDGET" > "$RAW_DIR/_plan.json"
PLAN_TSV="$(python3 "$ROOT/attack_path_spec.py" plan "$SIZES" "$BUDGET" --tsv)"
MODE="$(printf '%s\n' "$PLAN_TSV" | awk -F'\t' '$1=="MODE"{print $2}')"
OVERN="$(printf '%s\n' "$PLAN_TSV" | awk -F'\t' '$1=="MODE"{print $3}')"
echo "[$(date +%FT%T)] plan: mode=$MODE budget=$BUDGET"
# Fail LOUD on anything still over budget -- never silently truncate.
if [ "${OVERN:-0}" != "0" ]; then
  echo "[$(date +%FT%T)] WARNING: $OVERN scope(s) still over budget after region split (see $RAW_DIR/_plan.json)." >&2
  echo "  They will be pulled but MAY be truncated by context. Narrow further (severity/time window) or raise --budget deliberately." >&2
fi

# Partial-failure tracking: a chunk that fails is recorded and SKIPPED, not fatal -- one bad
# account must not discard the other N-1 that succeeded. Failed scopes are listed in the
# report gap-note and the run exits 3 (incomplete-but-report-produced) so a scheduler can
# alert without losing the partial result. set -e is relaxed around the per-chunk call only.
FAILED_SCOPES=""

# Emit one Claude prompt for a given scope and run it headless (fresh context each).
# Returns non-zero on failure; caller records it and continues.
run_scope () {
  local tag="$1" acct="$2" region="$3" scope_py
  if [ "$tag" = "tenant" ]; then scope_py=""      # whole tenant: no account/region scoping
  else scope_py="account='${acct}'"; [ -n "$region" ] && scope_py="${scope_py}, region='${region}'"; fi
  local prompt="Run the ext-attack-path skill for Tenable Cloud Security, scope: ${tag}.
Generate queries with attack_path_spec.build_inventory_query(${scope_py}),
build_endpoints_query(${scope_py}), build_cve_query(${scope_py}); paginate each fully via the
tcs MCP udm_execute_query tool. Save each raw response page verbatim to
${RAW_DIR}/raw_A_${tag}_p<N>.json, raw_B_${tag}_p<N>.json, raw_C_${tag}_p<N>.json.
Do NOT assemble or render; only write raw pages."
  echo "[$(date +%FT%T)] --- pull scope: ${tag} ---"
  if command -v claude >/dev/null 2>&1; then
    if ! claude -p "$prompt" --allowedTools "mcp__tcs__udm_execute_query" "Write" </dev/null; then
      echo "  [${tag}] pull FAILED -- recording gap and continuing" >&2
      return 1
    fi
  else
    echo "  'claude' CLI not found. Run this prompt in a FRESH Claude Code session, then re-run to merge:" >&2
    printf '  ---\n%s\n  ---\n' "$prompt"
  fi
  return 0
}

# --- 3. PULL per the plan (plain while-read over the TSV; no process substitution) ---
printf '%s\n' "$PLAN_TSV" | grep -v '^MODE' > "$RAW_DIR/_chunks.tsv"
NCHUNKS=0; NFAILED=0
while IFS=$'\t' read -r tag acct region; do
  [ -z "$tag" ] && continue
  NCHUNKS=$((NCHUNKS+1))
  if ! run_scope "$tag" "$acct" "$region"; then
    NFAILED=$((NFAILED+1)); FAILED_SCOPES="${FAILED_SCOPES}${FAILED_SCOPES:+, }${tag}"
  fi
done < "$RAW_DIR/_chunks.tsv"

# If EVERY chunk failed there is nothing to report -- that's a hard failure.
if [ "$NFAILED" -gt 0 ] && [ "$NFAILED" -ge "$NCHUNKS" ]; then
  echo "[$(date +%FT%T)] ERROR: all $NCHUNKS chunk(s) failed; no data pulled. Aborting." >&2
  exit 1
fi

# Record the coverage gap so it surfaces IN the report (never a silent partial).
GAP_NOTE=""
if [ "$NFAILED" -gt 0 ]; then
  GAP_NOTE="INCOMPLETE: ${NFAILED} of ${NCHUNKS} scopes failed to pull and are MISSING from this report: ${FAILED_SCOPES}. Re-run those scopes."
  echo "[$(date +%FT%T)] WARNING: $GAP_NOTE" >&2
  printf '%s\n' "$GAP_NOTE" > "$DATA_DIR/_coverage_gap.txt"
fi

# --- 4. MERGE (of whatever succeeded) ---
echo "[$(date +%FT%T)] assembling report from $((NCHUNKS-NFAILED))/${NCHUNKS} scope(s)..."
python3 "$ROOT/assemble.py" --raw "$RAW_DIR" --out "$DATA_DIR/assembled.json" --endpoint-ips "$DATA_DIR/endpoint_ips.json"
python3 "$ROOT/render_report.py" --data "$DATA_DIR" --date "$DATE" --out "./output/attack-paths-report-${DATE}.html"
echo "[$(date +%FT%T)] done -> ./output/attack-paths-report-${DATE}.html"
# Exit 3 = report produced but INCOMPLETE (some scopes missing); 0 = fully complete.
if [ "$NFAILED" -gt 0 ]; then
  echo "[$(date +%FT%T)] NOTE: report is INCOMPLETE ($NFAILED scope(s) missing: $FAILED_SCOPES); exit 3." >&2
  exit 3
fi
