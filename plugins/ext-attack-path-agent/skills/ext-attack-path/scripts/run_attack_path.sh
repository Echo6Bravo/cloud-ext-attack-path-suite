#!/usr/bin/env bash
# run_attack_path.sh -- ONE-COMMAND, full-fidelity MCP attack-path report at any scale.
#
# The MCP edition pulls data THROUGH a model's context, so a large tenant can't be pulled in a
# single session. This orchestrator keeps FULL MCP fidelity (every gate intact -- no API-edition
# fallback) by fanning the work out across SEPARATE headless `claude` sessions, one per
# account/region chunk, each holding only its small slice, then merging on disk into one report.
#
# It is turnkey: it sizes the tenant itself, plans the chunks deterministically, shows you the
# plan, and (after you confirm) runs the fan-out and renders a single report. No hand-authored
# sizes.json, no manual per-account runs.
#
#   size  -> one cheap grouped MCP call tallies qualifying CVE-rows per account (+region)
#   plan  -> attack_path_spec.py plan picks: one tenant run / one per account / region-split
#   PAUSE -> shows the plan + how many headless sessions it will spawn; asks to proceed
#   pull  -> one fresh `claude -p` per chunk, scoped via build_*_query(account=,region=)
#   merge -> assemble.py + render_report.py across all raw pages -> one HTML report
#
# Prereqs: Claude Code CLI (`claude`) with a Tenable Cloud Security UDM MCP connector; python3.
#
# Usage:
#   ./run_attack_path.sh [--connector NAME] [--budget N] [--data DIR] [--date YYYY-MM-DD]
#                        [--sizes FILE] [--yes]
#     --connector NAME  UDM MCP connector/server name (default: auto-detected from `claude mcp list`).
#     --budget N        max qualifying CVE-rows per chunk before splitting (default 4000).
#     --data DIR        working dir for raw pages + assembled.json (default ./data).
#     --date YYYY-MM-DD report date (default today).
#     --sizes FILE      skip auto-sizing; use this pre-measured sizes.json.
#     --yes             skip the confirmation prompt (for schedulers / CI).
#
# Testability: every `claude` invocation goes through $CLAUDE_BIN (default "claude"); tests set
# CLAUDE_BIN to a stub that emits fixture pages, so the size->plan->merge->render loop is
# verifiable without a live tenant.
#
# Exit codes: 0 = complete report; 3 = report produced but INCOMPLETE (some chunks failed);
#             2 = usage/precondition error; 1 = nothing pulled (total failure).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
DATA_DIR="./data"; DATE="$(date +%F)"; BUDGET=4000; CONNECTOR=""; SIZES=""; ASSUME_YES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --connector) CONNECTOR="${2:-}"; shift 2;;
    --budget)    BUDGET="${2:-}"; shift 2;;
    --data)      DATA_DIR="${2:-}"; shift 2;;
    --date)      DATE="${2:-}"; shift 2;;
    --sizes)     SIZES="${2:-}"; shift 2;;
    --yes|-y)    ASSUME_YES=1; shift;;
    -h|--help)   sed -n '2,40p' "$0"; exit 0;;
    *) echo "run_attack_path: unknown arg: $1" >&2; exit 2;;
  esac
done

log(){ echo "[$(date +%FT%T)] $*"; }
die(){ echo "run_attack_path: ERROR: $*" >&2; exit 2; }

case "$BUDGET" in (*[!0-9]*|"") die "--budget must be a positive integer, got '${BUDGET}'";; esac
[ "$BUDGET" -ge 1 ] || die "--budget must be >= 1"

command -v python3 >/dev/null 2>&1 || die "python3 not found"
command -v "$CLAUDE_BIN" >/dev/null 2>&1 || die "Claude Code CLI ('$CLAUDE_BIN') not found on PATH"

# --- 0. resolve the UDM MCP connector name --------------------------------------------------
# The pull tools are named mcp__<connector>__udm_execute_query. The connector name varies per
# environment (e.g. 'tenablecs-org1'), so NEVER hardcode it. Prefer --connector; else auto-detect
# the single Tenable-Cloud-Security-looking server from `claude mcp list`.
if [ -z "$CONNECTOR" ]; then
  # names appear as "<name>: <url> (TYPE) - <status>"; match Tenable-CS-ish UDM servers.
  cand="$("$CLAUDE_BIN" mcp list 2>/dev/null | sed -n 's/^\([A-Za-z0-9_-]*\):.*/\1/p' \
          | grep -iE 'tenablecs|tenable-cs|tenable_cs|^tcs$|cloudsec' || true)"
  n="$(printf '%s\n' "$cand" | grep -c . || true)"
  if [ "$n" -eq 1 ]; then
    CONNECTOR="$(printf '%s\n' "$cand" | head -1)"
    log "auto-detected UDM connector: $CONNECTOR"
  else
    die "could not auto-detect the UDM connector ($n candidates). Pass --connector <name> (see: $CLAUDE_BIN mcp list)."
  fi
fi
UDM_TOOL="mcp__${CONNECTOR}__udm_execute_query"

mkdir -p "$DATA_DIR"
# Absolute path: headless sessions get it via --add-dir, which must be unambiguous.
DATA_DIR="$(cd "$DATA_DIR" && pwd)"
RAW_DIR="$DATA_DIR/raw"; mkdir -p "$RAW_DIR"
rm -f "$RAW_DIR"/raw_*.json "$DATA_DIR/_coverage_gap.txt" 2>/dev/null || true

# A headless `claude -p` runs non-interactively: it CANNOT answer a permission prompt, so any
# tool it needs must be pre-authorized or it stalls. We (a) --add-dir the data dir so writing raw
# pages there is allowed, and (b) --permission-mode acceptEdits so file writes + the explicitly
# --allowedTools MCP call proceed without prompting. We do NOT use --dangerously-skip-permissions:
# the grant stays scoped to the one MCP tool + writes under the data dir.
CLAUDE_PERM=(--add-dir "$DATA_DIR" --permission-mode acceptEdits)

# --- 1. SIZE (auto, unless --sizes provided) ------------------------------------------------
if [ -z "$SIZES" ]; then
  SIZES="$DATA_DIR/sizes.json"
  log "sizing tenant (grouped CVE-row counts per account + region)..."
  size_prompt="SIZING ONLY -- do not pull findings. Using the ${CONNECTOR} Tenable Cloud Security MCP
connector, run the two grouped counting queries from the bundled spec and write a sizes.json.
Steps:
1. python3 attack_path_spec.py -> generate build_account_sizing_query(by='account') and
   build_account_sizing_query(by='region').
2. Execute each via the ${UDM_TOOL} tool (grouped count queries; one call each; no pagination).
3. From the by-account results build {\"accounts\":{\"<EntityTenant Id>\":<count>,...}} and from
   the by-region results {\"regions\":{\"<EntityTenant Id>|<EntityRegion>\":<count>,...}}.
4. Write the combined JSON object {\"accounts\":{...},\"regions\":{...}} to ${SIZES}. Nothing else."
  if ! "$CLAUDE_BIN" -p "$size_prompt" --allowedTools "$UDM_TOOL" "Write" "${CLAUDE_PERM[@]}" </dev/null; then
    die "sizing run failed. Re-run, or pass a pre-measured --sizes FILE."
  fi
  [ -f "$SIZES" ] || die "sizing did not produce $SIZES (the agent may lack connector access)."
fi

# validate sizes.json has at least one account (fail loud, not a silent empty report)
python3 - "$SIZES" <<'PY' || die "sizes.json invalid or has no accounts (see message above)"
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception as e: print(f"cannot parse sizes.json: {e}",file=sys.stderr); sys.exit(1)
if not isinstance(d,dict) or not (d.get("accounts") or {}): print("no 'accounts' entries",file=sys.stderr); sys.exit(1)
PY

# --- 2. PLAN (deterministic) ----------------------------------------------------------------
python3 "$ROOT/attack_path_spec.py" plan "$SIZES" "$BUDGET" > "$RAW_DIR/_plan.json" \
  || die "planning failed (see $RAW_DIR/_plan.json / message above)"
PLAN_TSV="$(python3 "$ROOT/attack_path_spec.py" plan "$SIZES" "$BUDGET" --tsv)"
MODE="$(printf '%s\n' "$PLAN_TSV" | awk -F'\t' '$1=="MODE"{print $2}')"
OVERN="$(printf '%s\n' "$PLAN_TSV" | awk -F'\t' '$1=="MODE"{print $3}')"
printf '%s\n' "$PLAN_TSV" | grep -v '^MODE' > "$RAW_DIR/_chunks.tsv"
NCHUNKS="$(grep -c . "$RAW_DIR/_chunks.tsv" || true)"

log "plan: mode=$MODE budget=$BUDGET chunks=$NCHUNKS connector=$CONNECTOR"
if [ "${OVERN:-0}" != "0" ]; then
  log "WARNING: $OVERN scope(s) exceed budget even after region split -- they will pull but MAY be"
  log "         truncated by context. Narrow (severity/time) or raise --budget deliberately."
fi

# --- 3. CONFIRM (fan-out spawns N token-consuming sessions) ---------------------------------
if [ "$ASSUME_YES" -ne 1 ]; then
  echo ""
  echo "About to run $NCHUNKS headless '$CLAUDE_BIN' session(s) (mode=$MODE) against connector '$CONNECTOR'."
  echo "Each pulls one scope through model context and consumes tokens. Plan: $RAW_DIR/_plan.json"
  printf "Proceed? [y/N] "
  if [ -r /dev/tty ]; then read -r ans </dev/tty; else read -r ans || ans=""; fi
  case "$ans" in [yY]|[yY][eE][sS]) ;; *) echo "aborted (no sessions run)."; exit 0;; esac
fi

# --- 4. PULL per chunk (fresh headless session each; partial-failure tolerant) --------------
# We PRE-GENERATE the three scoped query JSONs here (in this trusted shell -- no sub-agent code
# execution / Bash permission needed) and hand them to the headless session, which only has to
# execute each via the MCP tool, paginate, and write raw pages. This keeps the sub-agent's grant
# minimal (the one MCP tool + Write under --add-dir) and removes the fragile "let the agent run
# python3" step that a non-interactive session cannot get approved.
run_scope () {
  local tag="$1" acct="$2" region="$3"
  local qdir="$RAW_DIR/_queries_${tag}"; mkdir -p "$qdir"
  # generate scoped A/B/C queries to files; failure here is a real error for this scope.
  if ! ROOT="$ROOT" QDIR="$qdir" ACCT="$acct" REGION="$region" python3 - <<'PY'
import os, json, sys
sys.path.insert(0, os.environ["ROOT"])
import attack_path_spec as s
acct=os.environ["ACCT"] or None; region=os.environ["REGION"] or None
kw={}
if acct: kw["account"]=acct
if region: kw["region"]=region
qd=os.environ["QDIR"]
json.dump(s.build_inventory_query(**kw), open(f"{qd}/A.json","w"))
json.dump(s.build_endpoints_query(**kw), open(f"{qd}/B.json","w"))
json.dump(s.build_cve_query(**kw),       open(f"{qd}/C.json","w"))
PY
  then
    echo "  [${tag}] could not generate scoped queries" >&2; return 1
  fi
  local prompt="Pull external attack-path data for Tenable Cloud Security via the ${CONNECTOR} MCP
connector, scope tag '${tag}'. Three ready-to-run UDM query JSON files are on disk -- do NOT write
or modify queries, just READ and EXECUTE them:
  ${qdir}/A.json  (inventory)
  ${qdir}/B.json  (endpoints)
  ${qdir}/C.json  (cves)
For each of A, B, C: read the file, pass its exact contents as the 'query' argument to the
${UDM_TOOL} tool with skip=0, then repeat with skip incremented by 20 while the response's
hasMore is true. Write EACH raw response page VERBATIM (the full JSON the tool returns) to
${RAW_DIR}/raw_A_${tag}_p<N>.json, raw_B_${tag}_p<N>.json, raw_C_${tag}_p<N>.json (N = 0,1,2,...).
Do NOT assemble, merge, or render. Only read the 3 query files and write raw response pages.
You have the ${UDM_TOOL} tool and Write; no other tools are needed."
  log "--- pull scope: ${tag} ---"
  "$CLAUDE_BIN" -p "$prompt" --allowedTools "$UDM_TOOL" "Write" "Read" "${CLAUDE_PERM[@]}" </dev/null
}

NFAILED=0; FAILED_SCOPES=""
while IFS=$'\t' read -r tag acct region; do
  [ -z "$tag" ] && continue
  if ! run_scope "$tag" "$acct" "$region"; then
    NFAILED=$((NFAILED+1)); FAILED_SCOPES="${FAILED_SCOPES}${FAILED_SCOPES:+, }${tag}"
    log "WARNING: scope '$tag' failed -- recording gap and continuing"
  fi
done < "$RAW_DIR/_chunks.tsv"

if [ "$NCHUNKS" -gt 0 ] && [ "$NFAILED" -ge "$NCHUNKS" ]; then
  log "ERROR: all $NCHUNKS chunk(s) failed; no data pulled. Aborting."; exit 1
fi
if [ "$NFAILED" -gt 0 ]; then
  GAP="INCOMPLETE: ${NFAILED} of ${NCHUNKS} scopes failed and are MISSING from this report: ${FAILED_SCOPES}. Re-run those scopes."
  log "WARNING: $GAP"; printf '%s\n' "$GAP" > "$DATA_DIR/_coverage_gap.txt"
fi

# --- 5. MERGE + RENDER (of whatever succeeded) ----------------------------------------------
log "assembling from $((NCHUNKS-NFAILED))/${NCHUNKS} scope(s)..."
python3 "$ROOT/assemble.py" --raw "$RAW_DIR" --out "$DATA_DIR/assembled.json" \
  --endpoint-ips "$DATA_DIR/endpoint_ips.json" || die "assemble failed"
mkdir -p "$ROOT/output"
OUT="$ROOT/output/attack-paths-report-${DATE}.html"
python3 "$ROOT/render_report.py" --data "$DATA_DIR" --date "$DATE" --out "$OUT" || die "render failed"
log "done -> $OUT"

if [ "$NFAILED" -gt 0 ]; then
  log "NOTE: report is INCOMPLETE ($NFAILED scope(s) missing: $FAILED_SCOPES); exit 3."; exit 3
fi
