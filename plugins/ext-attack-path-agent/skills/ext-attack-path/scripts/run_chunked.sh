#!/usr/bin/env bash
# run_chunked.sh -- large-environment driver for the MCP edition.
#
# The MCP edition pulls data THROUGH the model's context, so a whole large tenant can't be
# pulled in one run (see SKILL.md "Scaling"). This driver keeps FULL MCP fidelity by
# chunking the pull BY CLOUD ACCOUNT: it runs one headless Claude session per account (each a
# fresh context that resets between accounts), each appending its raw pages to a shared
# raw/ dir, then assembles + renders ONE merged report across all accounts.
#
# This is "much more scalable, not infinitely scalable": it scales to the size of the
# LARGEST SINGLE ACCOUNT (which must still fit one context), not the whole estate. If one
# account is itself too big, sub-chunk it by region (see --max-per-account guard below).
#
# Prereqs: Claude Code CLI (`claude`) with the tcs MCP connector configured; python3.
# Usage:
#   ./run_chunked.sh --accounts "111111111111 222222222222"    # explicit list, or
#   ./run_chunked.sh --accounts-file accounts.txt              # one account id per line
#   (obtain the list + per-account sizes from build_account_sizing_query(); see SKILL.md)
# Optional: --data DIR (default ./data), --date YYYY-MM-DD, --max-per-account N (safety cap).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="./data"; DATE="$(date +%F)"; ACCOUNTS=""; ACCT_FILE=""; MAX_PER_ACCOUNT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --accounts) ACCOUNTS="$2"; shift 2;;
    --accounts-file) ACCT_FILE="$2"; shift 2;;
    --data) DATA_DIR="$2"; shift 2;;
    --date) DATE="$2"; shift 2;;
    --max-per-account) MAX_PER_ACCOUNT="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$ACCT_FILE" ] && ACCOUNTS="$(tr '\n' ' ' < "$ACCT_FILE")"
if [ -z "$ACCOUNTS" ]; then
  echo "No accounts given. Enumerate them first with the sizing query (build_account_sizing_query)," >&2
  echo "then pass --accounts \"id1 id2 ...\" or --accounts-file accounts.txt." >&2
  exit 2
fi

RAW_DIR="$DATA_DIR/raw"
mkdir -p "$RAW_DIR"
rm -f "$RAW_DIR"/raw_*.json 2>/dev/null || true   # fresh merge each run

echo "[$(date +%FT%T)] chunked MCP pull over $(echo $ACCOUNTS | wc -w) account(s)"
i=0
for acct in $ACCOUNTS; do
  i=$((i+1))
  echo "[$(date +%FT%T)] === account $i: $acct ==="
  # One fresh headless Claude session PER account. The prompt tells the skill to scope to this
  # account and write its raw pages into $RAW_DIR with an account-tagged prefix so pages merge.
  # `claude -p` runs headless with a fresh context (the essential reset between accounts).
  prompt="Run the ext-attack-path skill for Tenable Cloud Security, SCOPED TO CLOUD ACCOUNT ${acct} only.
Use attack_path_spec.build_inventory_query(account='${acct}'), build_endpoints_query(account='${acct}'),
and build_cve_query(account='${acct}') to generate the queries. Paginate each fully via the tcs MCP
udm_execute_query tool. Save each raw response page verbatim to files named
${RAW_DIR}/raw_A_${acct}_p<N>.json, raw_B_${acct}_p<N>.json, raw_C_${acct}_p<N>.json.
Before pulling, run udm_get_query_results_count on the CVE query for this account; if it exceeds
what one context can hold, STOP and report that this account must be sub-chunked by region --
do not silently truncate. Do NOT assemble or render; only write raw pages."
  if command -v claude >/dev/null 2>&1; then
    claude -p "$prompt" --allowedTools "mcp__tcs__udm_execute_query" "mcp__tcs__udm_get_query_results_count" "Write" \
      || { echo "  [account $acct] claude run failed" >&2; exit 1; }
  else
    echo "  'claude' CLI not found. Run this prompt manually in a fresh Claude Code session:" >&2
    echo "  ---"; echo "$prompt"; echo "  ---"
    echo "  Then re-run this script to assemble once all accounts' raw pages exist." >&2
  fi
done

echo "[$(date +%FT%T)] assembling merged report across all accounts..."
python3 "$ROOT/assemble.py" --raw "$RAW_DIR" --out "$DATA_DIR/assembled.json" \
  --endpoint-ips "$DATA_DIR/endpoint_ips.json" ${MAX_PER_ACCOUNT:+}
python3 "$ROOT/render_report.py" --data "$DATA_DIR" --date "$DATE" \
  --out "./output/attack-paths-report-${DATE}.html"
echo "[$(date +%FT%T)] done -> ./output/attack-paths-report-${DATE}.html"
