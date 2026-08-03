#!/usr/bin/env bash
# fetch_all.sh -- headless, paginated pull of the reduced-fidelity API-edition datasets,
# streamed to per-page raw files under $RAW_DIR (default ./data/raw). Designed to SCALE:
# it never holds more than one page in memory, writes each page to its own file, and
# critically SCOPES the (huge) vulnerability pull to only the exposed VMs found in phase 1
# via the server-side ResourceIds filter -- so it pulls vulns for the qualifying subset,
# NOT every open vulnerability in the tenant (which in a large customer is millions of rows).
#
# This is the scalable alternative to interactive MCP tool calls, which run only inside the
# model context and cannot paginate thousands of pages headlessly.
#
# Required env: TENABLE_CS_API_URL, TENABLE_CS_API_TOKEN
# Optional env: RAW_DIR (default ./data/raw), PAGE (default 5000), IDS_PER_BATCH (default 200)
#
# PAGE defaults to the API's hard maximum (1000 items/page; larger requests are rejected
# with error HC0051). The dominant cost is network round-trips (~1s each), not per-row work,
# so pulling the max per page is the main scaling lever -- at 20/page a vuln-heavy tenant is
# thousands of slow round-trips. Lower PAGE only if you hit response-size/memory limits.
#
# Pipeline: fetch_all.sh -> assemble_api.py -> render_report.py
# NOTE: REDUCED-FIDELITY edition (see graphql-queries.md); does not reproduce the full
# MCP contract (no running-state, no observed endpoint, no AC:Low, no CISA-KEV, no tiering).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALL="$HERE/tcs_graphql.sh"
RAW_DIR="${RAW_DIR:-./data/raw}"
PAGE="${PAGE:-1000}"          # API hard max is 1000 items/page (HC0051 above that)
IDS_PER_BATCH="${IDS_PER_BATCH:-200}"
: "${TENABLE_CS_API_URL:?set TENABLE_CS_API_URL}"
: "${TENABLE_CS_API_TOKEN:?set TENABLE_CS_API_TOKEN}"
mkdir -p "$RAW_DIR"
rm -f "$RAW_DIR"/gql_vms_*.json "$RAW_DIR"/gql_vulns_*.json 2>/dev/null || true

# _run <outfile> <query> : POST one query, fail loudly on GraphQL error.
_run () {
  local out="$1" q="$2"
  echo "$q" | "$CALL" > "$out"
  if jq -e '.errors' "$out" >/dev/null 2>&1; then
    echo "GraphQL error -> $out:" >&2; jq -c '.errors' "$out" >&2; return 1
  fi
  return 0
}

# ---- Phase 1: exposed VMs (gates 2-3), cursor-paginated to completion ----
echo "[$(date +%FT%T)] phase 1: exposed VMs -> $RAW_DIR"
after="null"; page=0; hasNext="true"
: > "$RAW_DIR/_exposed_ids.txt"
while [ "$hasNext" = "true" ]; do
  out="$RAW_DIR/gql_vms_$(printf '%04d' "$page").json"
  _run "$out" "query { VirtualMachines(first: $PAGE, after: $after) { pageInfo { hasNextPage endCursor } nodes { Id Name Provider AccountId Region NetworkAccess { Inbound { Accesses { Type Scope } } } } } }"
  hasNext="$(jq -r '.data.VirtualMachines.pageInfo.hasNextPage' "$out")"
  cursor="$(jq -r '.data.VirtualMachines.pageInfo.endCursor // empty' "$out")"
  n="$(jq -r '.data.VirtualMachines.nodes | length' "$out")"
  # collect Ids of VMs exposed InternetDirect + Wide/All (the only ones we pull vulns for)
  jq -r '.data.VirtualMachines.nodes[]
         | select(any(.NetworkAccess.Inbound.Accesses[]?; .Type=="InternetDirect" and (.Scope=="Wide" or .Scope=="All")))
         | .Id' "$out" >> "$RAW_DIR/_exposed_ids.txt"
  echo "  [vms] page $page: $n rows (hasNext=$hasNext)"
  [ -z "$cursor" ] && hasNext="false"
  [ "$page" -ge 100000 ] && { echo "  [vms] page cap hit" >&2; hasNext="false"; }
  after="\"$cursor\""; page=$((page+1))
done
EXPOSED=$(wc -l < "$RAW_DIR/_exposed_ids.txt" | tr -d ' ')
echo "[$(date +%FT%T)] phase 1 done: $EXPOSED exposed VMs (of $(( (page-1)*PAGE + n )) scanned)"

# ---- Phase 2: vulns for ONLY those exposed VMs, batched via ResourceIds ----
# Scopes the (otherwise tenant-wide) vuln pull to the qualifying subset. Each batch of
# IDS_PER_BATCH resource Ids is itself cursor-paginated to completion.
echo "[$(date +%FT%T)] phase 2: vulns for exposed VMs (batches of $IDS_PER_BATCH)"
if [ "$EXPOSED" -eq 0 ]; then
  echo "  no exposed VMs; nothing to pull."; echo "[$(date +%FT%T)] done."; exit 0
fi
batch=0; vpage=0
# split the id list into batches; build a JSON array per batch with jq (safe quoting)
split -l "$IDS_PER_BATCH" "$RAW_DIR/_exposed_ids.txt" "$RAW_DIR/_idbatch_"
for bf in "$RAW_DIR"/_idbatch_*; do
  idarr="$(jq -R -s -c 'split("\n") | map(select(length>0))' "$bf")"
  after="null"; hasNext="true"
  while [ "$hasNext" = "true" ]; do
    out="$RAW_DIR/gql_vulns_$(printf '%04d' "$vpage").json"
    _run "$out" "query { VulnerabilityInstances(filter: { Resolved: false, ResourceIds: $idarr }, first: $PAGE, after: $after) { pageInfo { hasNextPage endCursor } nodes { Software { Name Version } Resource { Name } Vulnerability { Id AttackVector EpssScore CvssScore ExploitMaturity Severity } } } }"
    hasNext="$(jq -r '.data.VulnerabilityInstances.pageInfo.hasNextPage' "$out")"
    cursor="$(jq -r '.data.VulnerabilityInstances.pageInfo.endCursor // empty' "$out")"
    n="$(jq -r '.data.VulnerabilityInstances.nodes | length' "$out")"
    echo "  [vulns] batch $batch page $vpage: $n rows (hasNext=$hasNext)"
    [ -z "$cursor" ] && hasNext="false"
    [ "$vpage" -ge 100000 ] && { echo "  [vulns] page cap hit" >&2; hasNext="false"; }
    after="\"$cursor\""; vpage=$((vpage+1))
  done
  batch=$((batch+1))
done
rm -f "$RAW_DIR"/_idbatch_* "$RAW_DIR/_exposed_ids.txt"
echo "[$(date +%FT%T)] done. Raw pages in $RAW_DIR. Next: assemble_api.py then render_report.py."
