#!/usr/bin/env bash
# fetch_all.sh -- headless, paginated pull of the reduced-fidelity API-edition datasets,
# streamed to per-page raw files under $RAW_DIR (default ./data/raw). Designed to SCALE:
# it never holds more than one page in memory, writes each page to its own file, and lets
# assemble.py stream them. This is the scalable alternative to interactive MCP tool calls,
# which run only inside the model context and cannot paginate thousands of pages headlessly.
#
# Required env: TENABLE_CS_API_URL, TENABLE_CS_API_TOKEN
# Optional env: RAW_DIR (default ./data/raw), PAGE (default 500)
#
# NOTE: this implements the REDUCED-FIDELITY API edition (see graphql-queries.md): exposed
# VMs (InternetDirect + Wide/All) and open, network-exploitable, EPSS/maturity vulns. It
# does NOT reproduce the MCP edition's full contract.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CALL="$HERE/tcs_graphql.sh"
RAW_DIR="${RAW_DIR:-./data/raw}"
PAGE="${PAGE:-500}"
: "${TENABLE_CS_API_URL:?set TENABLE_CS_API_URL}"
: "${TENABLE_CS_API_TOKEN:?set TENABLE_CS_API_TOKEN}"
mkdir -p "$RAW_DIR"

# Generic cursor-pagination loop: $1=label, $2=graphql query template containing __AFTER__,
# $3=jq path to the connection (for pageInfo). Streams each page to $RAW_DIR/<label>_NNN.json.
paginate () {
  local label="$1" tmpl="$2" conn="$3"
  local after="null" page=0 hasNext="true"
  while [ "$hasNext" = "true" ]; do
    local q="${tmpl//__AFTER__/$after}"
    local out="$RAW_DIR/${label}_$(printf '%04d' "$page").json"
    echo "$q" | "$CALL" > "$out"
    hasNext="$(jq -r "${conn}.pageInfo.hasNextPage" "$out")"
    local cursor; cursor="$(jq -r "${conn}.pageInfo.endCursor // empty" "$out")"
    local n; n="$(jq -r "${conn}.nodes | length" "$out")"
    echo "  [$label] page $page: $n rows (hasNext=$hasNext)"
    [ -z "$cursor" ] && break
    after="\"$cursor\""
    page=$((page+1))
    # hard safety stop so a schema change can't spin forever
    [ "$page" -gt 100000 ] && { echo "  [$label] page cap hit; stopping" >&2; break; }
  done
}

echo "[$(date +%FT%T)] fetching exposed VMs -> $RAW_DIR"
paginate "gql_vms" \
  "query { VirtualMachines(first: $PAGE, after: __AFTER__) { pageInfo { hasNextPage endCursor } nodes { Id Name Provider AccountId Region NetworkAccess { Inbound { Accesses { Type Scope } } } } } }" \
  ".data.VirtualMachines"

echo "[$(date +%FT%T)] fetching open vulnerability instances -> $RAW_DIR"
paginate "gql_vulns" \
  "query { VulnerabilityInstances(filter: { Resolved: false }, first: $PAGE, after: __AFTER__) { pageInfo { hasNextPage endCursor } nodes { Software { Name Version } Resource { Name } Vulnerability { Id AttackVector EpssScore CvssScore ExploitMaturity Severity } } } }" \
  ".data.VulnerabilityInstances"

echo "[$(date +%FT%T)] done. Raw pages in $RAW_DIR. Next: assemble_api.py then render_report.py."
