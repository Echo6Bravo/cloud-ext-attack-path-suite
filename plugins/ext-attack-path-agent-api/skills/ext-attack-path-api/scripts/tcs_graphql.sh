#!/usr/bin/env bash
# Tenable Cloud Security GraphQL caller (Bearer API token).
# Reads a GraphQL query from stdin and POSTs it to the /graphql endpoint.
#
# Required environment variables:
#   TENABLE_CS_API_URL    Tenable Cloud Security GraphQL endpoint.
#                         Default/commercial: https://app.tenable.com/api/graph
#                         (other regions/platforms may differ — confirm in the console / docs)
#   TENABLE_CS_API_TOKEN  API token generated in Tenable Cloud Security (used as a Bearer token)
#
# Dependencies: bash, curl, jq. Uses only widely-portable flags (no curl --fail-with-body,
# which needs curl 7.76+/2021 and is absent on RHEL7/8-era curl); HTTP status is checked
# portably via -w so this works on older enterprise curl too.
#
# Usage:
#   echo '{ ... }' | ./tcs_graphql.sh
#   ./tcs_graphql.sh < query.graphql | jq '.data'
set -euo pipefail

: "${TENABLE_CS_API_URL:?Set TENABLE_CS_API_URL to the GraphQL endpoint, e.g. https://app.tenable.com/api/graph}"
: "${TENABLE_CS_API_TOKEN:?Set TENABLE_CS_API_TOKEN to your Tenable Cloud Security API token}"

QUERY="$(cat)"

# Build a JSON body { "query": "..." } safely, then POST with Bearer auth.
# Append the HTTP status on its own trailing line via -w, then split body/status in shell so
# we fail on >=400 while still surfacing the error body -- portable back to curl 7.x.
_resp="$(jq -nc --arg q "$QUERY" '{query: $q}' \
  | curl -sS -X POST "$TENABLE_CS_API_URL" \
      -H "Authorization: Bearer ${TENABLE_CS_API_TOKEN}" \
      -H "Content-Type: application/json" \
      -H "User-Agent: ext-attack-path-agent/1.0" \
      --data-binary @- \
      -w $'\n%{http_code}')"
_code="${_resp##*$'\n'}"      # last line = status
_body="${_resp%$'\n'*}"       # everything before it = response body
printf '%s' "$_body"
case "$_code" in
  2*) : ;;                    # 2xx OK
  *) echo "tcs_graphql: HTTP $_code from $TENABLE_CS_API_URL" >&2; exit 22 ;;
esac
