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
# Resilience: automatically retries transient failures -- HTTP 429 (throttling) and 5xx --
# with exponential backoff (honoring Retry-After when present). A large-tenant pull WILL be
# rate-limited; without this it would fail on the first 429. Tunable via env:
#   TCS_MAX_RETRIES (default 5), TCS_BACKOFF_BASE seconds (default 2).
# 4xx other than 429 (e.g. 401/403/400) are NOT retried -- they won't fix themselves.
#
# Usage:
#   echo '{ ... }' | ./tcs_graphql.sh
#   ./tcs_graphql.sh < query.graphql | jq '.data'
set -euo pipefail

: "${TENABLE_CS_API_URL:?Set TENABLE_CS_API_URL to the GraphQL endpoint, e.g. https://app.tenable.com/api/graph}"
: "${TENABLE_CS_API_TOKEN:?Set TENABLE_CS_API_TOKEN to your Tenable Cloud Security API token}"
MAX_RETRIES="${TCS_MAX_RETRIES:-5}"
BACKOFF_BASE="${TCS_BACKOFF_BASE:-2}"

QUERY="$(cat)"
BODY="$(jq -nc --arg q "$QUERY" '{query: $q}')"

attempt=0
while : ; do
  # Capture body + trailing status line + Retry-After header (portable; no --fail-with-body).
  _resp="$(printf '%s' "$BODY" \
    | curl -sS -X POST "$TENABLE_CS_API_URL" \
        -H "Authorization: Bearer ${TENABLE_CS_API_TOKEN}" \
        -H "Content-Type: application/json" \
        -H "User-Agent: ext-attack-path-agent/1.0" \
        -D - --data-binary @- \
        -w $'\n%{http_code}' 2>/dev/null)" || {
          # curl transport error (network blip): treat as retryable
          _code="000"; _resp=""; }
  if [ -n "${_resp:-}" ]; then
    _code="${_resp##*$'\n'}"
    _rest="${_resp%$'\n'*}"
    # body is everything after the blank line separating headers from body
    _body="$(printf '%s' "$_rest" | awk 'BEGIN{b=0} /^\r?$/{b=1;next} b{print}')"
    _retry_after="$(printf '%s' "$_rest" | awk 'tolower($1)=="retry-after:"{print $2}' | tr -d '\r')"
  fi
  case "$_code" in
    2*) printf '%s' "$_body"; exit 0 ;;                 # success
    429|5*|000)                                          # transient -> retry with backoff
      attempt=$((attempt+1))
      if [ "$attempt" -gt "$MAX_RETRIES" ]; then
        echo "tcs_graphql: giving up after $MAX_RETRIES retries (last HTTP $_code) from $TENABLE_CS_API_URL" >&2
        exit 22
      fi
      # honor Retry-After if the server sent an integer; else exponential backoff 2,4,8,...
      if printf '%s' "${_retry_after:-}" | grep -qE '^[0-9]+$'; then delay="$_retry_after"
      else delay=$(( BACKOFF_BASE ** attempt )); fi
      echo "tcs_graphql: HTTP $_code (attempt $attempt/$MAX_RETRIES); retrying in ${delay}s..." >&2
      sleep "$delay" ;;
    *)  # non-retryable 4xx (401/403/400/404...) -- surface body + fail immediately
      printf '%s' "${_body:-}"
      echo "tcs_graphql: HTTP $_code from $TENABLE_CS_API_URL (not retryable)" >&2
      exit 22 ;;
  esac
done
