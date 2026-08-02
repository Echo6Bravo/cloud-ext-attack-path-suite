# External Attack-Path Agent — API-token edition

A Claude Code skill that produces the **same** high-fidelity External Attack-Path report
as the MCP edition, but sourced through the Tenable Cloud Security **public GraphQL API**
with a **Bearer API token** — **no MCP connector required**. Built for headless /
scheduled (daily) use.

The detection contract, tiering, exclusions, and renderer are **identical** to the MCP
edition; only the data-access mechanism differs (GraphQL instead of UDM MCP tools).

## What it does
1. Verifies the bundled detection spec (`ALL SELF-TESTS PASSED`).
2. **Introspects** the live GraphQL schema and maps each gate to concrete fields (the
   schema is environment-specific — the skill never assumes field names).
3. Pulls three cursor-paginated datasets, applying the exact same gate contract.
4. Assembles `assembled.json` and renders the two-tier HTML report via the shared renderer.

## Use it
Invoke the **`ext-attack-path-api`** skill. See `skills/ext-attack-path-api/SKILL.md` for
the workflow and `.../references/graphql-queries.md` for the introspection steps and
UDM→GraphQL mapping template.

## Setup
```bash
export TENABLE_CS_API_URL="https://app.tenable.com/api/graph"   # confirm your region
export TENABLE_CS_API_TOKEN="<your Tenable Cloud Security API token>"
echo 'query { __typename }' | ./scripts/tcs_graphql.sh          # connectivity check
```

`scripts/tcs_graphql.sh` is the Bearer-token GraphQL caller (query on stdin).
`run_daily.sh` is a thin scheduling wrapper that verifies the spec and renders once
`assembled.json` exists.

## Requirements
- `bash`, `curl`, `jq`; Python 3.8+ (standard library only).
- A Tenable Cloud Security API token with read access.

MIT licensed. **Never commit the token or real assessment data** (the repo `.gitignore`
blocks `*.env`, `*token*.json`, etc.).
