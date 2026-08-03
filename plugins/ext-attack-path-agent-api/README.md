# External Attack-Path Agent — API-token edition (reduced fidelity)

A Claude Code skill that produces an external attack-path report from the Tenable Cloud
Security **public GraphQL API** with a **Bearer API token** — **no MCP connector
required**. Built for headless / scheduled (daily) use.

> **This edition is a deliberate subset of the MCP edition.** Live schema introspection
> confirmed the GraphQL API does not expose several signals the full detection contract
> needs. This edition enforces what it *can*, applies the rest best-effort, and **states
> the gap in every report**. For the authoritative, de-noised path list, use the MCP
> edition (`ext-attack-path-agent`).

## What it enforces vs. drops (verified against the live GraphQL schema)

| Full contract gate | GraphQL API | This edition |
|--------------------|-------------|--------------|
| Internet-direct exposure | `NetworkAccess.Inbound.Accesses[].Type = InternetDirect` | ✅ enforced |
| Wide/All scope | `...Scope ∈ {Wide, All}` | ✅ enforced |
| Open finding | `filter:{Resolved:false}` | ✅ enforced |
| Network-exploitable (AV:N) | `Vulnerability.AttackVector = Network` | ✅ enforced |
| Public evidence | `EpssScore ≥ 0.30` OR `ExploitMaturity ∈ {Functional,High}` | ⚠️ EPSS exact; KEV **substituted** |
| Running VM | *no status field* | ❌ dropped |
| Observed listening endpoint | only SG rule port ranges exist | ❌ dropped |
| AC:Low | *no field* | ❌ dropped |
| Component ↔ exposed port | software name only, no observed port | ⚠️ name shown, not correlated |
| Privilege tiering | *no severe-permission field* | ❌ single un-tiered list |

So output is a **candidate list to triage**, not the defensible path list the MCP edition
produces.

## What it does
1. Verifies the bundled detection spec (`ALL SELF-TESTS PASSED`) — the full contract this
   edition subsets.
2. Uses the **verified** GraphQL queries in `references/graphql-queries.md` (re-introspects
   only if a field errors; never invents field names).
3. Pulls cursor-paginated exposed-VM and open-vulnerability data, applies the enforceable
   gates client-side, and joins them.
4. Assembles `assembled.json` and renders the HTML report via the shared renderer, with a
   prominent fidelity-gap note.

## Use it
Invoke the **`ext-attack-path-api`** skill. See `skills/ext-attack-path-api/SKILL.md` for
the workflow and fidelity table, and `.../references/graphql-queries.md` for the verified
queries and schema facts.

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
- **bash 3.2+**, **curl** (any 7.x; no `--fail-with-body` dependency), **jq 1.5+**;
  **Python 3.7+** (standard library only, invoked as `python3`). Portable GNU/BSD flags only.
- A Tenable Cloud Security API token with read access.

MIT licensed. **Never commit the token or real assessment data** (the repo `.gitignore`
blocks `*.env`, `*token*.json`, etc.).
