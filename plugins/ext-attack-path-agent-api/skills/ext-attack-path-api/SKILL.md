---
name: ext-attack-path-api
description: >-
  Autonomously produce a REDUCED-FIDELITY external attack-path report from live Tenable
  Cloud Security data via the public GraphQL API with a Bearer API token (no MCP
  connection). Reports internet-direct, wide-open virtual machines that carry an open,
  network-exploitable (AV:N) vulnerability with public/real-world exploitation evidence
  (EPSS >= 0.30 OR exploit maturity Functional/High), grouped by cloud provider/account.
  This edition is a deliberate subset of the MCP edition — the GraphQL API cannot express
  several gates the MCP/UDM edition enforces (see "Fidelity gap"). Use for headless /
  scheduled triage where no MCP connector is available. Never fabricates data.
---

# External Attack-Path Agent (API-token edition, reduced fidelity)

Produce an external attack-path report from the Tenable Cloud Security **public GraphQL
API** using a **Bearer API token** — no MCP connector required. Built for headless /
scheduled (e.g. daily cron) use. **Never fabricate data — every value must come from a
query result.**

> **This edition is intentionally lower-fidelity than the MCP edition.** The GraphQL API
> exposes fewer of the signals the detection contract needs. Rather than pretend
> otherwise, this agent enforces the subset the API *can* express, applies the rest
> best-effort, and **states the gap in every report it writes**. When the richest results
> matter, use the MCP edition (`ext-attack-path-agent`). The field mappings below were
> **verified by live schema introspection** against `https://app.tenable.com/api/graph`.

## Prerequisites

- **bash 3.2+** (no bash-4 features), **curl** (any 7.x+; no `--fail-with-body` dependency),
  **jq 1.5+**. All shell uses POSIX-portable flags (GNU and BSD/macOS).
- **Python 3.7+** (standard library only) for the bundled spec + renderer under
  `scripts/` (`attack_path_spec.py`, `render_report.py`, `assemble_api.py`).
- Environment variables:
  - `TENABLE_CS_API_URL` — GraphQL endpoint (commercial default
    `https://app.tenable.com/api/graph`; confirm your region/platform in the console).
  - `TENABLE_CS_API_TOKEN` — a Tenable Cloud Security API token, sent as a Bearer token.
- The caller `scripts/tcs_graphql.sh` reads a GraphQL query on stdin and POSTs it. Keep
  the token in the environment or a secrets manager — **never** commit it (the repo
  `.gitignore` blocks `*.env`, `*token*.json`, etc.).

## The MCP contract vs. what the GraphQL API can enforce

`scripts/attack_path_spec.py` remains the single source of truth for the **full**
contract (run `python3 scripts/attack_path_spec.py`; it must print
`ALL SELF-TESTS PASSED`). This edition maps each gate to the GraphQL API as follows —
**verified live**, not assumed:

| # | Full gate (MCP/UDM) | GraphQL API | Status |
|---|---------------------|-------------|--------|
| 1 | Running VM (`VirtualMachineStatus ≠ Stopped`) | *no VM status field exists* | ❌ **dropped** |
| 2 | Internet-direct (`ExternalDirect`) | `VirtualMachine.NetworkAccess.Inbound.Accesses[].Type = InternetDirect` | ✅ enforced |
| 3 | Wide/All scope | `...Accesses[].Scope ∈ {Wide, All}` | ✅ enforced |
| 4 | **Observed listening endpoint** | only SG rule `Connections[].DestinationPortRange` exists (a *rule*, not an observed listener) | ❌ **dropped** — methodology forbids using SG ranges as evidence of a listener |
| 5 | Open finding | `VulnerabilityInstances(filter:{Resolved:false})` | ✅ enforced |
| 6 | AV:N | `Vulnerability.AttackVector = Network` | ✅ enforced |
| 7 | AC:Low | *no AttackComplexity field exists* | ❌ **dropped** |
| 8 | Component **is** the exposed service | `VulnerabilityInstance.Software.Name` available, but no observed port to correlate against | ⚠️ **partial** — software name is shown, not correlated to a port |
| 9 | EPSS ≥ 0.30 **OR** CISA KEV | `Vulnerability.EpssScore` ✅; **no CISA-KEV field** — substitute `Vulnerability.ExploitMaturity ∈ {Functional, High}` | ⚠️ EPSS exact; KEV **substituted** (weaker, different signal) |

**Net effect:** this edition finds *internet-direct, wide-open VMs with an open,
network-exploitable, publicly-evidenced vulnerability*. It **cannot** confirm the workload
is running, that a service is actually listening on a reachable port, that the vuln is
low-complexity, or that the CVE is on CISA KEV. Treat its output as a **candidate list to
triage**, not the defensible, de-noised path list the MCP edition produces. Do not relax
the gates it *can* enforce to compensate.

## Workflow

### 1. Verify the shared spec
Run `python3 scripts/attack_path_spec.py`; confirm `ALL SELF-TESTS PASSED`. (It
documents the full contract this edition is a subset of.)

### 2. Confirm connectivity and schema-drift canary (BEFORE pulling)
```bash
echo 'query { __typename }' | ./scripts/tcs_graphql.sh   # expect {"data":{"__typename":"Query"}}
```
Then verify the fields the queries depend on still exist — the GraphQL analogue of the MCP
edition's `check_schema`. Introspect each type the pull uses and confirm the required fields
are present, e.g.:
```bash
echo 'query { __type(name:"Vulnerability"){ fields { name } } }' | ./scripts/tcs_graphql.sh \
  | jq -r '.data.__type.fields[].name' | grep -E 'AttackVector|EpssScore|ExploitMaturity' 
```
Required (see `references/graphql-queries.md` for the full map): `VirtualMachine.NetworkAccess.Inbound.Accesses{Type,Scope}`;
`VulnerabilityInstance.{Resolved,Software.Name,Resource.Name}`; `Vulnerability.{AttackVector,EpssScore,ExploitMaturity}`.
**If any required field is absent, STOP and report the missing field/type** — do not pull or
render (a renamed field would silently return empty). The schema can evolve; **never invent
field names** — re-introspect and update `references/graphql-queries.md` first.

### 3. Establish scope
Report the accounts/providers in scope from `VirtualMachine.Provider` / `AccountId`, and
capture the report date.

### 4. Pull the data (cursor-paginated)
**Preferred (scales headless):** run the bundled `scripts/fetch_all.sh`. It cursor-paginates
both connections and streams each page to `data/raw/gql_*.json` with no model context —
this is the path that scales to 50k+ VMs (a large tenant is just more pages of the same
loop). Then `scripts/assemble_api.py --raw ./data/raw --out ./data/assembled.json` applies
the reduced gates and writes the renderer's dataset. Set `PAGE` (default 500) and `RAW_DIR`
via env. Verified live against `app.tenable.com/api/graph`.

If pulling manually instead, use the concrete queries in `references/graphql-queries.md`.
GraphQL connections paginate on `pageInfo.hasNextPage` / `endCursor` — loop, don't stop at
the first page.

- **Exposed VMs:** `VirtualMachines(first:100, after:$cursor)`, selecting
  `Name, Provider, AccountId, NetworkAccess { Inbound { Accesses { Type Scope } } }`.
  Keep a VM only if some access has `Type = InternetDirect` AND `Scope ∈ {Wide, All}`
  (gates 2–3). Note: privilege/severe-permission tiering (`SeverePermissionActionPrincipalAttribute`
  in UDM) has **no** confirmed GraphQL field — everything lands in a single un-tiered list
  unless you find a `Labels`/`CustomProperties` signal for it; if so, document it.
- **Qualifying vulns:** `VulnerabilityInstances(filter:{Resolved:false, VulnerabilitySeverities:[…]}, first:200, after:$cursor)`,
  selecting `Software { Name Version }, Resource { Name }, Vulnerability { Id AttackVector
  EpssScore CvssScore ExploitMaturity Severity }`. Keep a node only if
  `AttackVector = Network` AND (`EpssScore ≥ 0.30` OR `ExploitMaturity ∈ {Functional, High}`)
  (gates 6 + reduced-9). Carry `Software.Name` as `component` (reduced gate 8).

### 5. Assemble and render (shared renderer)
`assemble_api.py` (step 4) writes `assembled.json = {"A":[inventory], "B":[], "C":[cve rows]}`
— **B** is intentionally empty (no observed endpoint; gate 4 dropped) and each C row's
`component` comes from `Software.Name`. Then render:
```bash
python3 scripts/render_report.py --data ./data --date <YYYY-MM-DD> \
    --no-endpoint --out ./output/attack-paths-report-api.html
```
`--no-endpoint` puts the renderer in **reduced mode**: because dataset B is empty, gate 8
degrades to the *listening-component* test only (keeps sshd/nginx/httpd/etc., still drops
clients/libraries like Thunderbird/libgnutls/kernel), the stopped-VM net still applies, and
the report is bannered as reduced-fidelity (candidates, port not confirmed). The renderer
also auto-enables this when B is empty, but pass the flag explicitly. Without it the full
gate 8 would reject **every** row (no observed ports → nothing correlates). The same
`--max-cards` / `--max-cves-per-host` scale caps apply (see MCP SKILL.md).

> **Scale (stress-tested).** `assemble_api.py` streams pages, so it handles very large pulls
> cheaply (measured: 300k raw rows / 302 pages → 1.5 s, ~113 MB). `render_report.py` holds the
> surviving rows in memory (measured: ~111k rows → ~286 MB, 2.5 MB capped HTML vs 28 MB
> uncapped), so the `--max-cards`/`--max-cves-per-host` caps are what keep the HTML openable.
> If a single scope yields *millions* of surviving rows, bound the set before rendering with
> `assemble_api.py --max-hosts N` (keeps the N hosts with the most qualifying CVEs).

### 6. Deliver — and STATE THE FIDELITY GAP
Present the report path and a 2–3 sentence summary. **Every API-edition report must
include a prominent note** that it is reduced-fidelity: it did not verify running-state, a
live listening endpoint, AC:Low, or CISA-KEV membership, and that findings are candidates
to confirm (ideally re-run the MCP edition for the authoritative list). List the exact
gates enforced vs. dropped (the table above). Flag demo/test-looking environments.

## Optional: run it daily (headless)
`run_daily.sh` verifies the spec and renders once `assembled.json` exists. Schedule the
data pull ahead of it. Example crontab (07:00 daily):
```
0 7 * * * cd /path/to/repo && TENABLE_CS_API_URL=... TENABLE_CS_API_TOKEN=... \
  bash plugins/ext-attack-path-agent-api/run_daily.sh >> /var/log/ext-attack-path.log 2>&1
```
Keep the token and any real assessment data out of version control.
