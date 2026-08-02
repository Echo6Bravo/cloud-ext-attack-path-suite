---
name: ext-attack-path-api
description: >-
  Autonomously produce a high-fidelity External Attack-Path report from live Tenable
  Cloud Security data via the public GraphQL API with a Bearer API token (no MCP
  connection). Same detection contract as the MCP edition: running, internet-direct
  virtual machines whose observed listening service carries a remotely exploitable
  (AV:N, AC:Low) vulnerability with public evidence (EPSS >= 0.30 OR CISA KEV),
  component-to-port correlation, and cloud-identity-blast-radius tiering. Use for
  headless/scheduled external attack-path triage where no MCP connector is available.
  Never fabricates data — every fact comes from a query result.
---

# External Attack-Path Agent (API-token edition)

Produce the **same** high-fidelity External Attack-Path report as the MCP edition, but
sourced through the Tenable Cloud Security **public GraphQL API** with a **Bearer API
token** — no MCP connector required. This edition is intended for headless / scheduled
(e.g. daily cron) use. **Never fabricate data — every value must come from a query
result.**

The detection contract, tiering, exclusions, and renderer are **identical** to the MCP
edition. Only the data-access mechanism differs (GraphQL instead of UDM MCP tools). Read
the MCP edition's `SKILL.md` for the full rationale behind each gate — this file focuses
on the API mechanics and the UDM→GraphQL field mapping.

## Prerequisites

- `bash`, `curl`, and `jq`.
- **Python 3.8+** (standard library only) for the bundled spec + renderer under
  `../../scripts/` (`attack_path_spec.py`, `render_report.py`).
- Environment variables:
  - `TENABLE_CS_API_URL` — GraphQL endpoint (commercial default
    `https://app.tenable.com/api/graph`; confirm your region/platform in the console).
  - `TENABLE_CS_API_TOKEN` — a Tenable Cloud Security API token, sent as a Bearer token.
- The caller `scripts/tcs_graphql.sh` reads a GraphQL query on stdin and POSTs it. Keep
  the token in the environment or a secrets manager — **never** commit it (the repo
  `.gitignore` blocks `*.env`, `*token*.json`, etc.).

## The detection contract (do not weaken)

`../../scripts/attack_path_spec.py` remains the single source of truth. Run
`python3 ../../scripts/attack_path_spec.py` first — it must print `ALL SELF-TESTS PASSED`.
A finding qualifies only if **all** of these hold, in order (identical to the MCP edition):

| # | Stage | Gate (plain English) | UDM attribute → map to GraphQL |
|---|-------|----------------------|--------------------------------|
| 1 | Workload | **Running** VM (a stopped VM is not a live path) | `VirtualMachineStatus ≠ Stopped` |
| 2 | Workload | Reachable **directly from the internet** | `EntityNetworkAccessType = ExternalDirect` |
| 3 | Workload | Open to a **wide range of IPs** | `EntityNetworkAccessScope ∈ {Wide, All}` |
| 4 | Exposure | A **live listening service observed** on an internet-facing port | network endpoint exists (host/port) |
| 5 | Vuln | The finding is **open** | `PackageVulnerabilityInstanceStatus = Open` |
| 6 | Vuln | **Exploitable over the network** | `VulnerabilityAttackVector = Network` |
| 7 | Vuln | **No unusual conditions** to exploit | `VulnerabilityAttackComplexity = Low` |
| 8 | Vuln | The vulnerable software **is the service on the exposed port** | component ↔ port (post-filter) |
| 9 | Evidence | **At least one** public threat signal | `VulnerabilityEpssScore ≥ 0.30` **OR** on CISA KEV |

**Deliberately NOT gates:** CVSS base/impact, VPR (proprietary), PoC availability. The one
KEV field used is the public CISA-KEV passthrough. Findings without a CVE identifier are
out of scope of the evidence gate by design (EPSS/KEV are CVE-keyed).

Gate 8 is applied by `attack_path_spec.post_filter()` inside the renderer — you do not
hand-implement it.

## Workflow

### 1. Verify the logic
Run `python3 ../../scripts/attack_path_spec.py`; confirm `ALL SELF-TESTS PASSED`.

### 2. Introspect the GraphQL schema (do NOT assume field names)
The GraphQL schema differs from UDM and evolves. **Introspect it, don't guess.** Run a
type-introspection query through the caller to discover the concrete query root, the
workload/finding types, and the field names that correspond to the UDM attributes in the
table above:

```bash
echo 'query { __schema { queryType { name } types { name kind } } }' \
  | ./scripts/tcs_graphql.sh | jq '.data.__schema.queryType, [.data.__schema.types[].name]'
```

Then introspect the specific types (e.g. the workloads/entities root and the
findings/vulnerabilities root) with `__type(name:"…"){ fields { name type { name kind
ofType { name } } } }` to locate the fields that carry: network access type & scope,
VM status, network endpoints (host/port/protocol), finding status, attack vector, attack
complexity, EPSS score, CISA-KEV flag, the workload identity, and the privilege/severe-
permission indicator. Record the mapping you find in `references/graphql-queries.md`
before pulling data — the file ships with a mapping **template and worked skeletons** to
fill in, not hard-coded field names, precisely because the schema is environment-specific.

### 3. Establish scope
Query the distinct accounts/tenants by provider and capture the report date. State scope
in the report header (accounts by provider; "running, internet-direct VMs only").

### 4. Pull the three datasets (paginate via cursors)
Using the mapped fields, pull the same three datasets the renderer expects. GraphQL
connections are cursor-paginated — loop on `pageInfo.hasNextPage` / `endCursor`, don't
stop at the first page:

- **Dataset A — Inventory:** one row per qualifying workload. Filter (or post-filter in
  `jq`) to running + ExternalDirect + Wide/All that also has a network endpoint AND a
  qualifying open vuln. Set `privileged = true` from the severe-permission indicator.
  Capture the identity string.
- **Dataset B — Endpoints:** the observed network endpoints (host, port, protocol) for
  those workloads. Dedupe to `[{instance_id, name, ports:[{port, protocol}]}]`; optionally
  build `endpoint_ips.json`. **Ports come only from observed endpoints — never a
  security-group rule.**
- **Dataset C — CVEs:** one row per qualifying (workload, CVE): open, AV:N, AC:Low, and
  (EPSS ≥ 0.30 OR CISA KEV). **Parse the package name and carry it as `component`** (from
  the finding's package/instance identifier) so the renderer's gate-8 post-filter works.

Because some gate arithmetic (the EPSS-OR-KEV evidence test, and the running/exposure
filters) may be easier to express client-side, it is acceptable to fetch the candidate
set and apply the numeric/boolean gates in `jq` — **as long as the resulting rows satisfy
the exact same contract** as the table above. Do not relax a threshold to compensate for
a schema limitation; if a signal genuinely isn't queryable, log that gap explicitly in
the report's verification notes rather than dropping the gate silently.

### 5. Assemble and render (shared renderer)
Write `assembled.json` as `{"A":[...],"B":[...],"C":[...]}` (and optionally
`endpoint_ips.json`) to a working data directory, then:

```bash
python3 ../../scripts/render_report.py --data ./data --date <YYYY-MM-DD> \
    --out ./output/attack-paths-report.html
```

The renderer applies gate 8 + the stopped-VM safety net, tiers by privilege, and writes
the HTML. It holds no thresholds — it defers to the spec.

### 6. Deliver
Present the report path and a 2–3 sentence summary (population, Tier 1 vs Tier 2 count,
KEV count, delta from prior run). Note PDF export via the browser print dialog. Flag
demo/test-looking environments.

## Tiering (ranking, not a gate)
- **Tier 1 — Privileged Attack Paths:** workload identity holds severe/administrative
  permissions. **Highest priority.**
- **Tier 2 — Additional Externally Exposed Workloads:** same exposed, exploitable service
  on a standard-privilege identity.

## Style
Concise and actionable. Quote all resource/identity/tenant IDs verbatim. Every number
must trace to a query result.

## Optional: run it daily (headless)
This edition is built for unattended runs. Offer to install a cron/launchd entry that
exports `TENABLE_CS_API_URL` / `TENABLE_CS_API_TOKEN` from a secrets store, invokes this
skill's steps, writes a dated report, and emails/uploads it. Example crontab (07:00 daily):

```
0 7 * * * cd /path/to/repo && TENABLE_CS_API_URL=... TENABLE_CS_API_TOKEN=... \
  bash plugins/ext-attack-path-agent-api/run_daily.sh >> /var/log/ext-attack-path.log 2>&1
```

Keep real assessment data and the token out of version control.
