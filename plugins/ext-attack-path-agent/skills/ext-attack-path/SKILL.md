---
name: ext-attack-path
description: >-
  Autonomously produce a high-fidelity External Attack-Path report from live Tenable
  Cloud Security data (the tcs MCP / Explore UDM data model). Reports ONLY running,
  internet-direct virtual machines whose observed listening service carries a remotely
  exploitable (AV:N, AC:Low) vulnerability backed by public evidence (EPSS >= 0.30 OR
  CISA KEV), where the vulnerable component is confirmed to be the service on the exposed
  port, tiered by cloud-identity blast radius. Use for external attack-path triage,
  internet-exposed-workload risk, or "what can actually be reached and exploited from the
  internet" questions. Never fabricates data — every fact comes from a query result.
---

# External Attack-Path Agent (MCP edition)

Produce a short, high-fidelity list of **genuine externally exposed attack paths** and
render them as a self-contained two-tier HTML report, sourced entirely from live Tenable
Cloud Security data via the `tcs` MCP connector. **Never fabricate data — every value
must come from a query result.**

> **What makes a finding.** A reachable IP:port and a scary CVSS score are not, by
> themselves, an attack path. This agent enforces the full chain — *running →
> internet-direct → wide exposure → a service is really listening → the vulnerable
> component IS that service → remotely exploitable → public evidence it matters* — then
> tiers by the workload identity's blast radius. It is deliberately conservative, so every
> finding is defensible to an owner.

## Prerequisites

- The **Tenable Cloud Security (`tcs`) MCP connector**. Tools:
  `mcp__tcs__udm_get_instructions`, `mcp__tcs__udm_get_object_type_metadata`,
  `mcp__tcs__udm_get_property_values`, `mcp__tcs__udm_execute_query`,
  `mcp__tcs__udm_get_query_results_count`.
  (In some environments the connector is namespaced differently, e.g.
  `mcp__tenablecs-<org>__udm_execute_query`. Use whichever `*_udm_*` tools are present.)
- **Python 3.8+** (standard library only) to run the bundled spec and renderer.
- The detection logic and renderer are bundled under `scripts/` in this skill:
  `attack_path_spec.py` (the single source of truth) and `render_report.py`.

## The detection contract (do not weaken)

`attack_path_spec.py` is the **single source of truth**. It declares the gates in order
and *generates every UDM query from that declaration*, so the documented logic and the
executed query cannot drift. Run `python3 scripts/attack_path_spec.py` first — it must
print `ALL SELF-TESTS PASSED`. A finding qualifies only if **all** of these hold, in order:

| # | Stage | Gate (plain English) | Attribute |
|---|-------|----------------------|-----------|
| 1 | Workload | **Running** virtual machine (a stopped VM is not a live path) | `VirtualMachineStatus ≠ Stopped` |
| 2 | Workload | Reachable **directly from the internet** | `EntityNetworkAccessType = ExternalDirect` |
| 3 | Workload | Open to a **wide range of IPs** / the whole internet | `EntityNetworkAccessScope ∈ {Wide, All}` |
| 4 | Exposure | A **live listening service was actually observed** on an internet-facing port (ports come from the validated endpoint, **never** the firewall/security-group rule) | `NetworkEndpoint` exists |
| 5 | Vuln | The finding is **open** (not remediated) | `PackageVulnerabilityInstanceStatus = Open` |
| 6 | Vuln | **Exploitable over the network** | `VulnerabilityAttackVector = Network` |
| 7 | Vuln | **No unusual conditions** to exploit | `VulnerabilityAttackComplexity = Low` |
| 8 | Vuln | The vulnerable software **is the service on the exposed port** (not a local tool or client) | component ↔ exposed-port correlation (post-filter) |
| 9 | Evidence | **At least one** public threat signal | `VulnerabilityEpssScore ≥ 0.30` **OR** on CISA KEV |

Gate 8 is the anti-false-positive core: a curated package → service → port map means an
SSH-only host is a path only if it has a remote vulnerability *in the SSH server itself*,
not in an installed-but-unexposed library. Gate 8 is applied by
`attack_path_spec.post_filter()` — you do not hand-implement it; the renderer calls it.

**Deliberately NOT gates** (evaluated and rejected — see `README.md` and the `GATES` /
`REJECTED_SIGNALS` declarations in the spec): CVSS base/impact score, VPR (proprietary),
and proof-of-concept availability. The one VPR-v2 field used is
`VulnerabilityVprV2MetricsOnCisaKev`, because it is a passthrough of the public CISA KEV
catalog. Findings without a CVE identifier (e.g. `DLA-`/`USN-` advisories) are out of
scope of the evidence gate by design, since EPSS/KEV are CVE-keyed.

## Quirks to remember (these will error otherwise)

- `udm_execute_query` **requires** both `skip` and `take` parameters. Paginate fully.
- `udm_get_object_type_metadata` uses the parameter name `objectTypeName`.
- Every query needs a unique hex GUID `id`; each property's `queryId` must match its
  parent query/join `id`. The spec-generated queries already satisfy this.
- The `NetworkDynamicAnalysisResourceNetworkEndpoints` relation returns null if selected
  as a plain property — it is used here via a **relation rule** (population/inventory) and
  a dedicated endpoints query rooted on `NetworkEndpoint`.
- Root the population/inventory query on **`IVirtualMachine`** so `VirtualMachineStatus`
  is in scope — gate 1 silently vanishes if you root on NetworkEndpoint/Vulnerability.

## Workflow

### 1. Refresh syntax and verify the logic
Call `mcp__tcs__udm_get_instructions` to load the current UDM schema. Then run
`python3 scripts/attack_path_spec.py` and confirm `ALL SELF-TESTS PASSED`. The four
canonical queries are in `references/udm-queries.md` (and regenerable via the spec's
`build_*` functions).

### 2. Establish scope
Query the distinct accounts/tenants in scope by provider (from `EntityTenant` /
`EntityTypeName` on the population). Capture the report date. State the scope plainly in
the report header (accounts by cloud provider; "running, internet-direct VMs only").

### 3. Pull the three datasets
**First, size the pull with `udm_get_query_results_count` on all three queries** (not just
the population). This determines feasibility — see "Scaling" below. Then run each query in
`references/udm-queries.md` via `udm_execute_query`, paginating fully (`skip`/`take`).

> **⚠️ Scaling — read before pulling.** `udm_execute_query` returns a fixed page size and
> MCP tool calls execute **only inside the model's context** (they can't be scripted or run
> headless). Dataset C (CVE rows) dominates: even a ~100-VM lab returns ~1,800 C rows
> (~90 pages). A large customer (10k–50k+ VMs) can produce hundreds of thousands of C rows
> = thousands of pages, which will exhaust context / time out. **The count query tells you
> which regime you're in:**
> - **Small (C ≲ ~1,000 rows / ≲ ~50 pages):** paginate inline here in the MCP session.
> - **Large:** do **not** paginate C inline. Either (a) **narrow scope** — run per-account
>   or per-region by adding an `EntityTenant`/`EntityRegion` rule so each pull is small, and
>   merge the resulting reports; or (b) use the **API-token edition's headless
>   `fetch_all.sh`** (cursor-paginated, streams pages to disk with no model context) for the
>   data pull, then assemble/render with the same shared code. Never silently truncate C —
>   if you cap it, say so in the report.

Use `udm_get_query_results_count` for the population total first.

- **Population (query 01)** — count/validate the candidate VM population (gates 1–9 as a
  relation-filtered existence check). Sanity-check the count before pulling rows.
- **Dataset A — Inventory (query 02)**, rooted on `IVirtualMachine`: one row per host.
  Set `privileged = true` when `EntityAttributes` contains
  `SeverePermissionActionPrincipalAttribute`. Capture `OriginatorEntityServiceIdentities`
  for the identity string.
- **Dataset B — Endpoints (query 03)**, rooted on `NetworkEndpoint`: dedupe to
  `[{instance_id, name, ports:[{port, protocol}]}]`. Optionally also assemble
  `endpoint_ips.json` (`{"endpoints":[{name, ip, port, protocol}]}`) from
  `NetworkEndpointHost`/`NetworkEndpointPort`/`NetworkEndpointProtocolType` to show the
  exact IP:port per finding.
- **Dataset C — CVEs (query 04)**, rooted on `PackageVulnerabilityInstanceModel`: one row
  per qualifying (host, CVE). **Parse the package from the 2nd path segment of the
  instance Id** and carry it as `component` — the renderer's gate-8 post-filter needs it.

### 4. Assemble and render
Save each raw `udm_execute_query` response page as a file under a `raw/` directory
(`raw_A_*.json`, `raw_B_*.json`, `raw_C_*.json`), then let the bundled assembler build
`assembled.json` — it parses the raw MCP envelope, sets `privileged` from
`EntityAttributes`, and parses `component` from the instance Id's 2nd path segment (so you
don't hand-build the JSON):

```bash
python3 scripts/assemble.py --raw ./data/raw --out ./data/assembled.json \
    --endpoint-ips ./data/endpoint_ips.json
python3 scripts/render_report.py --data ./data --date <YYYY-MM-DD> \
    --out ./output/attack-paths-report.html
```

The renderer applies `attack_path_spec.post_filter()` (gate 8 + a stopped-VM safety net),
tiers by privilege, and writes the HTML. It contains **no** detection thresholds — it
defers entirely to the spec.

> **Scaling the output.** The renderer caps full per-host cards at `--max-cards` (default
> 150) and CVE rows per host at `--max-cves-per-host` (default 25); hosts beyond the cap
> roll into a compact, risk-ranked overflow table and the KPI/summary counts still reflect
> the **true** totals. This keeps the HTML openable (~a few MB) even in a 50k-VM
> environment — an uncapped render there would exceed 1 GB. `assemble.py --max-hosts N` can
> additionally bound the host set before rendering. Raise/remove caps with `--max-cards 0`
> for small environments where you want a full card per host.

### 5. Deliver
Present the HTML report path and give a 2–3 sentence chat summary: the population size,
how many Tier 1 (privileged) vs Tier 2 paths, how many are on CISA KEV, and whether the
counts changed from a prior run. Note the report prints to PDF via the browser
(File → Print → Save as PDF, Background graphics on). Flag any demo/test-looking
environment (names containing `demo`/`test`).

## Tiering (ranking, not a gate)

Privilege never hides a real path — it ranks:
- **Tier 1 — Privileged Attack Paths:** the workload identity holds severe/administrative
  permissions (`SeverePermissionActionPrincipalAttribute`). Compromise can escalate to
  broad cloud control. **Highest priority.**
- **Tier 2 — Additional Externally Exposed Workloads:** same class of exposed, exploitable
  service on a standard-privilege identity. A real foothold, contained blast radius.

## Style
Concise and actionable. Quote all resource IDs, identity IDs, and tenant IDs verbatim.
Every reported number must trace to a query result — never estimate.

## Optional: run it daily
If the user wants continuous monitoring, offer to create a scheduled task (e.g. a
`cron`/launchd entry, or the Claude Code scheduler) that runs this skill each morning,
writes a dated report to `./output/attack-paths-report-<YYYY-MM-DD>.html`, and summarizes
the delta from the prior day. Keep real assessment data out of version control (see the
repo `.gitignore`).

> **⚠️ Scheduling does NOT lift the pull limit — pick the deployment by environment size.**
> A scheduled MCP run has the **same** constraint as an interactive one: every
> `udm_execute_query` page returns through the model's context (the model drives the
> `skip`/`hasMore` loop), so a large tenant's thousands of CVE pages will overflow context
> / time out no matter who launches it. Cron changes *when* it runs, not *how the data
> flows*. Context compaction won't save it either — it would summarize away the raw rows
> needed to assemble the report. Route by the **count** queries (step 3):
> - **Small tenant** (C ≲ ~1,000 rows): schedule this MCP skill directly.
> - **Large tenant**: **chunk by cloud account** to keep full MCP fidelity (preferred), or
>   fall back to the reduced-fidelity API edition. See "Chunked pull" below.

### Chunked pull — measured, not guessed (large tenants, full fidelity)
The MCP limit is on volume pulled through the model **per run/context** — not on total work.
The strategy is chosen **deterministically from measured CVE-row counts** (the quantity that
actually drives context cost — a low-host account can still have thousands of CVE rows), so a
tenant that fits does **one** cheap run and only larger ones chunk:

1. **Size it (CVE rows, not hosts).** Run `attack_path_spec.build_account_sizing_query()`
   once — a cheap grouped `ValueCount` of **qualifying CVE rows** per account (and per region
   with `by="region"`); validated live. Tally the results into
   `sizes.json = {"accounts":{"<id>":<count>,…}, "regions":{"<id>|<region>":<count>,…}}`.
2. **Plan deterministically.** `python3 scripts/attack_path_spec.py plan sizes.json <budget>`
   (budget = max CVE rows per run, default `ROWS_PER_RUN=4000`) returns the mode:
   - `total ≤ budget` → **one tenant run** (cheapest — avoids N× per-run overhead);
   - every account `≤ budget` → **one run per account**;
   - an account `> budget` → that account **split by region**;
   - a region still `> budget` → reported in `oversized` (narrow further or accept — **never
     silently truncated**).
3. **Pull per chunk, scoped.** `build_*` functions take `account=`/`region=` and inject
   `EntityTenant`/`EntityRegion` rules. Save each raw page to a shared `data/raw/` with a
   scope-tagged name (`raw_A_<tag>_p<N>.json`).
4. **Merge + render once.** `assemble.py` globs all `raw_*` pages and dedupes by
   `instance_id` → one merged report (proven end-to-end).

`scripts/run_chunked.sh --sizes sizes.json [--budget N]` automates steps 2–4 (plan → one
fresh headless `claude -p` per chunk → merge). **Scope note:** this scales to the size of the
**largest single chunk** (one region of one account) that must still fit one context — "much
more scalable, not unbounded." For truly unbounded headless scale, the API edition's shell
pull is the only option (reduced fidelity).
