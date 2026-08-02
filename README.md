# Cloud External Attack-Path Report

A repeatable **Tenable Cloud Security** report generator that surfaces *genuine externally
exposed attack paths* in a cloud environment using Tenable Cloud Security (UDM /
Explore). It finds running, internet-facing virtual machines whose **observed listening
service** carries a **remotely exploitable** vulnerability backed by **independent public
evidence of real-world risk**, and tiers them by the privilege of the workload's cloud
identity — so the output is a short, high-fidelity list of paths worth acting on, not a
raw vulnerability dump.

> **Why this exists.** A reachable IP:port and a scary CVSS score are not, by themselves,
> an attack path. This tool enforces the full chain — *exposed → a service is really
> listening → the vulnerable component is that service → it is remotely exploitable →
> there is public evidence it matters → the host identity has blast radius* — and is
> deliberately conservative about what counts, so findings are defensible to an owner.

---

## Table of contents
- [Highlights](#highlights)
- [How a finding qualifies](#how-a-finding-qualifies)
- [What is deliberately excluded](#what-is-deliberately-excluded)
- [Tiering](#tiering)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Quick start (synthetic sample)](#quick-start-synthetic-sample)
- [Running a real assessment](#running-a-real-assessment)
- [Extending & maintaining](#extending--maintaining)
- [Security & data handling](#security--data-handling)
- [License](#license)

---

## Highlights

- **Single source of truth.** All detection logic lives in `attack_path_spec.py`, which
  declares the gates as ordered data *and generates every UDM query from that
  declaration* — so the documented logic and the executed query can never drift.
- **Self-testing.** Running the spec fails loudly if a gate is missing or reordered, if a
  deliberately-rejected signal leaks into a filter, if the "not stopped" gate is dropped,
  or if a query GUID is malformed.
- **High-fidelity, not high-volume.** A validated-endpoint requirement plus a
  component-to-port correlation removes local-privilege-escalation and client-side CVEs
  that can't actually be reached over the exposed port.
- **Standards-based thresholds.** Qualification uses public/standard signals (CVSS
  vector attributes, EPSS, CISA KEV) rather than proprietary blended scores.
- **Two-tier output** by identity blast radius, rendered as a self-contained HTML report
  with per-finding attack-path diagrams, evidence, exposed IP:port, and remediation.

---

## How a finding qualifies

A workload is reported only if **all** of the following hold, applied in this order. The
authoritative, self-tested definition is the `GATES` list in `attack_path_spec.py`; the
plain-English description and the underlying attribute are shown together.

| # | Stage | Gate (plain English) | Attribute |
|---|-------|----------------------|-----------|
| 1 | Workload | It is a **running** virtual machine (a stopped VM is not a live path) | `VirtualMachineStatus ≠ Stopped` |
| 2 | Workload | Reachable **directly from the internet** | `EntityNetworkAccessType = ExternalDirect` |
| 3 | Workload | Open to a **wide range of IPs** / the whole internet | `EntityNetworkAccessScope ∈ {Wide, All}` |
| 4 | Exposure | A **live listening service was actually observed** on an internet-facing port (ports come from the validated endpoint, **never** the firewall/security-group rule) | `NetworkEndpoint` exists |
| 5 | Vuln | The finding is **open** (not remediated) | `PackageVulnerabilityInstanceStatus = Open` |
| 6 | Vuln | **Exploitable over the network** | `VulnerabilityAttackVector = Network` |
| 7 | Vuln | **No unusual conditions** required to exploit | `VulnerabilityAttackComplexity = Low` |
| 8 | Vuln | The vulnerable software **is the service on the exposed port** (not a local tool or client program) | component ↔ exposed-port correlation (post-filter) |
| 9 | Evidence | **At least one** public threat signal | `VulnerabilityEpssScore ≥ 0.30` **OR** on CISA KEV |

Gate 8 is the anti-false-positive core: it uses a curated package → service → port map
(`SERVICE_PORTS` in the spec) so, for example, an SSH-only host is a path only if it has a
remote+PoC vulnerability *in the SSH server itself* — not in an installed-but-unexposed
library.

## What is deliberately excluded

These signals were evaluated and **intentionally not used as qualifying gates**:

- **CVSS base / impact score** — frequently overweighted relative to real-world
  exploitability; as a threshold it admits more noise than signal.
- **VPR score** — this methodology targets the underlying exploitability signals
  (reachability, low attack complexity, exploitation likelihood, confirmed in-the-wild
  use) directly, rather than a single blended score.
- **Proof-of-concept availability** — as a gate it admits lower-impact and older findings
  that do not represent current, high-value exposure. (It is displayed for context, not
  used to qualify.)

**Coverage notes.** The threat-evidence gate relies on **CVE-keyed public sources**
(EPSS, CISA KEV), so findings without a CVE identifier (e.g. distribution advisories such
as `DLA-`/`USN-`) are out of scope by design. The CVE published year shown per finding is
informational only and **never** affects inclusion; non-CVE identifiers display "—".

## Tiering

Privilege is **not** a qualifying gate — it ranks findings so nothing real is hidden:

- **Tier 1 — Privileged Attack Paths:** the workload's identity holds
  severe/administrative permissions (`SeverePermissionActionPrincipalAttribute`). A
  service compromise here can escalate to broad cloud control. **Highest priority.**
- **Tier 2 — Additional Externally Exposed Workloads:** the same class of exposed,
  exploitable service on a standard-privilege identity. A real foothold, contained blast
  radius.

---

## Architecture

```
attack_path_spec.py   Single source of truth.
                      • GATES: the ordered gate list (the spec).
                      • build_population_query / build_inventory_query /
                        build_endpoints_query / build_cve_query: every UDM query is
                        generated from GATES, so query ≡ documented logic.
                      • post_filter(): gate 8 (component↔port) + a stopped-VM safety net.
                      • age_label(): CVE-year proxy (fail-open; never filters).
                      • _selftests(): invariants; run `python3 attack_path_spec.py`.
render_report.py      Parameterized renderer (--data, --out, --date). Reads the three
                      datasets, applies post_filter, tiers, and writes the HTML report.
                      Contains no detection thresholds — it defers to the spec.
queries/              The four spec-generated UDM queries, saved as reference:
                        01_population.json  validate/count the population
                        02_inventory.json   Dataset A — hosts + tier + identity
                        03_endpoints.json   Dataset B — validated IP:port endpoints
                        04_cve.json         Dataset C — per-host qualifying CVEs
data/                 Per-assessment inputs (gitignored except data/sample/).
data/sample/          Fully synthetic demo dataset (safe to commit).
output/               Generated HTML reports (gitignored).
LICENSE               MIT.
```

**Data flow:** `queries/*` are executed against your tenant → raw results assembled into
`data/assembled.json` (`{"A":…,"B":…,"C":…}`) → `render_report.py` applies the spec's
post-filter and renders `output/…html`.

## Requirements

- **Python 3.8+** (standard library only — no third-party packages).
- Access to a **Tenable Cloud Security** tenant and the **UDM / Explore query API**
  (e.g. via the Tenable MCP `udm_execute_query` tool) to pull the three datasets.

## Quick start (synthetic sample)

No real data or tenant access needed — a fabricated dataset ships under `data/sample/`
(documentation IP ranges per RFC 5737):

```bash
# 1) verify the detection logic (must print: ALL SELF-TESTS PASSED)
python3 attack_path_spec.py

# 2) render the sample report
python3 render_report.py --data ./data/sample --out ./output/sample-report.html
open ./output/sample-report.html      # macOS (use xdg-open on Linux)
```

The sample intentionally includes one non-listening library CVE (`libgnutls30`) to
demonstrate the component-to-port exclusion removing it.

## Running a real assessment

1. **Validate the logic:**
   ```bash
   python3 attack_path_spec.py
   ```
   Confirm it prints `ALL SELF-TESTS PASSED`; it also prints the gate order and the
   generated queries.

2. **Pull the data** for your tenant by executing the queries in `queries/` (or
   regenerating them with the spec's `build_*` functions) via the UDM API, paginating
   fully. Assemble the raw match arrays into `data/assembled.json`:
   - **A** — `build_inventory_query()`: one row per host. Set `privileged` from whether
     `EntityAttributes` contains `SeverePermissionActionPrincipalAttribute`; capture
     `OriginatorEntityServiceIdentities` for the identity.
   - **B** — `build_endpoints_query()`: dedupe to
     `[{instance_id, name, ports:[{port, protocol}]}]`. Optionally also write
     `data/endpoint_ips.json` (`{"endpoints":[{name, ip, port, protocol}]}`) to show the
     exact IP:port in each finding.
   - **C** — `build_cve_query()`: **parse the package from the 2nd path segment of the
     instance Id** and carry it as `component`. The renderer applies gate 8 to these rows
     via `attack_path_spec.post_filter()`.

3. **Render:**
   ```bash
   python3 render_report.py --data ./data --date $(date +%F) \
       --out ./output/attack-paths-report.html
   ```

> A future enhancement could automate step 2 with a small fetch script that calls the API
> and writes `assembled.json` directly.

### Printing to PDF

The report ships with a print stylesheet, so no extra tooling is needed. Open the HTML in
a browser and choose **File → Print → Save as PDF**:

- Paper **Letter or A4**, default margins.
- Enable **"Background graphics"** so severity colors render.

On print, the on-screen dark theme automatically switches to a **high-contrast,
ink-friendly light palette**, each tier starts on a fresh page, and findings (cards,
diagrams, table rows) are kept from splitting across page breaks — so it reads like a
professional printed report. Generating a separate PDF file per run is intentionally
*not* built in: it would require a heavyweight headless-browser/PDF dependency, whereas
the print stylesheet keeps the tool dependency-free and always in sync with the HTML.

## Extending & maintaining

- **Change a threshold or add a gate:** edit the `GATES` list (and, if needed,
  `SERVICE_PORTS`) in `attack_path_spec.py`. The self-tests enforce gate ordering, the
  no-rejected-signal rule, valid hex GUIDs, and that the stopped-VM exclusion stays gate
  #1. If you weaken an invariant, `python3 attack_path_spec.py` fails loudly.
- **Add a listening service** (e.g. a new web/app server): add it to `SERVICE_PORTS` and
  the keep-list in `component_is_listening()` / `service_key()`, and add a unit assertion.
- Because every query is generated from the same gate declaration, the query and the
  documented logic **cannot** diverge.

## Security & data handling

- **Never commit real assessment data.** `data/` and `output/` are gitignored (only
  `data/sample/` is tracked), and `.gitignore` additionally blocks common secret/key
  file types and ad-hoc pull artifacts. Real cloud account IDs, hostnames, public IPs,
  service-account identifiers, and findings must stay out of version control.
- Diagrams depict a *plausible* exploitation chain, not confirmed compromise.
- Validate the environment's classification (prod vs. lab) before acting on findings or
  filing remediation tickets.

## License

[MIT](./LICENSE) © 2026 Tenable, Inc.
