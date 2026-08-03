# Sample output

A rendered example of what the suite produces, so you can see the report before
running anything against your own tenant.

![Sample attack-path report — header, scope, and summary tiles](sample-report-hero.png)

## Files

| File | What it is |
|------|------------|
| [`sample-report.html`](sample-report.html) | The **actual rendered report** — self-contained (no external assets), open it in any browser. |
| [`sample-report.png`](sample-report.png) | Full-page screenshot of that report. |
| `sample-report-hero.png` | The header crop shown above (used in the top-level README). |

## How it was generated

Everything here is built from the checked-in **synthetic** fixture at
[`../data/sample/`](../data/sample) — no real assessment data. All IPs are from the
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) documentation ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and all account IDs, roles,
and hostnames are fabricated.

```bash
# regenerate the HTML from the synthetic fixture
python3 render_report.py --data ./data/sample --date 2026-08-03 \
  --out examples/sample-report.html
```

## What the report demonstrates

- **The gate chain, stated in plain English** — a workload appears only if every
  gate holds (running VM → internet-direct → wide exposure → observed listening
  endpoint → open finding → network-exploitable → low complexity → the vulnerable
  software *is* the exposed service → public threat signal). The report prints the
  full ladder and names the signals it deliberately does **not** gate on (CVSS, VPR,
  PoC availability).
- **Privilege tiering** — Tier 1 (privileged identity, escalates to broad cloud
  control) is separated from Tier 2 (standard identity, contained blast radius);
  privilege is shown and tiered, never used to hide a finding.
- **Per-host attack-path cards** — the exposed service → exploitable vuln → cloud
  identity → highest-risk action flow, with the validated open ports, the observed
  `IP:port` endpoint, EPSS/CVSS/CISA-KEV evidence, and layered remediation.
