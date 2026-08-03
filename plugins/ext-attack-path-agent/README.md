# External Attack-Path Agent — MCP edition

A Claude Code skill that produces a **high-fidelity External Attack-Path report** from
live Tenable Cloud Security data through the **`tcs` MCP connector** (Explore / UDM).

It reports only workloads that satisfy the full attack chain — *running → internet-direct
→ wide exposure → an observed listening service → the vulnerable component IS that service
→ remotely exploitable (AV:N, AC:Low) → public evidence (EPSS ≥ 0.30 OR CISA KEV)* — and
tiers them by the workload identity's cloud blast radius. It is deliberately conservative:
a reachable IP:port plus a high CVSS is **not** enough.

## What it does
1. Loads UDM syntax and verifies the bundled detection spec (`ALL SELF-TESTS PASSED`).
2. Pulls three datasets via `udm_execute_query` (inventory, validated endpoints,
   qualifying CVEs) — full pagination.
3. Assembles `assembled.json` and renders a self-contained two-tier HTML report.
4. Optionally runs daily and reports the delta.

## Use it
Invoke the **`ext-attack-path`** skill (e.g. "run the external attack-path sweep"). See
`skills/ext-attack-path/SKILL.md` for the full workflow and
`skills/ext-attack-path/references/udm-queries.md` for the four spec-generated queries.

## Detection contract & exclusions
The gate list, the deliberately-rejected signals (CVSS/VPR/PoC), and the tiering rationale
are documented in the skill and in the repo-root `README.md`. All logic lives in the
single self-testing source of truth `attack_path_spec.py` (bundled under `skills/.../
scripts/` by `build.sh`); the renderer holds no thresholds.

## Requirements
- Tenable Cloud Security `tcs` MCP connector.
- Python 3.7+ (standard library only; invoked as `python3`). Optional `run_attack_path.sh`
  orchestrator (turnkey large-tenant fan-out) needs bash 3.2+ and the `claude` CLI.

MIT licensed. Never commit real assessment data.
