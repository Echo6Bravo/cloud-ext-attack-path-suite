# Changelog

All notable changes are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-08-03

Initial public release — the Cloud External Attack-Path Suite.

### Added
- **Two-edition Claude Code plugin marketplace** sharing one self-testing detection spec and
  one renderer:
  - **MCP edition** (`ext-attack-path-agent`) — full detection contract via the `tcs`
    connector (Explore/UDM). Authoritative.
  - **API-token edition** (`ext-attack-path-agent-api`, reduced fidelity) — public GraphQL API
    with a Bearer token, headless; enforces the subset the API can express and states the gap.
- **Detection spec** (`attack_path_spec.py`) — gates declared once as data and every query
  generated from that declaration; three-way gate 8 (keep / **review** / drop) so an
  unmapped-but-exposed vulnerable service is surfaced, never silently dropped.
- **Renderer** (`render_report.py`) — two-tier HTML report; injection-safe (all environment
  data escaped); scale caps (`--max-cards`, `--max-cves-per-host`, `--max-rows`) with truthful
  truncation banners; print-to-PDF stylesheet.
- **Assembler** (`assemble.py`) — streams raw MCP pages into `assembled.json`; structure-aware
  instance-Id parsing across AWS/GCP/Azure shapes.
- **Scaling**: per-account/region chunking (`run_chunked.sh`) with a deterministic
  size-then-plan selector; headless cursor-paginated pull (`fetch_all.sh`) with 429/5xx
  retry+backoff.
- **Schema-drift canary** — validates required UDM/GraphQL fields against live metadata before
  pulling, and fails loud on a rename.
- **Layered remediation** — exact-CVE, per-service (~35 services), then a component/port-named
  generic fallback.
- **Testing/CI** — a 15-check suite plus GitHub Actions: Python 3.7–3.12 matrix, old-curl
  portability, gitleaks (full history), ruff + bandit + shellcheck + actionlint, and CodeQL.
  Version floors verified on real containers. CI actions are **pinned to commit SHAs** with
  **Dependabot** (github-actions, weekly) wired to keep them current.
- **Sample output** (`examples/`) — a rendered, self-contained HTML report plus screenshots,
  generated from the checked-in synthetic RFC 5737 fixture, so the report is viewable without
  a tenant. Linked from the top-level README.
- **Project docs** — `SECURITY.md` (threat model + coordinated disclosure), `CONTRIBUTING.md`
  (the merge bar), and this `CHANGELOG.md`.
