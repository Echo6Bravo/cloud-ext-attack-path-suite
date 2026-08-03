# Security Policy

## Reporting a vulnerability

Please report security issues privately:

- Open a **GitHub Security Advisory**
  ([Security → Advisories → Report a vulnerability](../../security/advisories/new)), or
- Open a regular issue **only if it is not sensitive**.

Include what the problem is, how to reproduce it, and the impact. Expect an initial response
within a few days; please don't disclose publicly until a fix is available.

## What this tool handles (threat model in brief)

This is a **read-only, standard-library Python** reporting tool for Tenable Cloud Security. It
pulls attack-path data and renders an HTML report. Security-relevant properties, all tested in
CI (`.github/workflows/ci.yml`) and the suite (`tests/run_tests.sh`):

- **No secrets in the repo.** `gitleaks` scans full history on every push; a `PreToolUse` hook
  blocks inline secrets in commands. The Tenable API token is supplied via environment variable
  only — never committed, never on a command line.
- **No real assessment data committed.** `.gitignore` blocks `data/`, `output/`, and secret
  file types; only synthetic RFC-5737 sample data is tracked.
- **Report is injection-safe.** Every environment-sourced value (VM names, identities, tenant
  IDs, components, CVE IDs) is HTML-escaped before entering the HTML/SVG report; verified by an
  adversarial DOM-level test.
- **TLS is verified** on all outbound API calls; no `--fail-with-body`/`-k`/`CERT_NONE`.
- **Defensive only.** It reads and reports; it does not exploit, move laterally, exfiltrate, or
  modify the environment.

## Handling the output responsibly

A generated report concentrates sensitive detail (internet-exposed hosts, exploitable CVEs,
identities, IP:ports) — an exploitation map. Treat rendered reports as confidential: store them
access-controlled, and do not commit them (they are gitignored by default).

## Out of scope

Vulnerabilities in the Tenable platform/APIs, or in third-party scanners this project's CI
uses, should be reported to their respective owners.
