---
name: enterprise-review
description: >-
  Adversarial pre-submission review gate for security-tooling / Tenable CyberAgents Exchange
  work. Systematically hunts the failure classes that hurt a customer — detection
  false-negatives, injection/XSS, messy-data robustness, scale limits, operational behavior,
  version portability, schema drift, and leaked secrets — and reports findings ranked by
  severity BEFORE any public/Exchange push. Use before shipping, submitting, or when the user
  asks "is this enterprise-ready / did we miss anything?".
---

# Enterprise readiness review

A repeatable adversarial pass. The goal is to find, up front, the issues that would otherwise
surface after "done" — the pattern where each question uncovers a bug. Run every dimension,
report findings ranked most-severe first, each with a concrete repro and fix. Do NOT rubber-
stamp: if a dimension is genuinely N/A for the artifact, say why.

For each dimension, actually TEST it (write a probe, feed adversarial input, run a container)
rather than reasoning about it. Prefer proof over assertion.

## Dimensions (in priority order — customer-impact first)

1. **Detection correctness — false NEGATIVES (highest priority for a security tool).**
   Does any real, in-scope finding get silently dropped? Check allow-lists/keep-lists for
   coverage gaps; confirm the tool SURFACES unknowns for review rather than discarding them.
   Probe with inputs the maps don't explicitly know about.

2. **Input safety — injection/XSS.** Every value sourced from the scanned environment (names,
   IDs, components, free text) that reaches HTML/SVG/CSV/shell/SQL must be escaped/parameterized
   for its sink. Prove it: inject `<script>`, attribute-breakout, and formula-injection
   payloads into every field and verify (DOM-level / parser-level) that nothing executes.

3. **Robustness on messy data.** Null/missing fields, wrong types, duplicates, empty result
   sets, truncated/interrupted inputs, malformed pages. Each must fail cleanly with an
   actionable message (never a raw stack trace) or degrade gracefully. Verify the exit-code
   contract.

4. **Scale.** Estimate volume at 10–50x the test environment (pull size, memory, output size,
   algorithmic complexity). Confirm caps/streaming/chunking exist and that nothing is silently
   truncated. Extrapolate output size; open the result.

5. **Operational.** Exit codes a scheduler can branch on; partial-failure tolerance (one unit
   fails → flag the gap, don't lose everything); API retry/backoff on 429/5xx; determinism/
   reproducibility for audit.

6. **Version portability.** Language/runtime floor (test on the real minimum, e.g. a
   container); avoid tool flags newer than the documented floor (e.g. `curl --fail-with-body`
   needs 7.76+). No unpinned/absent third-party deps assumed present.

7. **Schema/contract drift.** If the tool depends on an external schema (UDM/GraphQL/API), is
   there a canary that fails loud when a depended-on field is renamed/removed, rather than
   returning empty?

8. **Secrets & data hygiene.** No token/credential/real-assessment-data in tracked files, in
   command lines, or in the transcript. `.gitignore` blocks secrets + real data; only synthetic
   samples are committed. Rotate anything that leaked.

9. **Tests & CI.** Is each of the above locked in by an automated test so it can't regress? A
   finding fixed without a regression test is only half-fixed.

10. **Docs.** README/SKILL state what it does, prerequisites, how to run, outputs, limits, and
    any fidelity/coverage caveats — accurately (no overclaiming; e.g. "reduced fidelity" stays
    labeled as such).

## Output

Report as: dimension → findings (most severe first) with `file:line`, a concrete failure
scenario, and the specific fix. End with an explicit **verdict**: ready to submit, or the
blocking items. If findings are fixed in the same pass, re-run the relevant probe to confirm,
and add/point to the regression test.

## For Tenable CyberAgents Exchange submissions specifically
Also confirm the listing passes the live `validator.py` + contributing checklist, the repo is
public + on a personal (non-EMU) account, and the LICENSE copyright is correct
(see the exchange submission reference). Never rubber-stamp a red CI.
