# Contributing

Contributions welcome. This project holds a high bar (it's a security tool), enforced by CI —
a PR is expected to keep every gate green.

## Before opening a PR

Run the local gate (or `/ship` if you use the bundled command):

```bash
python3 attack_path_spec.py     # must print ALL SELF-TESTS PASSED
bash tests/run_tests.sh         # must print ALL TESTS PASSED (15 checks)
./build.sh                      # verifies the spec, syncs the shared lib into both plugins, packages
ruff check . && bandit -r . --skip B101 --exclude ./tests,./dist,./plugins
```

Also: `shellcheck -S warning` any changed `*.sh`, and `actionlint` any changed workflow.

## Ground rules

- **Detection logic lives once**, in `attack_path_spec.py` (the `GATES` declaration). Every
  query is generated from it; don't hand-write divergent query JSON. The plugin copies under
  `plugins/*/skills/*/scripts/` are **synced by `build.sh`** — edit the root files, not the
  copies.
- **Never weaken a gate silently.** Self-tests enforce gate ordering, the rejected-signal rule,
  and the stopped-VM gate; if you change detection, update the tests and say why in the PR.
- **No secrets, no real data.** `gitleaks` scans full history in CI; only synthetic RFC-5737
  sample data is committed. The API token is env-var only.
- **Add a regression test** for any bug you fix (dimension 11 of the review bar) and keep the
  README/CHANGELOG in sync. Don't overclaim (e.g. "reduced fidelity" stays labeled).
- **CI must be green** — including CodeQL. Don't merge a red pipeline.

## Versioning

[SemVer](https://semver.org/) + [Keep a Changelog](https://keepachangelog.com/). Note
user-facing changes under an "Unreleased" heading in your PR.
