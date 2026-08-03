---
description: Verify-then-commit gate — run spec self-tests, the full test suite, and build before committing. Blocks on any failure.
---

Run the project's full verification gate and only commit if everything passes. This is the
standard pre-commit ritual for this repo (spec self-tests → test suite → build → commit → push).

Do this in order and STOP at the first failure, reporting exactly what failed:

1. **Spec self-tests** — `python3 attack_path_spec.py` must print `ALL SELF-TESTS PASSED`.
2. **Full test suite** — `bash tests/run_tests.sh` must end with `ALL TESTS PASSED` (covers
   gate-8 taxonomy, injection safety, messy-data handling, remediation layers, schema-drift
   canary, the GraphQL caller's retry/HTTP handling, and the plan CLI).
3. **Build** — `./build.sh` must succeed (verifies + syncs the shared lib into both plugins
   and packages them).
4. **Secret/data scan** — confirm no token or real assessment data is staged:
   `git ls-files | xargs grep -lI "TENABLE_CS_API_TOKEN=[A-Za-z0-9]" 2>/dev/null` must be empty,
   and no real tenant IDs/hostnames in tracked non-sample files.

If ALL pass: show `git status --short`, then commit with a clear message (no AI-attribution
trailer) and push to the `personal` remote (`Echo6Bravo`, per the user's account rules).
If ANY step fails: do NOT commit; report the failing step and its output, and offer to fix.

If the user passed a message after `/ship`, use it as the commit message; otherwise draft one
from the staged diff and confirm before committing.
