#!/usr/bin/env bash
# test_orchestrator.sh -- end-to-end test of run_attack_path.sh with a MOCKED claude CLI.
#
# The real `claude -p` + live MCP path CANNOT be verified without a tenant, so we mock the CLI
# (tests/fixtures/mock_claude.sh): it answers `mcp list`, writes a sizes.json for the sizing
# prompt, and writes fixture raw pages for each pull prompt. This verifies the orchestration
# itself -- connector detection, auto-size, plan, fan-out loop, merge, render, exit codes --
# deterministically, without a live tenant.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOCK_SRC="$ROOT/tests/fixtures/mock_claude.sh"
pass=0; fail=0
ok(){ echo "  [PASS] $1"; pass=$((pass+1)); }
bad(){ echo "  [FAIL] $1"; fail=$((fail+1)); }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/orch.XXXXXX")"
BIN="$WORK/bin"; mkdir -p "$BIN"
trap 'rm -rf "$WORK"' EXIT
cp "$MOCK_SRC" "$BIN/claude"; chmod +x "$BIN/claude"

DATA="$WORK/data"
export MOCK_RAW_DIR="$DATA/raw" MOCK_SIZES="$DATA/sizes.json"
mkdir -p "$MOCK_RAW_DIR"
REPORT="$ROOT/output/attack-paths-report-2026-08-03.html"

check_merged_report(){ # $1 = label
  local html; html="$(cat "$REPORT")"
  echo "$html" | grep -q "111111111111" && ok "$1: AWS account in merged report" || bad "$1: AWS account missing"
  echo "$html" | grep -q "8be0927e" && ok "$1: Azure account merged (cross-provider)" || bad "$1: Azure account missing"
  echo "$html" | grep -q "203.0.113.10:3389" && ok "$1: AWS exposed endpoint rendered" || bad "$1: AWS endpoint missing"
}

echo "== A) tenant mode (budget fits whole tenant -> 1 session, both accounts) =="
rm -f "$REPORT"; rm -rf "$DATA/raw"; mkdir -p "$DATA/raw"
OUT="$( CLAUDE_BIN="$BIN/claude" PATH="$BIN:$PATH" \
        bash "$ROOT/run_attack_path.sh" --budget 4000 --data "$DATA" --date 2026-08-03 --yes 2>&1 )"; rc=$?
echo "$OUT" | sed 's/^/    /'
[ "$rc" -eq 0 ] && ok "tenant: exit 0" || bad "tenant: exit $rc (want 0)"
echo "$OUT" | grep -q "auto-detected UDM connector: tenablecs-org1" && ok "tenant: auto-detected connector" || bad "tenant: connector not detected"
echo "$OUT" | grep -Eq "mode=tenant .*chunks=1" && ok "tenant: single-session plan" || bad "tenant: expected mode=tenant chunks=1"
[ -f "$REPORT" ] && ok "tenant: report rendered" || bad "tenant: no report"
[ -f "$REPORT" ] && check_merged_report "tenant"

echo "== B) per-account fan-out (tiny budget -> one session PER account) =="
rm -f "$REPORT"; rm -rf "$DATA/raw"; mkdir -p "$DATA/raw"
OUT="$( CLAUDE_BIN="$BIN/claude" PATH="$BIN:$PATH" \
        bash "$ROOT/run_attack_path.sh" --budget 45 --data "$DATA" --date 2026-08-03 --yes 2>&1 )"; rc=$?
echo "$OUT" | sed 's/^/    /'
[ "$rc" -eq 0 ] && ok "fanout: exit 0" || bad "fanout: exit $rc (want 0)"
echo "$OUT" | grep -q "chunks=2" && ok "fanout: 2 per-account sessions planned" || bad "fanout: expected chunks=2"
[ -f "$REPORT" ] && ok "fanout: report rendered" || bad "fanout: no report"
[ -f "$REPORT" ] && check_merged_report "fanout"

echo "== C) precondition guards =="
# no UDM connector in `mcp list` -> clean exit 2, nothing pulled
cat > "$BIN/claude_noconn" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = "mcp" ] && { echo "randomserver: https://x (HTTP) - connected"; exit 0; }
exit 0
EOF
chmod +x "$BIN/claude_noconn"
CLAUDE_BIN="$BIN/claude_noconn" bash "$ROOT/run_attack_path.sh" --budget 100 --data "$WORK/d2" --yes >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "no-connector -> clean exit 2" || bad "no-connector should exit 2"
# bad budget -> clean exit 2
CLAUDE_BIN="$BIN/claude" bash "$ROOT/run_attack_path.sh" --budget 0 --data "$WORK/d3" --yes >/dev/null 2>&1
[ "$?" -eq 2 ] && ok "budget=0 -> clean exit 2" || bad "budget=0 should exit 2"
# explicit --connector overrides auto-detect. Point the mock's output env at THIS run's data dir.
mkdir -p "$WORK/d4/raw"
OUT="$( CLAUDE_BIN="$BIN/claude" MOCK_RAW_DIR="$WORK/d4/raw" MOCK_SIZES="$WORK/d4/sizes.json" \
        bash "$ROOT/run_attack_path.sh" --connector tenablecs-org1 \
        --budget 4000 --data "$WORK/d4" --date 2026-08-03 --yes 2>&1 )"
echo "$OUT" | grep -q "connector=tenablecs-org1" && ok "--connector honored" || bad "--connector not honored ($OUT)"

rm -f "$REPORT" 2>/dev/null || true
echo ""
echo "orchestrator: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
