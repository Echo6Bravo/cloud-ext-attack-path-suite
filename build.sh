#!/usr/bin/env bash
# Build a distributable .plugin (zip) for every plugin under ./plugins into ./dist.
#
# The detection logic (attack_path_spec.py), the renderer (render_report.py), the
# reference queries (queries/), and the synthetic sample (data/sample/) live ONCE at the
# repo root as the single source of truth. This script SYNCS them into each plugin's
# bundled scripts/ (and references) at build time so the two never drift, then zips.
#
# Usage:  ./build.sh          # sync + package both editions into ./dist
#         ./build.sh --sync   # sync bundled copies only (no zip); useful pre-commit
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"

# --- 0. verify the logic before packaging anything --------------------------
echo "verifying detection spec..."
python3 "$ROOT/attack_path_spec.py" >/dev/null
echo "  spec self-tests passed"

# --- 1. sync the shared library into each plugin ----------------------------
MCP_SKILL="$ROOT/plugins/ext-attack-path-agent/skills/ext-attack-path"
API_SKILL="$ROOT/plugins/ext-attack-path-agent-api/skills/ext-attack-path-api"

sync_shared () {
  local skill_dir="$1"
  mkdir -p "$skill_dir/scripts" "$skill_dir/references"
  cp "$ROOT/attack_path_spec.py" "$skill_dir/scripts/attack_path_spec.py"
  cp "$ROOT/render_report.py"    "$skill_dir/scripts/render_report.py"
  cp "$ROOT/assemble.py"         "$skill_dir/scripts/assemble.py"   # MCP raw-page -> assembled.json
  # turnkey one-command orchestrator (auto-size -> plan -> fan-out -> merge -> render).
  # MCP edition only: it drives headless `claude -p` MCP sessions, irrelevant to the API edition.
  case "$skill_dir" in
    *ext-attack-path) cp "$ROOT/run_attack_path.sh" "$skill_dir/scripts/run_attack_path.sh" ;;
  esac
  # sample data so the skill can be demoed offline
  mkdir -p "$skill_dir/scripts/data/sample"
  cp "$ROOT/data/sample/assembled.json"    "$skill_dir/scripts/data/sample/assembled.json"
  cp "$ROOT/data/sample/endpoint_ips.json" "$skill_dir/scripts/data/sample/endpoint_ips.json"
}

sync_shared "$MCP_SKILL"
sync_shared "$API_SKILL"
# reference queries: root queries/ is authoritative; copy into the MCP skill references
cp "$ROOT"/queries/*.json "$MCP_SKILL/references/" 2>/dev/null || true
echo "  synced shared lib into both plugins"

if [ "${1:-}" = "--sync" ]; then
  echo "sync-only complete"
  exit 0
fi

# --- 2. package each plugin -------------------------------------------------
mkdir -p "$DIST"
rm -f "$DIST"/*.plugin 2>/dev/null || true

for dir in "$ROOT"/plugins/*/; do
  name="$(python3 -c "import json; print(json.load(open('$dir/.claude-plugin/plugin.json'))['name'])")"
  out="$DIST/$name.plugin"
  ( cd "$dir" && zip -r "$out" . -x "*.DS_Store" -x "*.plugin" -x "*__pycache__*" >/dev/null )
  echo "built  $out"
done

echo "done -> $DIST"
