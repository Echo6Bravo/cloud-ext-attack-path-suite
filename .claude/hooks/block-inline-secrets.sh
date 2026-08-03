#!/usr/bin/env bash
# PreToolUse(Bash) hook: block a shell command that hard-codes a secret inline, forcing
# environment-variable / secrets-file usage instead. Prevents the "token pasted into a command
# ends up in the transcript / shell history / logs" problem structurally.
#
# Reads the hook JSON on stdin; emits a PreToolUse decision on stdout.
#   - deny  -> the command is blocked with a reason shown to the model/user.
#   - (silent pass) -> anything else is allowed.
#
# Deliberately narrow to avoid false positives: it flags an ASSIGNMENT of a known secret var
# to a NON-placeholder literal, and a few high-signal token shapes. `export FOO="$BAR"` or
# `TOKEN=<your-token>` style placeholders are allowed.
set -euo pipefail

payload="$(cat)"
cmd="$(printf '%s' "$payload" | jq -r '.tool_input.command // ""' 2>/dev/null || printf '')"
[ -z "$cmd" ] && exit 0

deny() {
  # emit a PreToolUse "deny" decision (schema: hookSpecificOutput.permissionDecision)
  jq -nc --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

# 1) Known secret env-vars assigned to a real (non-placeholder) value on the command line.
#    Matches e.g. TENABLE_CS_API_TOKEN=abc123...  /  AWS_SECRET_ACCESS_KEY=...
if printf '%s' "$cmd" | grep -Eq '(TENABLE_CS_API_TOKEN|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|API_TOKEN|API_KEY|SECRET_KEY|BEARER_TOKEN)=[A-Za-z0-9_+/=.-]{12,}'; then
  # allow obvious placeholders / env-indirection
  if ! printf '%s' "$cmd" | grep -Eq '=(\$|"\$|<|\{\{|xxx|your-|YOUR-|changeme|REDACTED|example)'; then
    deny "Inline secret detected: a credential is assigned to a literal value on the command line, which would leak into the transcript, shell history, and logs. Set it via an environment variable exported outside the command, or read it from a gitignored secrets file (e.g. \$TENABLE_CS_API_TOKEN)."
  fi
fi

# 2) High-signal standalone token shapes (GitHub PATs, AWS keys, Slack, private keys).
if printf '%s' "$cmd" | grep -Eq '(gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)'; then
  deny "A credential/token/private-key literal was detected in the command. Do not pass secrets inline; use an environment variable or a gitignored secrets file so it never enters the transcript or logs."
fi

exit 0
