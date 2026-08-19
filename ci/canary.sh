#!/usr/bin/env bash
# Canary against the real Claude Code binary. seki's per-session config
# dirs depend on two pieces of Claude Code behavior that are outside our
# control and could change with any release:
#   1. CLAUDE_CONFIG_DIR relocates .claude.json into that directory
#      (and the session never touches $HOME/.claude.json).
#   2. Writes to files reached through a symlink resolve the link instead
#      of replacing it with a regular file.
# This script runs an unauthenticated `claude -p` against a fixture config
# dir and asserts both. No seki involved.
set -euo pipefail

CLAUDE=$(command -v claude || echo "$HOME/.local/bin/claude")
"$CLAUDE" --version

T=""
if command -v timeout >/dev/null; then T="timeout 180"; elif command -v gtimeout >/dev/null; then T="gtimeout 180"; fi

FAKEHOME=$(mktemp -d)
CFG=$FAKEHOME/cfg
SHARED=$FAKEHOME/shared
mkdir -p "$CFG" "$SHARED"

printf '{"verbose":false}' > "$SHARED/settings.json"
ln -s "$SHARED/settings.json" "$CFG/settings.json"
printf '{"numStartups":1}' > "$CFG/.claude.json"

cd "$FAKEHOME"
OUT=$(env HOME="$FAKEHOME" CLAUDE_CONFIG_DIR="$CFG" $T "$CLAUDE" -p "say ok" 2>&1 || true)
echo "claude output: $OUT"
[ -n "$OUT" ] || { echo "FAIL: claude produced no output"; exit 1; }

fail() { echo "FAIL: $1"; exit 1; }

[ -f "$CFG/.claude.json" ] || fail ".claude.json missing from CLAUDE_CONFIG_DIR"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$CFG/.claude.json" \
  || fail ".claude.json is not valid JSON after the run"
[ -L "$CFG/settings.json" ] || fail "settings.json symlink was replaced by a regular file"
[ ! -e "$FAKEHOME/.claude.json" ] || fail "claude wrote \$HOME/.claude.json despite CLAUDE_CONFIG_DIR"

echo "claude canary: OK"
