#!/usr/bin/env bash
# End-to-end test of the Linux sandbox's per-session CLAUDE_CONFIG_DIR:
# materialization, symlinked shared assets, survival of Claude Code's
# atomic-rename rewrites (the race that killed the bind-mount approach),
# and the exit sync-back (identity, credentials, host merge, salvage).
set -euo pipefail

SEKI=$PWD/seki
FAKEHOME=$(mktemp -d)
export HOME=$FAKEHOME

mkdir -p "$HOME/.claude/skills" "$HOME/.config/seki" "$HOME/.claude-profiles/work" "$HOME/proj"

cat > "$HOME/.claude.json" <<'EOF'
{"oauthAccount":{"accountUuid":"host-acct"},"numStartups":1,"projects":{"/host":{"x":1}}}
EOF
printf '{"token":"host"}' > "$HOME/.claude/.credentials.json"
printf '{"verbose":false}' > "$HOME/.claude/settings.json"
echo skill > "$HOME/.claude/skills/s.md"

printf '{"accountUuid":"work-acct"}' > "$HOME/.claude-profiles/work/oauthAccount.json"
printf '{"token":"work"}' > "$HOME/.claude-profiles/work/.credentials.json"

cat > "$HOME/.config/seki/config.json" <<'EOF'
{"claude_profiles":{"default":"personal","projects":[]}}
EOF

cat > "$HOME/inner.sh" <<'EOF'
set -eu
[ -n "$CLAUDE_CONFIG_DIR" ] || { echo "CLAUDE_CONFIG_DIR not set"; exit 1; }
grep -q work-acct "$CLAUDE_CONFIG_DIR/.claude.json"
grep -q '"token":"work"' "$CLAUDE_CONFIG_DIR/.credentials.json"
[ -L "$CLAUDE_CONFIG_DIR/settings.json" ]
[ -L "$CLAUDE_CONFIG_DIR/skills" ]
grep -q skill "$CLAUDE_CONFIG_DIR/skills/s.md"

# Simulate Claude Code's atomic-rename rewrite of .claude.json.
cat > "$CLAUDE_CONFIG_DIR/.claude.json.tmp" <<'JSON'
{"oauthAccount":{"accountUuid":"work-acct2"},"numStartups":2,"projects":{"/session":{"y":1}}}
JSON
mv "$CLAUDE_CONFIG_DIR/.claude.json.tmp" "$CLAUDE_CONFIG_DIR/.claude.json"

# Simulate a token refresh and a state file with no ~/.claude counterpart.
printf '{"token":"work2"}' > "$CLAUDE_CONFIG_DIR/.credentials.json"
echo orphan > "$CLAUDE_CONFIG_DIR/new-state.txt"
echo inner-ok
EOF

cd "$HOME/proj"
OUT=$("$SEKI" exec --claude-profile work -- bash "$HOME/inner.sh")
echo "$OUT"
echo "$OUT" | grep -q inner-ok

fail() { echo "FAIL: $1"; exit 1; }

grep -q work-acct2 "$HOME/.claude-profiles/work/oauthAccount.json" \
  || fail "session identity not persisted to profile store"
grep -q '"token":"work2"' "$HOME/.claude-profiles/work/.credentials.json" \
  || fail "refreshed credentials not synced to profile store"
grep -q '"token":"host"' "$HOME/.claude/.credentials.json" \
  || fail "host credentials must stay untouched for a non-default profile"
grep -q host-acct "$HOME/.claude.json" \
  || fail "host identity must be preserved by the merge"
grep -q '"/session"' "$HOME/.claude.json" \
  || fail "session project not merged into host claude.json"
grep -q '"/host"' "$HOME/.claude.json" \
  || fail "host project wiped by the merge"
grep -q orphan "$HOME/.claude/new-state.txt" \
  || fail "new session state not salvaged into ~/.claude"
[ -z "$(ls -A "$HOME/.claude-profiles/work/sessions" 2>/dev/null)" ] \
  || fail "session dir not cleaned up"

echo "linux sandbox E2E: OK"
