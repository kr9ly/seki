#!/usr/bin/env bash
# Shared (linux + darwin) end-to-end test of the per-session
# CLAUDE_CONFIG_DIR: materialization, symlinked shared assets, survival of
# Claude Code's atomic-rename rewrites, the exit sync-back (identity,
# credentials, host merge, salvage), and migration from the legacy darwin
# layout where ~/.claude-profiles/<p> itself was CLAUDE_CONFIG_DIR.
#
# Usage: HOME=<fakehome> e2e-claudecfg.sh <seki-binary>
set -euo pipefail

SEKI=$1
fail() { echo "FAIL: $1"; exit 1; }

# Realistic login shape: syncCredentials only trusts a file with non-empty
# access/refresh tokens and uses expiresAt as the freshness clock.
login() { printf '{"claudeAiOauth":{"accessToken":"%s","refreshToken":"r","expiresAt":%s}}' "$1" "$2"; }

mkdir -p "$HOME/.claude/skills" "$HOME/.config/seki" "$HOME/.claude-profiles/work" "$HOME/proj"

cat > "$HOME/.claude.json" <<'JSON'
{"oauthAccount":{"accountUuid":"host-acct"},"numStartups":1,"projects":{"/host":{"x":1}}}
JSON
login host 100 > "$HOME/.claude/.credentials.json"
printf '{"verbose":false}' > "$HOME/.claude/settings.json"
echo skill > "$HOME/.claude/skills/s.md"

printf '{"accountUuid":"work-acct"}' > "$HOME/.claude-profiles/work/oauthAccount.json"
login work 100 > "$HOME/.claude-profiles/work/.credentials.json"

cat > "$HOME/.config/seki/config.json" <<'JSON'
{"claude_profiles":{"default":"personal","projects":[]}}
JSON

cat > "$HOME/inner.sh" <<'EOF2'
set -eu
[ -n "$CLAUDE_CONFIG_DIR" ] || { echo "CLAUDE_CONFIG_DIR not set"; exit 1; }
case "$CLAUDE_CONFIG_DIR" in */.claude-profiles/work/sessions/*) ;; *) echo "unexpected dir $CLAUDE_CONFIG_DIR"; exit 1;; esac
grep -q work-acct "$CLAUDE_CONFIG_DIR/.claude.json"
grep -q '"accessToken":"work"' "$CLAUDE_CONFIG_DIR/.credentials.json"
[ -L "$CLAUDE_CONFIG_DIR/settings.json" ]
[ -L "$CLAUDE_CONFIG_DIR/skills" ]
grep -q skill "$CLAUDE_CONFIG_DIR/skills/s.md"

# Simulate Claude Code's atomic-rename rewrite of .claude.json.
cat > "$CLAUDE_CONFIG_DIR/.claude.json.tmp" <<'JSON'
{"oauthAccount":{"accountUuid":"work-acct2"},"numStartups":2,"projects":{"/session":{"y":1}}}
JSON
mv "$CLAUDE_CONFIG_DIR/.claude.json.tmp" "$CLAUDE_CONFIG_DIR/.claude.json"

# Simulate a token refresh (fresher expiresAt) and a state file with no
# ~/.claude counterpart.
printf '{"claudeAiOauth":{"accessToken":"work2","refreshToken":"r","expiresAt":200}}' > "$CLAUDE_CONFIG_DIR/.credentials.json"
echo orphan > "$CLAUDE_CONFIG_DIR/new-state.txt"
echo inner-ok
EOF2

cd "$HOME/proj"
echo "--- session lifecycle (profile: work)"
OUT=$("$SEKI" exec --claude-profile work -- bash "$HOME/inner.sh")
echo "$OUT"
echo "$OUT" | grep -q inner-ok

grep -q work-acct2 "$HOME/.claude-profiles/work/oauthAccount.json" \
  || fail "session identity not persisted to profile store"
grep -q '"accessToken":"work2"' "$HOME/.claude-profiles/work/.credentials.json" \
  || fail "refreshed credentials not synced to profile store"
grep -q '"accessToken":"host"' "$HOME/.claude/.credentials.json" \
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

echo "--- legacy layout migration (profile dir was CLAUDE_CONFIG_DIR)"
mkdir -p "$HOME/.claude-profiles/legacy" "$HOME/.claude-profiles/personal"
printf '{"oauthAccount":{"accountUuid":"legacy-acct"},"numStartups":9}' > "$HOME/.claude-profiles/legacy/.claude.json"
login legacy 100 > "$HOME/.claude-profiles/legacy/.credentials.json"
printf '{"verbose":true}' > "$HOME/.claude-profiles/legacy/settings.json"
OUT=$("$SEKI" exec --claude-profile legacy -- bash -c '
  grep -q legacy-acct "$CLAUDE_CONFIG_DIR/.claude.json" || { echo "legacy identity not applied"; exit 1; }
  grep -q '"'"'"verbose":false'"'"' "$CLAUDE_CONFIG_DIR/settings.json" || { echo "settings must come from ~/.claude, not the legacy profile dir"; exit 1; }
  echo legacy-ok')
echo "$OUT"
echo "$OUT" | grep -q legacy-ok
grep -q legacy-acct "$HOME/.claude-profiles/legacy/oauthAccount.json" \
  || fail "legacy identity not migrated into oauthAccount.json"

# Default profile: a legacy per-profile login fresher than ~/.claude's is adopted.
login personal 300 > "$HOME/.claude-profiles/personal/.credentials.json"
OUT=$("$SEKI" exec --claude-profile personal -- bash -c '
  grep -q '"'"'"accessToken":"personal"'"'"' "$CLAUDE_CONFIG_DIR/.credentials.json" || { echo "default profile did not adopt legacy login"; exit 1; }
  echo default-ok')
echo "$OUT"
echo "$OUT" | grep -q default-ok
grep -q '"accessToken":"personal"' "$HOME/.claude/.credentials.json" \
  || fail "legacy default-profile login not adopted into ~/.claude"

echo "claudecfg E2E: OK"
