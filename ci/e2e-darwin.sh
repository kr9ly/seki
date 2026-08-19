#!/usr/bin/env bash
# Smoke test of the darwin Seatbelt backend on a GitHub Actions macOS
# runner: basic exec, per-profile CLAUDE_CONFIG_DIR, direct-outbound deny
# (Seatbelt), and allow/deny decisions through the CONNECT proxy.
set -euo pipefail

SEKI=$PWD/seki
FAKEHOME=$(mktemp -d)

mkdir -p "$FAKEHOME/.config/seki" "$FAKEHOME/proj"
cat > "$FAKEHOME/.config/seki/config.json" <<'EOF'
{"claude_profiles":{"default":"personal","projects":[]}}
EOF
cat > "$FAKEHOME/.config/seki/rules.json" <<'EOF'
{"rules":[{"match":"example.com","action":"allow"},{"match":"*","action":"deny"}]}
EOF

cd "$FAKEHOME/proj"

echo "--- exec + per-profile CLAUDE_CONFIG_DIR"
OUT=$(HOME=$FAKEHOME "$SEKI" exec --claude-profile work -- /bin/sh -c 'echo "CFG=$CLAUDE_CONFIG_DIR"; echo sandbox-ok')
echo "$OUT"
echo "$OUT" | grep -q sandbox-ok
echo "$OUT" | grep -q "CFG=$FAKEHOME/.claude-profiles/work"

echo "--- Seatbelt blocks direct outbound (proxy bypassed)"
if HOME=$FAKEHOME "$SEKI" exec -- /usr/bin/curl -s --noproxy '*' --connect-timeout 10 https://example.com >/dev/null 2>&1; then
  echo "FAIL: direct outbound was not blocked by Seatbelt"
  exit 1
fi
echo "direct-outbound deny: OK"

echo "--- allowed domain via CONNECT proxy"
HOME=$FAKEHOME "$SEKI" exec -- /bin/sh -c 'curl -s --connect-timeout 20 https://example.com' | grep -qi example
echo "proxy allow: OK"

echo "--- denied domain via CONNECT proxy"
if HOME=$FAKEHOME "$SEKI" exec -- /bin/sh -c 'curl -s --connect-timeout 10 https://github.com' >/dev/null 2>&1; then
  echo "FAIL: denied domain was reachable through the proxy"
  exit 1
fi
echo "proxy deny: OK"

echo "darwin seatbelt smoke: OK"
