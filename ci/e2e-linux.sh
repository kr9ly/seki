#!/usr/bin/env bash
# End-to-end test of the Linux sandbox: the shared per-session
# CLAUDE_CONFIG_DIR suite (ci/e2e-claudecfg.sh) inside the netns backend.
set -euo pipefail

SEKI=$PWD/seki
export HOME=$(mktemp -d)
"$PWD/ci/e2e-claudecfg.sh" "$SEKI"
echo "linux sandbox E2E: OK"
