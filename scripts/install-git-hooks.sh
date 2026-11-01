#!/bin/bash
# Enable the repository's versioned git hooks.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK="$ROOT/.githooks/commit-msg"

[[ -f "$HOOK" ]] || { echo "missing hook: $HOOK" >&2; exit 1; }
chmod +x "$HOOK"
git -C "$ROOT" config core.hooksPath .githooks
echo "commit-msg hook enabled: .githooks/commit-msg"
