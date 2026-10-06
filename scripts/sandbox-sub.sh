#!/usr/bin/env bash
# Test a real V2Ray subscription inside the isolated sandbox container (see sandbox.sh).
#
#   bash scripts/sandbox-sub.sh /path/to/sub.txt          # file holding the subscription URL, or the links/YAML/JSON itself
#   NODE_LIMIT=20 bash scripts/sandbox-sub.sh sub.txt      # test more nodes (default 12)
#
# The file is mounted read-only into the container and never copied into the repository. The report
# prints node names, protocols, latency and the exit country; it never prints hosts, UUIDs or passwords.
set -euo pipefail
cd "$(dirname "$0")/.."

SUB="${1:-}"
[ -n "$SUB" ] && [ -f "$SUB" ] || { echo "usage: $0 /path/to/subscription-file" >&2; exit 64; }
SUB="$(readlink -f "$SUB")"

export SANDBOX_MOUNT="$SUB:/sub/sub.txt:ro"
export SANDBOX_INSIDE="python3 /work/scripts/sandbox-sub-inside.py"
exec bash scripts/sandbox.sh
