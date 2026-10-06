#!/usr/bin/env bash
# Run the live test suite inside a throwaway Docker container.
#
# The container has its own network namespace, so the TUN device, policy rules and DNS hijack that
# RouteRaft creates exist only there. Nothing touches the host's routes, interfaces or resolv.conf.
# The host's /usr is mounted read-only so the test uses the real sing-box, python and iproute2 binaries
# without pulling an image; this works because the container image and the host are both Debian 12.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE="${SANDBOX_IMAGE:-debian:12}"

# PID 1 inside the container must reap orphaned children (a SIGKILLed sing-box would otherwise linger as a
# zombie and confuse the checks). `docker --init` is not usable here because /usr is replaced by the host's.
REAPER='import os, sys
pid = os.fork()
if pid == 0:
    os.execvp("bash", ["bash", "/work/scripts/sandbox-inside.sh"])
while True:
    try:
        child, status = os.wait()
    except ChildProcessError:
        break
    if child == pid:
        sys.exit(os.waitstatus_to_exitcode(status))'

exec docker run --rm --name routeraft-sandbox \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -v /usr:/usr:ro -v /etc/ssl:/etc/ssl:ro -v /etc/ca-certificates:/etc/ca-certificates:ro \
  -v "$PWD":/work:ro -w /work \
  "$IMAGE" python3 -c "$REAPER"
