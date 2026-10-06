#!/usr/bin/env bash
# Installs or upgrades sing-box from the official SagerNet apt repository (Debian / Ubuntu). Run with sudo.
#
# Only the SagerNet index is refreshed, never the whole system. A plain `apt-get update` waits on every
# configured repository, and one unreachable mirror can add a minute or more to every run.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

KEYRING=/etc/apt/keyrings/sagernet.asc
LIST=/etc/apt/sources.list.d/sagernet.list

mkdir -p /etc/apt/keyrings
if [ ! -s "$KEYRING" ]; then
  curl -fsSL --max-time 30 https://sing-box.app/gpg.key -o "$KEYRING"
  chmod a+r "$KEYRING"
fi

rm -f /etc/apt/sources.list.d/sagernet.sources   # deb822 file from an earlier version of this script
echo "deb [signed-by=$KEYRING] https://deb.sagernet.org/ * *" > "$LIST"

# One-line source files can be updated in isolation (deb822 .sources files cannot).
apt-get \
  -o Dir::Etc::sourcelist="$LIST" -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0 \
  -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o Acquire::Retries=1 \
  update

apt-get install -y sing-box

# The packaged unit would fight RouteRaft for the TUN device; RouteRaft runs sing-box itself.
systemctl disable --now sing-box 2>/dev/null || true
sing-box version | head -1
