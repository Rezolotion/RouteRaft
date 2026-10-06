#!/usr/bin/env bash
# Installs sing-box from the official SagerNet apt repo (Debian/Ubuntu). Run with sudo.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

mkdir -p /etc/apt/keyrings
curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc
chmod a+r /etc/apt/keyrings/sagernet.asc
cat > /etc/apt/sources.list.d/sagernet.sources <<'EOF'
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF
apt-get update
apt-get install -y sing-box
# The packaged unit would fight RouteRaft for the TUN; RouteRaft runs sing-box itself.
systemctl disable --now sing-box 2>/dev/null || true
sing-box version | head -1
