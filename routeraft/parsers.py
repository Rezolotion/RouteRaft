"""Importers: turn provider files / links into RouteRaft exit dicts.

An *exit* is the unit you swap. Types:
  wireguard  - Surfshark / Windscribe / any WireGuard .conf
  vless      - one node of a V2Ray subscription
  openvpn    - the company VPN (.ovpn), runs as its own process
  direct     - the physical uplink (Iran route)
"""
from __future__ import annotations

import base64
import configparser
import re
import urllib.parse


def slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.-]+", "-", text.strip()).strip("-")
    return s[:48] or "node"


# ---------------------------------------------------------------- WireGuard
def parse_wireguard(text: str, name: str) -> dict:
    """Parse a wg-quick style .conf (Surfshark, Windscribe, Mullvad, ...)."""
    cp = configparser.ConfigParser(strict=False, delimiters=("=",), interpolation=None)
    cp.optionxform = str  # keep key case
    cp.read_string(text)
    if "Interface" not in cp or "Peer" not in cp:
        raise ValueError("not a WireGuard config: need [Interface] and [Peer]")
    iface, peer = cp["Interface"], cp["Peer"]

    def split(v: str) -> list[str]:
        return [x.strip() for x in v.split(",") if x.strip()]

    endpoint = peer["Endpoint"].strip()
    host, _, port = endpoint.rpartition(":")
    host = host.strip("[]")
    exit_ = {
        "id": slug(name),
        "type": "wireguard",
        "name": name,
        "address": split(iface["Address"]),
        "private_key": iface["PrivateKey"].strip(),
        "dns": split(iface["DNS"]) if "DNS" in iface else [],
        "mtu": int(iface.get("MTU", 1280)),
        "server": host,
        "server_port": int(port),
        "peer_public_key": peer["PublicKey"].strip(),
        "allowed_ips": split(peer.get("AllowedIPs", "0.0.0.0/0, ::/0")),
    }
    if "PresharedKey" in peer:
        exit_["pre_shared_key"] = peer["PresharedKey"].strip()
    return exit_


# -------------------------------------------------------------------- VLESS
def parse_vless(link: str) -> dict:
    """Parse vless://uuid@host:port?params#name into an exit dict."""
    u = urllib.parse.urlsplit(link.strip())
    if u.scheme != "vless":
        raise ValueError("not a vless:// link")
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    name = urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}"
    exit_ = {
        "id": slug(name),
        "type": "vless",
        "name": name,
        "server": u.hostname,
        "server_port": u.port,
        "uuid": urllib.parse.unquote(u.username or ""),
        "flow": q.get("flow", ""),
        "network": q.get("type", "tcp"),
        "security": q.get("security", "none"),
        "sni": q.get("sni", ""),
        "fingerprint": q.get("fp", ""),
        "alpn": q.get("alpn", ""),
        "path": urllib.parse.unquote(q.get("path", "")),
        "host": q.get("host", ""),
        "service_name": q.get("serviceName", ""),
        "reality_public_key": q.get("pbk", ""),
        "reality_short_id": q.get("sid", ""),
        "insecure": q.get("allowInsecure", "0") in ("1", "true"),
    }
    if not exit_["server"] or not exit_["server_port"] or not exit_["uuid"]:
        raise ValueError("vless link missing host/port/uuid")
    return exit_


def parse_subscription(body: str) -> list[dict]:
    """A subscription body is base64 (or plain) text with one link per line."""
    body = body.strip()
    if "://" not in body:
        padded = body + "=" * (-len(body) % 4)
        body = base64.b64decode(padded, altchars=b"-_").decode("utf-8", "replace")
    exits, seen = [], set()
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("vless://"):
            continue  # vmess/trojan/ss are ignored for now
        try:
            e = parse_vless(line)
        except ValueError:
            continue
        base, n = e["id"], 2
        while e["id"] in seen:
            e["id"] = f"{base}-{n}"
            n += 1
        seen.add(e["id"])
        exits.append(e)
    return exits


# ------------------------------------------------------------------ OpenVPN
def parse_ovpn_remote(text: str) -> tuple[str, int] | None:
    """Extract the first `remote host port` so we can keep it off the tunnel."""
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] == "remote" and len(parts) >= 2:
            port = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 1194
            return parts[1], port
    return None
