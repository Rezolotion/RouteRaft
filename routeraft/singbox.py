"""Compile RouteRaft state into a sing-box (>=1.12) config.

One TUN captures the whole laptop. Every exit is an outbound/endpoint, `global` is a
selector (switchable at runtime through the clash API), and the routing map becomes
ordered route + DNS rules. Targets: sing-box 1.12+ (endpoints, DNS server types).
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

from .config import SELECTABLE_TYPES

MATCH_KEYS = ("domain_suffix", "domain", "ip_cidr", "rule_set", "process_name")


def _wireguard(e: dict) -> dict:
    return {
        "type": "wireguard",
        "tag": e["id"],
        "address": e["address"],
        "private_key": e["private_key"],
        "mtu": e.get("mtu", 1280),
        "peers": [
            {
                "address": e["server"],
                "port": e["server_port"],
                "public_key": e["peer_public_key"],
                "allowed_ips": e.get("allowed_ips", ["0.0.0.0/0", "::/0"]),
                **({"pre_shared_key": e["pre_shared_key"]} if e.get("pre_shared_key") else {}),
            }
        ],
    }


def _vless(e: dict) -> dict:
    o = {
        "type": "vless",
        "tag": e["id"],
        "server": e["server"],
        "server_port": e["server_port"],
        "uuid": e["uuid"],
    }
    if e.get("flow"):
        o["flow"] = e["flow"]
    sec = e.get("security", "none")
    if sec in ("tls", "reality"):
        tls = {"enabled": True, "server_name": e.get("sni") or e.get("host") or e["server"]}
        if e.get("insecure"):
            tls["insecure"] = True
        if e.get("alpn"):
            tls["alpn"] = e["alpn"].split(",")
        if e.get("fingerprint"):
            tls["utls"] = {"enabled": True, "fingerprint": e["fingerprint"]}
        if sec == "reality":
            tls["reality"] = {
                "enabled": True,
                "public_key": e["reality_public_key"],
                "short_id": e.get("reality_short_id", ""),
            }
            tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
        o["tls"] = tls
    net = e.get("network", "tcp")
    if net == "ws":
        t = {"type": "ws", "path": e.get("path") or "/"}
        if e.get("host"):
            t["headers"] = {"Host": e["host"]}
        o["transport"] = t
    elif net == "grpc":
        o["transport"] = {"type": "grpc", "service_name": e.get("service_name", "")}
    elif net == "httpupgrade":
        o["transport"] = {"type": "httpupgrade", "path": e.get("path") or "/", "host": e.get("host", "")}
    elif net in ("h2", "http"):
        o["transport"] = {"type": "http", "path": e.get("path") or "/", "host": [e["host"]] if e.get("host") else []}
    return o


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def build(state: dict, rule_dir: Path | None = None) -> dict:
    st = state["settings"]
    exits = state["exits"]
    corp = state["corp"]
    corp_on = bool(corp.get("enabled") and corp.get("ovpn_path"))
    sel_ids = [i for i, e in exits.items() if e["type"] in SELECTABLE_TYPES]
    vless_ids = [i for i, e in exits.items() if e["type"] == "vless"]

    endpoints, outbounds = [], [{"type": "direct", "tag": "direct"}]
    for e in exits.values():
        if e["type"] == "wireguard":
            endpoints.append(_wireguard(e))
        elif e["type"] == "vless":
            outbounds.append(_vless(e))

    members = list(sel_ids)
    if len(vless_ids) > 1:
        outbounds.append({
            "type": "urltest", "tag": "auto-vless", "outbounds": vless_ids,
            "url": st["test_url"], "interval": "5m", "tolerance": 100,
        })
        members.append("auto-vless")
    members.append("direct")
    default = state["global"] if state["global"] in members else members[0]
    outbounds.append({"type": "selector", "tag": "global", "outbounds": members, "default": default})
    if corp_on:
        outbounds.append({"type": "direct", "tag": "corp", "bind_interface": corp["interface"]})

    # ---- rule sets: prefer files cached by `routeraft update-rules`, else fetch via global
    rule_sets, known_sets = [], set()
    used = {s for r in state["routes"] if r["enabled"] for s in r["rule_set"]}
    for tag in sorted(used):
        url = st["rule_sets"].get(tag)
        if not url:
            continue
        local = rule_dir / f"{tag}.srs" if rule_dir else None
        if local and local.exists():
            rule_sets.append({"tag": tag, "type": "local", "format": "binary", "path": str(local)})
        else:
            rule_sets.append({"tag": tag, "type": "remote", "format": "binary", "url": url,
                              "download_detour": "global", "update_interval": "7d"})
        known_sets.add(tag)

    def target(exit_ref: str) -> str:
        if exit_ref in ("global", "direct"):
            return exit_ref
        if exit_ref == "corp":
            return "corp" if corp_on else "direct"
        return exit_ref if exit_ref in exits or exit_ref == "auto-vless" else "global"

    # ---- DNS: each destination resolves on the side of the exit it will use
    local_dns = ({"type": "local", "tag": "dns-direct"} if st["local_dns"] == "local"
                 else {"type": "udp", "tag": "dns-direct", "server": st["local_dns"]})
    dns_servers = [local_dns, {"type": "https", "tag": "dns-global", "server": st["remote_dns"], "detour": "global"}]
    if corp_on and corp.get("dns"):
        dns_servers.append({"type": "udp", "tag": "dns-corp", "server": corp["dns"], "detour": "corp"})
    dns_for = {"direct": "dns-direct", "global": "dns-global"}
    if corp_on and corp.get("dns"):
        dns_for["corp"] = "dns-corp"

    route_rules = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
    ]
    dns_rules = []
    # keep the company VPN's own transport off the tunnel (no VPN-in-VPN loop)
    bypass = {"action": "route", "outbound": "direct", "process_name": ["openvpn"]}
    route_rules.append(bypass)
    if corp_on and corp.get("server"):
        key = "ip_cidr" if _is_ip(corp["server"]) else "domain"
        route_rules.append({key: [corp["server"]], "action": "route", "outbound": "direct"})
        dns_rules.append({"domain": [corp["server"]], "action": "route", "server": "dns-direct"}
                         if key == "domain" else None)

    for r in state["routes"]:
        if not r["enabled"]:
            continue
        match = {k: [x for x in r.get(k, []) if (k != "rule_set" or x in known_sets)] for k in MATCH_KEYS}
        match = {k: v for k, v in match.items() if v}
        if not match:
            continue
        out = target(r["exit"])
        route_rules.append({**match, "action": "route", "outbound": out})
        dns_match = {k: v for k, v in match.items() if k in ("domain_suffix", "domain", "rule_set")}
        if dns_match:
            dns_rules.append({**dns_match, "action": "route", "server": dns_for.get(out, "dns-global")})
    dns_rules = [d for d in dns_rules if d]

    route_rules.append({"ip_is_private": True, "action": "route", "outbound": "direct"})

    tun = {
        "type": "tun", "tag": "tun-in", "interface_name": st["tun_name"],
        "address": [st["tun_address"]] + (["fdfe:dcba:9876::1/126"] if st["ipv6"] else []),
        "auto_route": True, "strict_route": True, "stack": "mixed",
    }
    if st.get("tun_exclude"):
        tun["route_exclude_address"] = st["tun_exclude"]

    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {"servers": dns_servers, "rules": dns_rules, "final": "dns-global",
                "strategy": "prefer_ipv4" if st["ipv6"] else "ipv4_only"},
        "inbounds": [tun],
        "outbounds": outbounds,
        "endpoints": endpoints,
        "route": {
            "rules": route_rules,
            "rule_set": rule_sets,
            "final": "global",
            "auto_detect_interface": True,
            "default_domain_resolver": "dns-direct",
        },
        "experimental": {
            "clash_api": {"external_controller": f"127.0.0.1:{st['api_port']}", "secret": state["api_secret"]},
            "cache_file": {"enabled": True, "path": "cache.db"},
        },
    }
