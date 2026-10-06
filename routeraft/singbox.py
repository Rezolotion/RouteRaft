"""Compile RouteRaft state into a sing-box (>=1.12) config.

One TUN captures the whole laptop. Every exit becomes an outbound/endpoint and `global`
is a selector (switchable at runtime through the clash API). OpenVPN/IKEv2 exits cannot
live inside sing-box, so they run as their own process on a fixed interface and sing-box
reaches them through one `direct` outbound bound to that interface ("ovpn" / "ikev2").
Only one such exit is up at a time: the one currently selected for `global`.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

MATCH_KEYS = ("domain_suffix", "domain", "ip_cidr", "rule_set", "process_name")
IKE_IFACE = "rr-ike0"


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def member_for(state: dict, exit_id: str) -> str:
    """Selector member that realises an exit id."""
    e = state["exits"].get(exit_id)
    if exit_id in ("direct",) or exit_id.startswith("auto:"):
        return exit_id
    if not e:
        return "direct"
    return {"openvpn": "ovpn", "ikev2": "ikev2"}.get(e["kind"], exit_id)


def loaded_wireguard(state: dict) -> set[str]:
    """WireGuard endpoints start with sing-box, so only keep favourites + the selected one loaded."""
    wg = {i for i, e in state["exits"].items() if e["kind"] == "wireguard"}
    return (set(state["favorites"]) | {state["global"]}) & wg


def build(state: dict, rule_dir: Path | None = None) -> dict:
    st, exits, corp = state["settings"], state["exits"], state["corp"]
    corp_on = bool(corp.get("enabled") and corp.get("ovpn_path"))
    sb_ids = [i for i, e in exits.items() if e["kind"] == "singbox"]
    wg_ids = sorted(loaded_wireguard(state))
    has_ovpn = any(e["kind"] == "openvpn" for e in exits.values())
    has_ike = any(e["kind"] == "ikev2" for e in exits.values())

    outbounds = [{"type": "direct", "tag": "direct"}]
    endpoints = []
    for i in sb_ids:
        outbounds.append({**exits[i]["outbound"], "tag": i})
    for i in wg_ids:
        endpoints.append({**exits[i]["endpoint"], "tag": i})

    members = list(sb_ids) + wg_ids
    by_provider: dict[str, list[str]] = {}
    for i in sb_ids:
        by_provider.setdefault(exits[i]["provider"], []).append(i)
    for prov, ids in by_provider.items():
        if len(ids) > 1:
            tag = f"auto:{prov}"
            outbounds.append({"type": "urltest", "tag": tag, "outbounds": ids, "url": st["test_url"],
                              "interval": "5m", "tolerance": 100})
            members.append(tag)
    if has_ovpn:
        outbounds.append({"type": "direct", "tag": "ovpn", "bind_interface": st["vpn_iface"]})
        members.append("ovpn")
    if has_ike:
        outbounds.append({"type": "direct", "tag": "ikev2", "bind_interface": IKE_IFACE})
        members.append("ikev2")
    members.append("direct")
    want = member_for(state, state["global"]) if state["global"] else "direct"
    outbounds.append({"type": "selector", "tag": "global", "outbounds": members,
                      "default": want if want in members else "direct"})
    if corp_on:
        outbounds.append({"type": "direct", "tag": "corp", "bind_interface": corp["interface"]})

    # ---- rule sets: prefer files cached by `routeraft update-rules`, else fetch via global
    rule_sets, known = [], set()
    for tag in sorted({s for r in state["routes"] if r["enabled"] for s in r["rule_set"]}):
        url = st["rule_sets"].get(tag)
        if not url:
            continue
        local = rule_dir / f"{tag}.srs" if rule_dir else None
        if local and local.exists():
            rule_sets.append({"tag": tag, "type": "local", "format": "binary", "path": str(local)})
        else:
            rule_sets.append({"tag": tag, "type": "remote", "format": "binary", "url": url,
                              "download_detour": "global", "update_interval": "7d"})
        known.add(tag)

    tags = {o["tag"] for o in outbounds} | {e["tag"] for e in endpoints}

    def target(ref: str) -> str:
        if ref in ("global", "direct"):
            return ref
        if ref == "corp":
            return "corp" if corp_on else "direct"
        return ref if ref in tags else "global"  # pinned exit that is not loaded falls back to global

    # ---- DNS: each destination resolves on the side of the exit it will use
    local = ({"type": "local", "tag": "dns-direct"} if st["local_dns"] == "local"
             else {"type": "udp", "tag": "dns-direct", "server": st["local_dns"]})
    dns_servers = [local, {"type": "https", "tag": "dns-global", "server": st["remote_dns"], "detour": "global"}]
    dns_for = {"direct": "dns-direct", "global": "dns-global"}
    if corp_on and corp.get("dns"):
        dns_servers.append({"type": "udp", "tag": "dns-corp", "server": corp["dns"], "detour": "corp"})
        dns_for["corp"] = "dns-corp"

    route_rules = [{"action": "sniff"}, {"protocol": "dns", "action": "hijack-dns"}]
    dns_rules: list[dict] = []

    # keep VPN transports off the tunnel (no VPN-in-VPN loop)
    route_rules.append({"process_name": ["openvpn", "charon", "stunnel4", "stunnel", "wstunnel"],
                        "action": "route", "outbound": "direct"})
    bypass: list[str] = []
    g = exits.get(state["global"])
    if g and g["kind"] in ("openvpn", "ikev2"):
        bypass += [r["host"] for r in g.get("remotes", [])] or [g["server"]]
    if corp_on and corp.get("server"):
        bypass.append(corp["server"])
    ips = sorted({b for b in bypass if is_ip(b)})
    doms = sorted({b for b in bypass if b and not is_ip(b)})
    if ips:
        route_rules.append({"ip_cidr": ips, "action": "route", "outbound": "direct"})
    if doms:
        route_rules.append({"domain": doms, "action": "route", "outbound": "direct"})
        dns_rules.append({"domain": doms, "action": "route", "server": "dns-direct"})

    for r in state["routes"]:
        if not r["enabled"]:
            continue
        match = {k: [x for x in r.get(k, []) if k != "rule_set" or x in known] for k in MATCH_KEYS}
        match = {k: v for k, v in match.items() if v}
        if not match:
            continue
        out = target(r["exit"])
        route_rules.append({**match, "action": "route", "outbound": out})
        dm = {k: v for k, v in match.items() if k in ("domain_suffix", "domain", "rule_set")}
        if dm:
            dns_rules.append({**dm, "action": "route", "server": dns_for.get(out, "dns-global")})

    route_rules.append({"ip_is_private": True, "action": "route", "outbound": "direct"})

    tun = {"type": "tun", "tag": "tun-in", "interface_name": st["tun_name"],
           "address": [st["tun_address"]] + (["fdfe:dcba:9876::1/126"] if st["ipv6"] else []),
           "auto_route": True, "strict_route": True, "stack": "mixed"}
    if st.get("tun_exclude"):
        tun["route_exclude_address"] = st["tun_exclude"]

    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {"servers": dns_servers, "rules": dns_rules, "final": "dns-global",
                "strategy": "prefer_ipv4" if st["ipv6"] else "ipv4_only"},
        "inbounds": [tun],
        "outbounds": outbounds,
        "endpoints": endpoints,
        "route": {"rules": route_rules, "rule_set": rule_sets, "final": "global",
                  "auto_detect_interface": True, "default_domain_resolver": "dns-direct"},
        "experimental": {
            "clash_api": {"external_controller": f"127.0.0.1:{st['api_port']}", "secret": state["api_secret"]},
            "cache_file": {"enabled": True, "path": "cache.db"},
        },
    }
