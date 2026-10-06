"""Importers: turn provider files / share links / subscriptions into RouteRaft exits.

Every exit is a dict with display fields (id, name, protocol, provider, country, server,
server_port, transport) plus ONE payload that carries the secrets:
  kind "singbox"   -> `outbound`  : a sing-box outbound (vless, vmess, trojan, shadowsocks,
                                     hysteria, hysteria2, tuic, anytls, socks, http)
  kind "wireguard" -> `endpoint`  : a sing-box WireGuard endpoint (Surfshark / Windscribe / any)
  kind "openvpn"   -> `ovpn_path` : a profile on disk, run as its own process (UDP or TCP)
Payload keys are stripped from everything the web UI can read (see config.Store.public).
"""
from __future__ import annotations

import base64
import binascii
import configparser
import json
import re
import urllib.parse
from pathlib import Path


class Unsupported(ValueError):
    """A link we understand but sing-box cannot run (e.g. xhttp, mKCP)."""


def slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.\-]+", "-", text.strip()).strip("-")
    return s[:48] or "node"


def b64decode(s: str) -> str:
    s = s.strip()
    return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_").decode("utf-8", "replace")


def _q(u: urllib.parse.SplitResult) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}


def _truthy(v) -> bool:
    return str(v).lower() in ("1", "true", "yes")


def _exit(name: str, protocol: str, outbound: dict, transport: str = "tcp", provider: str = "manual") -> dict:
    return {
        "id": slug(name), "name": name, "kind": "singbox", "protocol": protocol, "provider": provider,
        "country": guess_country(name), "server": outbound.get("server", ""),
        "server_port": outbound.get("server_port", 0), "transport": transport, "outbound": outbound,
    }


# ------------------------------------------------------------- shared pieces
def _tls(q: dict, server: str, default_on: bool = True, alpn_default: str = "") -> dict | None:
    sec = q.get("security", "tls" if default_on else "none")
    if sec in ("", "none"):
        return None
    tls: dict = {"enabled": True, "server_name": q.get("sni") or q.get("peer") or q.get("host") or server}
    if _truthy(q.get("allowInsecure", q.get("insecure", q.get("skip-cert-verify", "0")))):
        tls["insecure"] = True
    alpn = q.get("alpn") or alpn_default
    if alpn:
        tls["alpn"] = [a for a in urllib.parse.unquote(alpn).split(",") if a]
    if q.get("fp") and q["fp"] != "none":
        tls["utls"] = {"enabled": True, "fingerprint": q["fp"]}
    if sec == "reality":
        tls["reality"] = {"enabled": True, "public_key": q.get("pbk", ""), "short_id": q.get("sid", "")}
        tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
    return tls


def _transport(q: dict, net_key: str = "type") -> tuple[dict | None, str]:
    net = q.get(net_key, "tcp") or "tcp"
    host, path = q.get("host", ""), urllib.parse.unquote(q.get("path", ""))
    if net == "tcp":
        if q.get("headerType") == "http":
            return {"type": "http", "host": [h for h in host.split(",") if h], "path": path or "/"}, "tcp"
        return None, "tcp"
    if net == "ws":
        t = {"type": "ws", "path": path or "/"}
        if host:
            t["headers"] = {"Host": host}
        return t, "ws"
    if net == "grpc":
        return {"type": "grpc", "service_name": q.get("serviceName", q.get("path", ""))}, "grpc"
    if net == "httpupgrade":
        return {"type": "httpupgrade", "path": path or "/", "host": host}, "httpupgrade"
    if net in ("h2", "http"):
        return {"type": "http", "path": path or "/", "host": [h for h in host.split(",") if h]}, "h2"
    if net == "quic":
        return {"type": "quic"}, "quic"
    raise Unsupported(f"transport '{net}' is not supported by sing-box")


# ------------------------------------------------------------------ links
def parse_vless(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    q = _q(u)
    name = urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}"
    o = {"type": "vless", "server": u.hostname, "server_port": u.port, "uuid": urllib.parse.unquote(u.username or "")}
    if q.get("flow"):
        o["flow"] = q["flow"]
    if q.get("encryption", "none") not in ("none", ""):
        raise Unsupported("vless encryption is not supported")
    tls = _tls(q, u.hostname, default_on=False)
    if tls:
        o["tls"] = tls
    tr, tname = _transport(q)
    if tr:
        o["transport"] = tr
    if not (o["server"] and o["server_port"] and o["uuid"]):
        raise ValueError("vless link missing host/port/uuid")
    return _exit(name, "vless", o, tname)


def parse_vmess(link: str) -> dict:
    body = link[len("vmess://"):]
    try:
        j = json.loads(b64decode(body.split("#")[0]))
    except (binascii.Error, json.JSONDecodeError, ValueError):
        # non-standard URI form vmess://uuid@host:port?...
        u = urllib.parse.urlsplit(link)
        q = _q(u)
        j = {"ps": urllib.parse.unquote(u.fragment), "add": u.hostname, "port": u.port, "id": u.username,
             "net": q.get("type", "tcp"), "tls": "tls" if q.get("security") == "tls" else "", "host": q.get("host", ""),
             "path": q.get("path", ""), "sni": q.get("sni", ""), "aid": q.get("aid", 0), "scy": q.get("encryption", "auto")}
    name = j.get("ps") or f"{j['add']}:{j['port']}"
    o = {"type": "vmess", "server": j["add"], "server_port": int(j["port"]), "uuid": j["id"],
         "security": j.get("scy") or "auto", "alter_id": int(j.get("aid") or 0)}
    q = {"type": j.get("net", "tcp"), "host": j.get("host", ""), "path": j.get("path", ""),
         "headerType": j.get("type", ""), "serviceName": j.get("path", ""),
         "security": "tls" if j.get("tls") in ("tls", True) else "none",
         "sni": j.get("sni", ""), "alpn": j.get("alpn", ""), "fp": j.get("fp", "")}
    tls = _tls(q, j["add"], default_on=False)
    if tls:
        o["tls"] = tls
    tr, tname = _transport(q)
    if tr:
        o["transport"] = tr
    return _exit(name, "vmess", o, tname)


def parse_trojan(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    q = _q(u)
    name = urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}"
    o = {"type": "trojan", "server": u.hostname, "server_port": u.port, "password": urllib.parse.unquote(u.username or "")}
    tls = _tls(q, u.hostname, default_on=True)
    if tls:
        o["tls"] = tls
    tr, tname = _transport(q)
    if tr:
        o["transport"] = tr
    return _exit(name, "trojan", o, tname)


def parse_ss(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    name = urllib.parse.unquote(u.fragment)
    if "@" in (u.netloc or ""):  # SIP002: ss://base64(method:pass)@host:port or plain method:pass@host
        userinfo, _, hostport = u.netloc.rpartition("@")
        if ":" not in userinfo:
            userinfo = b64decode(userinfo)
        method, _, password = urllib.parse.unquote(userinfo).partition(":")
        host, _, port = hostport.rpartition(":")
    else:  # legacy: ss://base64(method:pass@host:port)
        raw = b64decode(link[len("ss://"):].split("#")[0].split("?")[0])
        userinfo, _, hostport = raw.rpartition("@")
        method, _, password = userinfo.partition(":")
        host, _, port = hostport.rpartition(":")
    o = {"type": "shadowsocks", "server": host.strip("[]"), "server_port": int(port), "method": method, "password": password}
    plugin = _q(u).get("plugin")
    if plugin:
        pname, _, opts = urllib.parse.unquote(plugin).partition(";")
        o["plugin"] = {"obfs-local": "obfs-local", "simple-obfs": "obfs-local", "v2ray-plugin": "v2ray-plugin"}.get(pname, pname)
        o["plugin_opts"] = opts
    return _exit(name or f"{host}:{port}", "shadowsocks", o, "tcp")


def parse_hysteria2(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    q = _q(u)
    name = urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}"
    pw = urllib.parse.unquote(u.username or "")
    if u.password:
        pw += ":" + urllib.parse.unquote(u.password)
    o = {"type": "hysteria2", "server": u.hostname, "server_port": u.port or 443, "password": pw,
         "tls": _tls({**q, "security": "tls"}, u.hostname)}
    if q.get("obfs"):
        o["obfs"] = {"type": q["obfs"], "password": q.get("obfs-password", "")}
    if q.get("mport"):
        o["server_ports"] = [p.replace("-", ":") for p in q["mport"].split(",")]
    if q.get("pinSHA256"):
        o["tls"]["certificate_public_key_sha256"] = [q["pinSHA256"]]
    return _exit(name, "hysteria2", o, "udp")


def parse_hysteria(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    q = _q(u)
    name = urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}"
    o = {"type": "hysteria", "server": u.hostname, "server_port": u.port,
         "up_mbps": int(re.sub(r"\D", "", q.get("upmbps", "")) or 50), "down_mbps": int(re.sub(r"\D", "", q.get("downmbps", "")) or 100),
         "tls": _tls({**q, "security": "tls"}, u.hostname)}
    if q.get("auth"):
        o["auth_str"] = q["auth"]
    if q.get("obfsParam"):
        o["obfs"] = q["obfsParam"]
    return _exit(name, "hysteria", o, "udp")


def parse_tuic(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    q = _q(u)
    name = urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}"
    o = {"type": "tuic", "server": u.hostname, "server_port": u.port, "uuid": urllib.parse.unquote(u.username or ""),
         "password": urllib.parse.unquote(u.password or ""), "congestion_control": q.get("congestion_control", "bbr"),
         "udp_relay_mode": q.get("udp_relay_mode", "native"),
         "tls": _tls({**q, "security": "tls", "insecure": q.get("allow_insecure", q.get("insecure", "0"))}, u.hostname, alpn_default="h3")}
    return _exit(name, "tuic", o, "udp")


def parse_anytls(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    q = _q(u)
    name = urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}"
    o = {"type": "anytls", "server": u.hostname, "server_port": u.port or 443,
         "password": urllib.parse.unquote(u.username or ""), "tls": _tls({**q, "security": "tls"}, u.hostname)}
    return _exit(name, "anytls", o, "tcp")


def parse_socks_http(link: str) -> dict:
    u = urllib.parse.urlsplit(link)
    name = urllib.parse.unquote(u.fragment) or f"{u.hostname}:{u.port}"
    typ = "socks" if u.scheme.startswith("socks") else "http"
    o = {"type": typ, "server": u.hostname, "server_port": u.port or (1080 if typ == "socks" else 8080)}
    if u.username:
        o["username"], o["password"] = urllib.parse.unquote(u.username), urllib.parse.unquote(u.password or "")
    if u.scheme == "https":
        o["tls"] = {"enabled": True, "server_name": u.hostname}
    return _exit(name, typ, o, "tcp")


LINK_PARSERS = {
    "vless": parse_vless, "vmess": parse_vmess, "trojan": parse_trojan, "ss": parse_ss,
    "hysteria2": parse_hysteria2, "hy2": parse_hysteria2, "hysteria": parse_hysteria,
    "tuic": parse_tuic, "anytls": parse_anytls,
    "socks": parse_socks_http, "socks5": parse_socks_http, "http": parse_socks_http, "https": parse_socks_http,
}


def parse_link(link: str) -> dict:
    scheme = link.split("://", 1)[0].lower()
    if scheme not in LINK_PARSERS:
        raise Unsupported(f"unknown scheme '{scheme}'")
    return LINK_PARSERS[scheme](link.strip())


# ------------------------------------------------------- Clash / sing-box JSON
def _clash_node(p: dict) -> dict:
    t, name = p.get("type", ""), str(p.get("name", ""))
    server, port = p.get("server"), int(p.get("port", 0))
    base = {"server": server, "server_port": port}
    tls = None
    if p.get("tls") or p.get("security") == "tls" or t in ("trojan", "hysteria2", "hysteria", "tuic", "anytls"):
        tls = {"enabled": True, "server_name": p.get("servername") or p.get("sni") or server}
        if p.get("skip-cert-verify"):
            tls["insecure"] = True
        if p.get("alpn"):
            tls["alpn"] = p["alpn"] if isinstance(p["alpn"], list) else [p["alpn"]]
        if p.get("client-fingerprint"):
            tls["utls"] = {"enabled": True, "fingerprint": p["client-fingerprint"]}
        ro = p.get("reality-opts")
        if ro:
            tls["reality"] = {"enabled": True, "public_key": ro.get("public-key", ""), "short_id": ro.get("short-id", "")}
            tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
    net = p.get("network", "tcp")
    tr = None
    if net == "ws":
        w = p.get("ws-opts", {}) or {}
        tr = {"type": "ws", "path": w.get("path", "/")}
        if (w.get("headers") or {}).get("Host"):
            tr["headers"] = {"Host": w["headers"]["Host"]}
    elif net == "grpc":
        tr = {"type": "grpc", "service_name": (p.get("grpc-opts") or {}).get("grpc-service-name", "")}
    elif net in ("h2", "http"):
        h = p.get(f"{net}-opts", {}) or {}
        tr = {"type": "http", "path": (h.get("path") or ["/"])[0] if isinstance(h.get("path"), list) else h.get("path", "/"),
              "host": h.get("host", [])}
    elif net == "httpupgrade":
        h = p.get("http-upgrade-opts", {}) or {}
        tr = {"type": "httpupgrade", "path": h.get("path", "/"), "host": h.get("host", "")}
    elif net not in ("tcp", ""):
        raise Unsupported(f"clash network '{net}' unsupported")

    if t == "vless":
        o = {"type": "vless", **base, "uuid": p["uuid"], **({"flow": p["flow"]} if p.get("flow") else {})}
    elif t == "vmess":
        o = {"type": "vmess", **base, "uuid": p["uuid"], "security": p.get("cipher", "auto"), "alter_id": int(p.get("alterId", 0))}
    elif t == "trojan":
        o = {"type": "trojan", **base, "password": p["password"]}
    elif t == "ss":
        o = {"type": "shadowsocks", **base, "method": p["cipher"], "password": p["password"]}
        if p.get("plugin"):
            o["plugin"] = {"obfs": "obfs-local"}.get(p["plugin"], p["plugin"])
            o["plugin_opts"] = ";".join(f"{k}={v}" for k, v in (p.get("plugin-opts") or {}).items())
        tls = None
    elif t == "hysteria2":
        o = {"type": "hysteria2", **base, "password": p.get("password", "")}
        if p.get("obfs"):
            o["obfs"] = {"type": p["obfs"], "password": p.get("obfs-password", "")}
    elif t == "hysteria":
        o = {"type": "hysteria", **base, "auth_str": p.get("auth-str", p.get("auth_str", "")),
             "up_mbps": int(re.sub(r"\D", "", str(p.get("up", 50))) or 50), "down_mbps": int(re.sub(r"\D", "", str(p.get("down", 100))) or 100)}
    elif t == "tuic":
        o = {"type": "tuic", **base, "uuid": p["uuid"], "password": p.get("password", ""),
             "congestion_control": p.get("congestion-controller", "bbr"), "udp_relay_mode": p.get("udp-relay-mode", "native")}
    elif t == "anytls":
        o = {"type": "anytls", **base, "password": p["password"]}
    elif t in ("socks5", "http"):
        o = {"type": "socks" if t == "socks5" else "http", **base}
        if p.get("username"):
            o["username"], o["password"] = p["username"], p.get("password", "")
        tls = {"enabled": True, "server_name": server} if (t == "http" and p.get("tls")) else None
    else:
        raise Unsupported(f"clash type '{t}' unsupported")
    if tls:
        o["tls"] = tls
    if tr:
        o["transport"] = tr
    return _exit(name or f"{server}:{port}", o["type"], o, {"hysteria2": "udp", "hysteria": "udp", "tuic": "udp"}.get(o["type"], net if net != "" else "tcp"))


def parse_clash(text: str) -> tuple[list[dict], list[str]]:
    import yaml  # PyYAML (apt: python3-yaml) - only needed for Clash subscriptions
    doc = yaml.safe_load(text) or {}
    exits, skipped = [], []
    for p in doc.get("proxies", []) or []:
        try:
            exits.append(_clash_node(p))
        except (Unsupported, KeyError, ValueError, TypeError) as e:
            skipped.append(f"{p.get('name', '?')}: {e}")
    return exits, skipped


SB_PROXY_TYPES = {"vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2", "tuic", "anytls", "socks", "http",
                  "shadowtls", "ssh", "naive"}


def parse_singbox_json(text: str) -> tuple[list[dict], list[str]]:
    doc = json.loads(text)
    exits, skipped = [], []
    for o in doc.get("outbounds", []):
        if o.get("type") not in SB_PROXY_TYPES:
            continue
        o = {k: v for k, v in o.items() if k != "tag"}
        name = o.pop("_name", None) or next((x.get("tag") for x in doc["outbounds"] if x is not None and {k: v for k, v in x.items() if k != "tag"} == o), "") or f"{o.get('server')}:{o.get('server_port')}"
        exits.append(_exit(name, o["type"], o, "udp" if o["type"] in ("hysteria", "hysteria2", "tuic") else "tcp"))
    return exits, skipped


# ----------------------------------------------------------- subscriptions
def parse_subscription(body: str, provider: str = "manual") -> tuple[list[dict], list[str]]:
    """Auto-detect: sing-box JSON, Clash YAML, or base64/plain list of share links."""
    body = body.strip()
    skipped: list[str] = []
    if body.startswith("{"):
        exits, skipped = parse_singbox_json(body)
    elif re.search(r"^\s*proxies\s*:", body, re.M):
        exits, skipped = parse_clash(body)
    else:
        if "://" not in body.splitlines()[0] if body else True:
            try:
                body = b64decode(body)
            except (binascii.Error, ValueError):
                pass
        exits = []
        for line in body.replace("\r", "").split("\n"):
            line = line.strip()
            if "://" not in line:
                continue
            try:
                exits.append(parse_link(line))
            except Unsupported as e:
                skipped.append(f"{line[:40]}…: {e}")
            except (ValueError, KeyError, binascii.Error, TypeError) as e:
                skipped.append(f"{line[:40]}…: invalid ({e})")
    seen: set[str] = set()
    for e in exits:
        e["provider"] = provider
        base, n = e["id"], 2
        while e["id"] in seen:
            e["id"] = f"{base}-{n}"
            n += 1
        seen.add(e["id"])
    return exits, skipped


# --------------------------------------------------------------- WireGuard
def parse_wireguard(text: str, name: str, provider: str = "manual") -> dict:
    cp = configparser.ConfigParser(strict=False, delimiters=("=",), interpolation=None)
    cp.optionxform = str
    cp.read_string(text)
    if "Interface" not in cp or "Peer" not in cp:
        raise ValueError("not a WireGuard config: need [Interface] and [Peer]")
    iface, peer = cp["Interface"], cp["Peer"]
    split = lambda v: [x.strip() for x in v.split(",") if x.strip()]  # noqa: E731
    host, _, port = peer["Endpoint"].strip().rpartition(":")
    host = host.strip("[]")
    ep = {
        "type": "wireguard", "address": split(iface["Address"]), "private_key": iface["PrivateKey"].strip(),
        "mtu": int(iface.get("MTU", 1280)),
        "peers": [{"address": host, "port": int(port), "public_key": peer["PublicKey"].strip(),
                   "allowed_ips": split(peer.get("AllowedIPs", "0.0.0.0/0, ::/0")),
                   **({"pre_shared_key": peer["PresharedKey"].strip()} if "PresharedKey" in peer else {}),
                   **({"persistent_keepalive_interval": int(peer["PersistentKeepalive"])} if "PersistentKeepalive" in peer else {})}],
    }
    return {"id": slug(name), "name": name, "kind": "wireguard", "protocol": "wireguard", "provider": provider,
            "country": guess_country(name), "server": host, "server_port": int(port), "transport": "udp", "endpoint": ep}


# ----------------------------------------------------------------- OpenVPN
EXTERNAL_FILE_OPTS = ("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12", "dh", "crl-verify", "extra-certs")


def parse_ovpn(text: str, name: str, provider: str = "") -> dict:
    remotes, proto, needs_auth, external = [], "udp", False, False
    for raw in text.splitlines():
        line = raw.split("#")[0].split(";")[0].strip()
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "remote" and len(parts) >= 2:
            remotes.append((parts[1], int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 1194,
                            parts[3] if len(parts) > 3 else None))
        elif parts[0] == "proto" and len(parts) > 1:
            proto = "tcp" if parts[1].startswith("tcp") else "udp"
        elif parts[0] == "auth-user-pass" and len(parts) == 1:
            needs_auth = True
        elif parts[0] in EXTERNAL_FILE_OPTS and len(parts) > 1 and not line.startswith("<"):
            external = True
    if not remotes:
        raise ValueError("no `remote` line in .ovpn")
    host, port, rproto = remotes[0]
    if rproto:
        proto = "tcp" if rproto.startswith("tcp") else "udp"
    if not provider:
        provider = next((p for p in ("surfshark", "windscribe") if p in host.lower() or p in name.lower()), "manual")
    return {"id": slug(name), "name": name, "kind": "openvpn", "protocol": "openvpn", "provider": provider,
            "country": guess_country(name) or guess_country(host), "server": host, "server_port": port,
            "transport": proto, "remotes": [{"host": h, "port": p} for h, p, _ in remotes],
            "needs_auth": needs_auth, "external_files": external,
            "stealth": "stealth" in name.lower() or "wstunnel" in name.lower() or host in ("127.0.0.1", "localhost")}


# ---------------------------------------------------------------- country
_CC = ("AE AL AM AR AT AU AZ BA BD BE BG BR BS BY CA CH CL CN CO CR CY CZ DE DK DZ EC EE EG ES FI FR GB GE GH GR HK HR HU "
       "ID IE IL IM IN IR IS IT JP KE KR KZ LI LK LT LU LV MA MC MD ME MK MT MX MY NG NL NO NP NZ PA PE PH PK PL PT PY QA "
       "RO RS RU SA SE SG SI SK TH TN TR TW UA UK US UY UZ VE VN ZA").split()
_CCSET = set(_CC)


def guess_country(text: str) -> str:
    """Two-letter code from names like 'de-fra_udp', 'Windscribe-DE-Frankfurt', '🇩🇪 Germany'."""
    for ch in re.findall(r"[\U0001F1E6-\U0001F1FF]{2}", text):  # flag emoji
        return "".join(chr(ord(c) - 0x1F1E6 + 65) for c in ch)
    for tok in re.split(r"[^A-Za-z]+", text):
        if len(tok) == 2 and tok.upper() in _CCSET:
            return "GB" if tok.upper() == "UK" else tok.upper()
    return ""
