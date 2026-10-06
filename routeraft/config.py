"""Persistent state: the *routing map* plus the exits it points to.

The map never mentions a provider by name. Routes point at one of:
  "global"  - whatever exit is currently selected for the global slot
  "direct"  - the physical uplink (Iran IP)
  "corp"    - the company OpenVPN tunnel
  <exit id> - pin a route to one specific sing-box/WireGuard exit
So swapping Surfshark <-> Windscribe <-> any V2Ray node is one field (`global`), not a rewrite.
"""
from __future__ import annotations

import json
import os
import secrets
import tempfile
import threading
from pathlib import Path

GLOBAL_KINDS = ("singbox", "wireguard", "openvpn", "ikev2")  # may sit in the global slot
RESERVED = {"global", "direct", "corp", "ovpn", "ikev2"}
SECRET_KEYS = ("outbound", "endpoint", "ovpn_path", "ike")  # payloads that never reach the UI

DEFAULT_STATE = {
    "version": 2,
    "global": "",  # id of the exit used by the global slot ("" => direct)
    "favorites": [],  # WireGuard exits kept loaded in sing-box so switching is instant
    "exits": {},
    "providers": {  # service credentials for OpenVPN/IKEv2 profiles
        "surfshark": {"username": "", "password": ""},
        "windscribe": {"username": "", "password": ""},
        "manual": {"username": "", "password": ""},
    },
    "subscriptions": {},  # id -> {name, url}
    "corp": {
        "enabled": False,
        "ovpn_path": "",
        "auth_file": "",
        "interface": "tun-corp",
        "server": "",
        "server_port": 1194,
        "dns": "",
    },
    "routes": [
        {"id": "iran", "name": "Domestic (Iranian) sites", "enabled": True, "exit": "direct",
         "domain_suffix": [".ir"], "domain": [], "ip_cidr": [], "rule_set": ["geosite-ir", "geoip-ir"], "process_name": []},
        {"id": "corp", "name": "Corporate tools", "enabled": True, "exit": "corp",
         "domain_suffix": [], "domain": [], "ip_cidr": [], "rule_set": [], "process_name": []},
    ],
    "settings": {
        "tun_name": "rr0",
        "tun_address": "172.19.0.1/30",
        "tun_exclude": ["172.17.0.0/16", "172.18.0.0/16", "172.28.0.0/16", "192.168.122.0/24"],
        "local_dns": "local",
        "remote_dns": "1.1.1.1",
        "ipv6": False,
        "api_port": 9090,
        "ui_port": 8787,
        "test_url": "https://www.gstatic.com/generate_204",
        "vpn_iface": "rr-vpn0",  # interface the active OpenVPN global exit uses
        "stop_conflicting": ["v2raya"],
        "rollback_seconds": 90,  # auto-disconnect unless a new config is confirmed in time
        "rule_sets": {
            "geosite-ir": "https://github.com/Chocolate4U/Iran-sing-box-rules/releases/latest/download/geosite-ir.srs",
            "geoip-ir": "https://github.com/Chocolate4U/Iran-sing-box-rules/releases/latest/download/geoip-ir.srs",
        },
    },
    "confirmed_config": "",  # hash of the last config the user confirmed working
}


class Store:
    """JSON state file (mode 0600, atomic writes). Holds secrets - never expose raw."""

    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.profiles = self.dir / "profiles"
        self.profiles.mkdir(exist_ok=True)
        os.chmod(self.profiles, 0o700)
        self.path = self.dir / "state.json"
        self.lock = threading.RLock()
        self.data = self._load()

    def _load(self) -> dict:
        data = json.loads(self.path.read_text()) if self.path.exists() else {}
        merged = json.loads(json.dumps(DEFAULT_STATE))
        for k, v in data.items():
            if isinstance(v, dict) and isinstance(merged.get(k), dict) and k not in ("exits", "subscriptions"):
                merged[k].update(v)
            else:
                merged[k] = v
        merged.setdefault("api_secret", secrets.token_hex(16))   # sing-box clash API
        merged.setdefault("ui_token", secrets.token_urlsafe(24))  # web UI CSRF token
        return merged

    def save(self) -> None:
        with self.lock:
            fd, tmp = tempfile.mkstemp(dir=self.dir)
            with os.fdopen(fd, "w") as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)

    # ---- exits
    def add_exits(self, exits: list[dict], save: bool = True) -> list[str]:
        ids = []
        with self.lock:
            for e in exits:
                while e["id"] in RESERVED or (e["id"] in self.data["exits"] and not e.get("_replace")):
                    e["id"] += "-x"
                e.pop("_replace", None)
                self.data["exits"][e["id"]] = e
                ids.append(e["id"])
            if not self.data["global"] and exits:
                self.data["global"] = exits[0]["id"]
            if save:
                self.save()
        return ids

    def remove_exit(self, exit_id: str) -> None:
        with self.lock:
            e = self.data["exits"].pop(exit_id, None)
            if e and e.get("kind") == "openvpn" and e.get("ovpn_path", "").startswith(str(self.profiles)):
                Path(e["ovpn_path"]).unlink(missing_ok=True)
            if exit_id in self.data["favorites"]:
                self.data["favorites"].remove(exit_id)
            if self.data["global"] == exit_id:
                self.data["global"] = ""
            for r in self.data["routes"]:
                if r["exit"] == exit_id:
                    r["exit"] = "global"
            self.save()

    def remove_provider_exits(self, provider: str) -> int:
        ids = [i for i, e in self.data["exits"].items() if e.get("provider") == provider]
        for i in ids:
            self.remove_exit(i)
        return len(ids)

    # ---- sanitised view for the UI (no private keys / uuids / passwords / paths)
    def public(self) -> dict:
        d = json.loads(json.dumps(self.data))
        for k in ("api_secret", "ui_token"):
            d.pop(k, None)
        for e in d["exits"].values():
            for k in SECRET_KEYS:
                e.pop(k, None)
        for p in d["providers"].values():
            p["has_credentials"] = bool(p.get("username") and p.get("password"))
            p.pop("password", None)
        d["corp"].pop("auth_file", None)
        return d
