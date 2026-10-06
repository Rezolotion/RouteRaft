"""Persistent state: the *routing map* plus the exits it points to.

The map never mentions a provider by name. Routes point at one of:
  "global"  - whatever exit is currently selected for the global slot
  "direct"  - the physical uplink (Iran IP)
  "corp"    - the company OpenVPN tunnel
  <exit id> - pin a route to one specific exit
So swapping Surfshark <-> Windscribe <-> VLESS is one field (`global`), not a rewrite.
"""
from __future__ import annotations

import json
import os
import secrets
import tempfile
import threading
from pathlib import Path

SELECTABLE_TYPES = ("wireguard", "vless")  # may sit in the global slot
RESERVED = {"global", "direct", "corp", "auto-vless"}

DEFAULT_STATE = {
    "version": 1,
    "global": "",  # id of the exit used by the global slot ("" => direct)
    "exits": {},
    "corp": {
        "enabled": False,
        "ovpn_path": "",
        "auth_file": "",  # optional user/pass file, mode 0600
        "interface": "tun-corp",
        "server": "",  # host of the OpenVPN server, kept off the tunnel
        "server_port": 1194,
        "dns": "",  # company DNS, used for corp domains
    },
    "routes": [
        {
            "id": "iran",
            "name": "Iranian sites",
            "enabled": True,
            "exit": "direct",
            "domain_suffix": [".ir"],
            "domain": [],
            "ip_cidr": [],
            "rule_set": ["geosite-ir", "geoip-ir"],
            "process_name": [],
        },
        {
            "id": "corp",
            "name": "Company tools",
            "enabled": True,
            "exit": "corp",
            "domain_suffix": [],
            "domain": [],
            "ip_cidr": [],
            "rule_set": [],
            "process_name": [],
        },
    ],
    "settings": {
        "tun_name": "rr0",
        "tun_address": "172.19.0.1/30",
        "tun_exclude": ["172.17.0.0/16", "172.18.0.0/16", "172.28.0.0/16", "192.168.122.0/24"],
        "local_dns": "local",  # "local" = system resolver, or an IP like 10.99.246.183
        "remote_dns": "1.1.1.1",
        "ipv6": False,
        "api_port": 9090,
        "ui_port": 8787,
        "test_url": "https://www.gstatic.com/generate_204",
        "stop_conflicting": ["v2raya"],  # services stopped on connect
        "rule_sets": {
            "geosite-ir": "https://github.com/Chocolate4U/Iran-sing-box-rules/releases/latest/download/geosite-ir.srs",
            "geoip-ir": "https://github.com/Chocolate4U/Iran-sing-box-rules/releases/latest/download/geoip-ir.srs",
        },
    },
}


class Store:
    """JSON state file (mode 0600, atomic writes). Holds secrets - never expose raw."""

    def __init__(self, state_dir: Path):
        self.dir = Path(state_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.path = self.dir / "state.json"
        self.lock = threading.RLock()
        self.data = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            data = json.loads(self.path.read_text())
        else:
            data = {}
        merged = json.loads(json.dumps(DEFAULT_STATE))
        for k, v in data.items():
            if isinstance(v, dict) and isinstance(merged.get(k), dict) and k != "exits":
                merged[k].update(v)
            else:
                merged[k] = v
        if "api_secret" not in merged:
            merged["api_secret"] = secrets.token_hex(16)  # sing-box clash API
        if "ui_token" not in merged:
            merged["ui_token"] = secrets.token_urlsafe(24)  # web UI CSRF token
        return merged

    def save(self) -> None:
        with self.lock:
            fd, tmp = tempfile.mkstemp(dir=self.dir)
            with os.fdopen(fd, "w") as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)

    # ---- exits
    def add_exits(self, exits: list[dict]) -> list[str]:
        ids = []
        with self.lock:
            for e in exits:
                if e["id"] in RESERVED:
                    e["id"] += "-x"
                self.data["exits"][e["id"]] = e
                ids.append(e["id"])
            if not self.data["global"]:
                for e in exits:
                    if e["type"] in SELECTABLE_TYPES:
                        self.data["global"] = e["id"]
                        break
            self.save()
        return ids

    def remove_exit(self, exit_id: str) -> None:
        with self.lock:
            self.data["exits"].pop(exit_id, None)
            if self.data["global"] == exit_id:
                self.data["global"] = ""
            for r in self.data["routes"]:
                if r["exit"] == exit_id:
                    r["exit"] = "global"
            self.save()

    def selectable(self) -> list[str]:
        return [i for i, e in self.data["exits"].items() if e["type"] in SELECTABLE_TYPES]

    # ---- sanitised view for the UI (no private keys / uuids / secrets)
    def public(self) -> dict:
        d = json.loads(json.dumps(self.data))
        d.pop("api_secret", None)
        d.pop("ui_token", None)
        for e in d["exits"].values():
            for k in ("private_key", "pre_shared_key", "uuid", "reality_public_key", "reality_short_id"):
                e.pop(k, None)
        return d
