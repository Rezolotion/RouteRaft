"""Read-only integration with the providers' official command-line clients.

RouteRaft never asks for, receives, or stores an account password here. Signing in is done by the
user in their own terminal with the provider's own tool; this module only reads the resulting
status so the UI can show it. Only commands known to be read-only are ever executed.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from typing import Callable

Runner = Callable[..., subprocess.CompletedProcess]

PROVIDERS = {
    "windscribe": {
        "label": "Windscribe",
        "cli": "windscribe-cli",
        "login": "windscribe-cli login",
        "status": ["windscribe-cli", "status"],
        "pages": {"Config generator": "https://windscribe.com/features/config-generators",
                  "OpenVPN credentials": "https://windscribe.com/getconfig/openvpn"},
    },
    "surfshark": {
        "label": "Surfshark",
        "cli": "surfshark-vpn",
        "login": "surfshark-vpn login",
        "status": None,  # no verified read-only status command: report installation only
        "pages": {"Manual setup": "https://my.surfshark.com/vpn/manual-setup/main"},
    },
}


def parse_windscribe_status(text: str) -> dict:
    """Pull the three lines we care about out of `windscribe-cli status`."""
    def field(name: str) -> str:
        m = re.search(rf"^{name}:\s*(.+)$", text, re.M | re.I)
        return m.group(1).strip() if m else ""

    login = field("Login state")
    connect = field("Connect state")
    return {
        "login_state": login.split(". ")[0].rstrip(".") + ("." if login else ""),  # first sentence only
        "logged_in": bool(login) and not re.search(r"could not|not logged|logged out|error", login, re.I),
        "connect_state": connect,
        "connected": bool(re.search(r"^connected", connect, re.I)),
        "firewall": field("Firewall state"),
    }


def provider_status(name: str, runner: Runner = subprocess.run, which: Callable = shutil.which) -> dict:
    p = PROVIDERS[name]
    out = {"provider": name, "label": p["label"], "installed": bool(which(p["cli"])), "login_command": p["login"], "pages": p["pages"]}
    if not out["installed"] or not p["status"]:
        return out
    try:
        r = runner(p["status"], capture_output=True, text=True, timeout=8)
        if name == "windscribe":
            out.update(parse_windscribe_status(r.stdout))
    except (OSError, subprocess.SubprocessError):
        out["login_state"] = "status unavailable"
    return out


def all_status(runner: Runner = subprocess.run, which: Callable = shutil.which) -> dict:
    return {n: provider_status(n, runner, which) for n in PROVIDERS}
