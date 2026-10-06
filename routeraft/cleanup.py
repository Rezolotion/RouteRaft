"""Put the network back the way it was: after a crash, a kill, or a panic click.

sing-box removes its TUN device and policy rules on a clean exit, but a SIGKILL, an OOM kill
or a power-cycled daemon can leave them behind, and leftover rules can blackhole all traffic.
Everything here is idempotent, so it is safe to run when there is nothing to clean up.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Callable

SINGBOX_RULE_PRIORITIES = range(9000, 9011)  # priorities sing-box uses for auto_route policy rules
SINGBOX_ROUTE_TABLE = "2022"                 # sing-box's default auto_route table
PIDFILE = "pids.json"
STOPPED_FILE = "stopped-services.json"

Runner = Callable[..., subprocess.CompletedProcess]


def _ok(cmd: list[str], runner: Runner) -> bool:
    try:
        return runner(cmd, capture_output=True, text=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def clean_network(interfaces: list[str], runner: Runner = subprocess.run) -> list[str]:
    """Remove leftover sing-box policy rules, its route table, and the named tunnel interfaces."""
    done: list[str] = []
    for fam in ("-4", "-6"):
        for prio in SINGBOX_RULE_PRIORITIES:
            for _ in range(8):  # a priority can carry several identical rules
                if not _ok(["ip", fam, "rule", "del", "priority", str(prio)], runner):
                    break
                done.append(f"ip {fam} rule priority {prio}")
        if _ok(["ip", fam, "route", "flush", "table", SINGBOX_ROUTE_TABLE], runner):
            done.append(f"ip {fam} route table {SINGBOX_ROUTE_TABLE}")
    for name in interfaces:
        if Path(f"/sys/class/net/{name}").exists() and _ok(["ip", "link", "del", name], runner):
            done.append(f"link {name}")
    return done


# ------------------------------------------------------------ process tracking
def record_pid(state_dir: Path, key: str, pid: int) -> None:
    f = state_dir / PIDFILE
    data = json.loads(f.read_text()) if f.exists() else {}
    data[key] = pid
    f.write_text(json.dumps(data))
    os.chmod(f, 0o600)


def forget_pid(state_dir: Path, key: str) -> None:
    f = state_dir / PIDFILE
    if f.exists():
        data = json.loads(f.read_text())
        data.pop(key, None)
        f.write_text(json.dumps(data))


def _running(pid: int) -> bool:
    """True if the process exists and is not a zombie (an unreaped, already-dead child)."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return stat.rsplit(")", 1)[-1].split()[0] != "Z"


def kill_leftovers(state_dir: Path) -> list[str]:
    """Stop processes recorded by a previous run. Verifies the command line first so a recycled PID is never hit."""
    f = state_dir / PIDFILE
    killed: list[str] = []
    if not f.exists():
        return killed
    for key, pid in json.loads(f.read_text()).items():
        if not _running(pid):
            continue  # already gone
        try:
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace")
        except OSError:
            continue
        if not any(name in cmd for name in ("sing-box", "openvpn")):
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(20):
                time.sleep(0.2)
                if not _running(pid):
                    break
            else:
                os.kill(pid, signal.SIGKILL)
            killed.append(f"{key} ({pid})")
        except OSError:
            pass
    f.unlink(missing_ok=True)
    return killed


# ----------------------------------------------------- services we stopped on connect
def record_stopped(state_dir: Path, services: list[str]) -> None:
    f = state_dir / STOPPED_FILE
    f.write_text(json.dumps(sorted(set(services))))
    os.chmod(f, 0o600)


def restore_services(state_dir: Path, runner: Runner = subprocess.run) -> list[str]:
    f = state_dir / STOPPED_FILE
    if not f.exists():
        return []
    started = [s for s in json.loads(f.read_text()) if _ok(["systemctl", "start", s], runner)]
    f.unlink(missing_ok=True)
    return started


def panic(state_dir: Path, interfaces: list[str], runner: Runner = subprocess.run) -> dict:
    """The big red button: stop everything RouteRaft started, remove its network changes, restore services."""
    return {
        "killed": kill_leftovers(state_dir),
        "cleaned": clean_network(interfaces, runner),
        "restored_services": restore_services(state_dir, runner),
    }
