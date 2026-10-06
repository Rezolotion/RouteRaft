"""Runs sing-box and the company OpenVPN, talks to the clash API, handles conflicts."""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import singbox
from .config import Store

SBIN = "/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin"


def which(name: str) -> str | None:
    return shutil.which(name, path=os.environ.get("PATH", "") + ":" + SBIN)


class Supervisor:
    def __init__(self, store: Store, dry_run: bool = False):
        self.store = store
        self.dry_run = dry_run
        self.sb: subprocess.Popen | None = None
        self.ovpn: subprocess.Popen | None = None
        self.stopped_services: list[str] = []
        self.logdir = store.dir / "logs"
        self.logdir.mkdir(exist_ok=True)
        self.rule_dir = store.dir / "rules"
        self.rule_dir.mkdir(exist_ok=True)

    # ------------------------------------------------------------ helpers
    @property
    def cfg_path(self) -> Path:
        return self.store.dir / "sing-box.json"

    def write_config(self) -> Path:
        cfg = singbox.build(self.store.data, self.rule_dir)
        fd = os.open(self.cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, indent=2)
        return self.cfg_path

    def check_config(self) -> str | None:
        """Return None if sing-box accepts the config (or isn't installed), else the error."""
        exe = which("sing-box")
        if not exe:
            return None
        p = subprocess.run([exe, "check", "-c", str(self.cfg_path)], capture_output=True, text=True, cwd=self.store.dir)
        return None if p.returncode == 0 else (p.stderr or p.stdout).strip()

    def _api(self, method: str, path: str, body: dict | None = None, timeout: float = 5):
        st = self.store.data
        req = urllib.request.Request(
            f"http://127.0.0.1:{st['settings']['api_port']}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            method=method,
            headers={"Authorization": f"Bearer {st['api_secret']}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}

    # ------------------------------------------------------------- status
    def running(self) -> bool:
        return self.sb is not None and self.sb.poll() is None

    def corp_running(self) -> bool:
        return self.ovpn is not None and self.ovpn.poll() is None

    def status(self) -> dict:
        s = {"running": self.running(), "corp_running": self.corp_running(),
             "singbox_installed": bool(which("sing-box")), "openvpn_installed": bool(which("openvpn")),
             "dry_run": self.dry_run, "selected": self.store.data["global"]}
        if self.running():
            try:
                s["selected"] = self._api("GET", "/proxies/global").get("now", s["selected"])
            except (urllib.error.URLError, OSError, ValueError):
                pass
        return s

    # ------------------------------------------------------------ actions
    def connect(self) -> dict:
        if self.running():
            return {"ok": True, "note": "already running"}
        self.write_config()
        err = self.check_config()
        if err:
            return {"ok": False, "error": f"sing-box rejected the config:\n{err}"}
        if self.dry_run:
            return {"ok": True, "note": f"dry-run: config written to {self.cfg_path}"}
        exe = which("sing-box")
        if not exe:
            return {"ok": False, "error": "sing-box is not installed (see README: Install)"}
        if os.geteuid() != 0:
            return {"ok": False, "error": "need root to create the TUN device (run the daemon as a service)"}
        for svc in self.store.data["settings"]["stop_conflicting"]:
            if subprocess.run(["systemctl", "is-active", "--quiet", svc]).returncode == 0:
                subprocess.run(["systemctl", "stop", svc])
                self.stopped_services.append(svc)
        if self.store.data["corp"]["enabled"]:
            r = self.corp_up()
            if not r["ok"]:
                return r  # surface it, but do not block the main tunnel below
        log = open(self.logdir / "sing-box.log", "ab")
        self.sb = subprocess.Popen([exe, "run", "-c", str(self.cfg_path)], cwd=self.store.dir,
                                   stdout=log, stderr=log, start_new_session=True)
        for _ in range(40):  # wait for the API to answer
            time.sleep(0.25)
            if self.sb.poll() is not None:
                return {"ok": False, "error": "sing-box exited; see logs"}
            try:
                self._api("GET", "/version")
                return {"ok": True}
            except (urllib.error.URLError, OSError):
                continue
        return {"ok": False, "error": "sing-box started but its API never answered; see logs"}

    def disconnect(self) -> dict:
        self._terminate(self.sb)
        self.sb = None
        self.corp_down()
        for svc in self.stopped_services:  # give back what we took
            subprocess.run(["systemctl", "start", svc])
        self.stopped_services = []
        return {"ok": True}

    def switch_global(self, exit_id: str) -> dict:
        members = self.store.selectable() + ["auto-vless", "direct"]
        if exit_id not in members:
            return {"ok": False, "error": f"unknown exit {exit_id}"}
        self.store.data["global"] = exit_id
        self.store.save()
        if self.running():
            try:
                self._api("PUT", "/proxies/global", {"name": exit_id})
            except (urllib.error.URLError, OSError, ValueError) as e:
                return {"ok": False, "error": f"clash api: {e}"}
        return {"ok": True}

    def apply(self) -> dict:
        """Routing map / exits changed: rebuild the config and restart if running."""
        was = self.running()
        self.write_config()
        err = self.check_config()
        if err:
            return {"ok": False, "error": err}
        if was:
            self._terminate(self.sb)
            self.sb = None
            return self.connect()
        return {"ok": True}

    def delay(self, exit_id: str) -> dict:
        if not self.running():
            return {"ok": False, "error": "not connected"}
        q = urllib.parse.urlencode({"url": self.store.data["settings"]["test_url"], "timeout": 5000})
        try:
            r = self._api("GET", f"/proxies/{urllib.parse.quote(exit_id)}/delay?{q}", timeout=8)
            return {"ok": True, "ms": r.get("delay")}
        except urllib.error.HTTPError:
            return {"ok": True, "ms": None}  # timeout => unreachable
        except (urllib.error.URLError, OSError, ValueError) as e:
            return {"ok": False, "error": str(e)}

    # ----------------------------------------------------- company OpenVPN
    def corp_up(self) -> dict:
        c = self.store.data["corp"]
        if self.corp_running():
            return {"ok": True}
        exe = which("openvpn")
        if not exe or not c["ovpn_path"]:
            return {"ok": False, "error": "company OpenVPN not configured/installed"}
        if self.dry_run:
            return {"ok": True}
        cmd = [exe, "--config", c["ovpn_path"], "--dev", c["interface"], "--dev-type", "tun",
               "--route-nopull", "--pull-filter", "ignore", "redirect-gateway",
               "--pull-filter", "ignore", "dhcp-option", "--pull-filter", "ignore", "block-outside-dns"]
        if c["auth_file"]:
            cmd += ["--auth-user-pass", c["auth_file"]]
        log = open(self.logdir / "openvpn-corp.log", "ab")
        self.ovpn = subprocess.Popen(cmd, stdout=log, stderr=log, start_new_session=True)
        for _ in range(60):  # wait for the interface to exist
            time.sleep(0.5)
            if self.ovpn.poll() is not None:
                return {"ok": False, "error": "openvpn exited; see logs"}
            if Path(f"/sys/class/net/{c['interface']}").exists():
                return {"ok": True}
        return {"ok": False, "error": "company tunnel did not come up in 30s; see logs"}

    def corp_down(self) -> dict:
        self._terminate(self.ovpn)
        self.ovpn = None
        return {"ok": True}

    # -------------------------------------------------------------- rules
    def update_rules(self) -> dict:
        """Download rule sets into the cache. Goes out over whatever the OS routes now."""
        out = {}
        for tag, url in self.store.data["settings"]["rule_sets"].items():
            try:
                with urllib.request.urlopen(url, timeout=30) as r:
                    (self.rule_dir / f"{tag}.srs").write_bytes(r.read())
                out[tag] = "ok"
            except (urllib.error.URLError, OSError) as e:
                out[tag] = f"failed: {e}"
        return out

    def logs(self, name: str = "sing-box", lines: int = 200) -> str:
        p = self.logdir / ("openvpn-corp.log" if name == "corp" else "sing-box.log")
        if not p.exists():
            return ""
        return "\n".join(p.read_text(errors="replace").splitlines()[-lines:])

    @staticmethod
    def _terminate(p: subprocess.Popen | None) -> None:
        if p is None or p.poll() is not None:
            return
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(8)
        except subprocess.TimeoutExpired:
            p.kill()
