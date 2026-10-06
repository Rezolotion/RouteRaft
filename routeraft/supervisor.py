"""Runs sing-box and the OpenVPN processes, talks to the clash API, imports exits,
and arms the auto-rollback that protects you from a config that kills connectivity."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from . import cleanup, parsers, singbox
from .config import Store

SBIN = "/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin"
NET_ERRORS = (urllib.error.URLError, OSError, ValueError)


def which(name: str) -> str | None:
    return shutil.which(name, path=os.environ.get("PATH", "") + ":" + SBIN)


class Supervisor:
    def __init__(self, store: Store, dry_run: bool = False):
        self.store, self.dry_run = store, dry_run
        self.sb: subprocess.Popen | None = None
        self.vpn: subprocess.Popen | None = None      # active OpenVPN *global* exit
        self.vpn_exit: str = ""
        self.corp: subprocess.Popen | None = None     # company OpenVPN
        self.stopped_services: list[str] = []
        self.lock = threading.RLock()
        self.rollback_timer: threading.Timer | None = None
        self.rollback_deadline = 0.0
        self.watch_stop = threading.Event()
        self.health: dict = {"ok": None, "failures": 0, "ms": None, "failover": False}
        self.event = ""  # last notable thing that happened without the user asking (crash, failover)
        self.logdir = store.dir / "logs"
        self.logdir.mkdir(exist_ok=True)
        self.rule_dir = store.dir / "rules"
        self.rule_dir.mkdir(exist_ok=True)

    # ------------------------------------------------------------ config
    @property
    def cfg_path(self) -> Path:
        return self.store.dir / "sing-box.json"

    def build(self) -> dict:
        return singbox.build(self.store.data, self.rule_dir)

    def config_hash(self, cfg: dict) -> str:
        c = json.loads(json.dumps(cfg))
        c["experimental"]["clash_api"].pop("secret", None)
        for o in c["outbounds"]:
            o.pop("default", None)  # picking another exit must not look like a new config
        return hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()

    def write_config(self) -> tuple[Path, str]:
        cfg = self.build()
        fd = os.open(self.cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, indent=2)
        return self.cfg_path, self.config_hash(cfg)

    def check_config(self) -> str | None:
        exe = which("sing-box")
        if not exe:
            return None
        p = subprocess.run([exe, "check", "-c", str(self.cfg_path)], capture_output=True, text=True, cwd=self.store.dir)
        return None if p.returncode == 0 else (p.stderr or p.stdout).strip()

    def _api(self, method: str, path: str, body: dict | None = None, timeout: float = 5):
        d = self.store.data
        req = urllib.request.Request(
            f"http://127.0.0.1:{d['settings']['api_port']}{path}",
            data=json.dumps(body).encode() if body is not None else None, method=method,
            headers={"Authorization": f"Bearer {d['api_secret']}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}

    # ------------------------------------------------------------ status
    def running(self) -> bool:
        return self.sb is not None and self.sb.poll() is None

    @staticmethod
    def _alive(p: subprocess.Popen | None) -> bool:
        return p is not None and p.poll() is None

    def status(self) -> dict:
        d = self.store.data
        s = {"running": self.running(), "corp_running": self._alive(self.corp), "vpn_running": self._alive(self.vpn),
             "singbox_installed": bool(which("sing-box")), "openvpn_installed": bool(which("openvpn")),
             "dry_run": self.dry_run, "selected": d["global"],
             "rollback_in": max(0, int(self.rollback_deadline - time.time())) if self.rollback_timer else 0,
             "health": self.health, "event": self.event}
        return s

    # ---------------------------------------------------------- rollback
    def _arm(self, cfg_hash: str) -> None:
        secs = int(self.store.data["settings"]["rollback_seconds"])
        if secs <= 0 or cfg_hash == self.store.data["confirmed_config"]:
            return
        self._disarm()
        self.rollback_deadline = time.time() + secs
        self.rollback_timer = threading.Timer(secs, self._rollback)
        self.rollback_timer.daemon = True
        self.rollback_timer.start()
        self._pending_hash = cfg_hash

    def _disarm(self) -> None:
        if self.rollback_timer:
            self.rollback_timer.cancel()
        self.rollback_timer = None

    def _rollback(self) -> None:
        with self.lock:
            self.rollback_timer = None
            (self.logdir / "routeraft.log").open("a").write(f"{time.ctime()} rollback: not confirmed, disconnecting\n")
            self.disconnect()

    def confirm(self) -> dict:
        with self.lock:
            if self.rollback_timer:
                self._disarm()
                self.store.data["confirmed_config"] = getattr(self, "_pending_hash", "")
                self.store.save()
        return {"ok": True}

    # ----------------------------------------------------------- actions
    def connect(self) -> dict:
        with self.lock:
            if self.running():
                return {"ok": True, "note": "already running"}
            _, h = self.write_config()
            err = self.check_config()
            if err:
                return {"ok": False, "error": f"sing-box rejected the config:\n{err}"}
            if self.dry_run:
                return {"ok": True, "note": f"dry-run: config written to {self.cfg_path}"}
            exe = which("sing-box")
            if not exe:
                return {"ok": False, "error": "sing-box is not installed (packaging/install-singbox.sh)"}
            if os.geteuid() != 0:
                return {"ok": False, "error": "need root to create the TUN device (run the daemon as a service)"}
            for svc in self.store.data["settings"]["stop_conflicting"]:
                if subprocess.run(["systemctl", "is-active", "--quiet", svc]).returncode == 0:
                    subprocess.run(["systemctl", "stop", svc])
                    self.stopped_services.append(svc)
            cleanup.record_stopped(self.store.dir, self.stopped_services)
            warn = ""
            if self.store.data["corp"]["enabled"]:
                r = self.corp_up()
                warn = "" if r["ok"] else f"company VPN: {r['error']}"
            g = self.store.data["exits"].get(self.store.data["global"])
            if g and g["kind"] == "openvpn":
                r = self._vpn_up(g)
                if not r["ok"]:
                    self._restore_services()
                    return r
            log = open(self.logdir / "sing-box.log", "ab")
            self.sb = subprocess.Popen([exe, "run", "-c", str(self.cfg_path)], cwd=self.store.dir,
                                       stdout=log, stderr=log, start_new_session=True)
            cleanup.record_pid(self.store.dir, "sing-box", self.sb.pid)
            for _ in range(60):  # wait for the API
                time.sleep(0.25)
                if self.sb.poll() is not None:
                    self._restore_services()
                    return {"ok": False, "error": "sing-box exited; see logs"}
                try:
                    self._api("GET", "/version")
                    self._select(singbox.member_for(self.store.data, self.store.data["global"]))
                    self._arm(h)
                    self._start_watchdog()
                    return {"ok": True, "note": warn, "rollback": bool(self.rollback_timer)}
                except NET_ERRORS:
                    continue
            self.disconnect()
            return {"ok": False, "error": "sing-box started but its API never answered; see logs"}

    def _restore_services(self) -> None:
        if not self.dry_run:  # give back what we took
            cleanup.restore_services(self.store.dir)
        self.stopped_services = []

    def _ifaces(self) -> list[str]:
        st, corp = self.store.data["settings"], self.store.data["corp"]
        return [st["tun_name"], st["vpn_iface"], corp["interface"], singbox.IKE_IFACE]

    def _can_touch_network(self) -> bool:
        return not self.dry_run and os.geteuid() == 0

    def disconnect(self) -> dict:
        with self.lock:
            self._disarm()
            self.watch_stop.set()
            self._terminate(self.sb)
            self.sb = None
            self._vpn_down()
            self.corp_down()
            if self._can_touch_network():
                cleanup.clean_network(self._ifaces())  # idempotent: a no-op after a clean exit
            for key in ("sing-box", "openvpn-global", "openvpn-corp"):
                cleanup.forget_pid(self.store.dir, key)
            self._restore_services()
            self.health = {"ok": None, "failures": 0, "ms": None, "failover": False}
        return {"ok": True}

    def panic(self) -> dict:
        """Restore normal internet no matter what state we are in, including after a crash."""
        with self.lock:
            self.disconnect()
            self.event = ""
            extra = cleanup.panic(self.store.dir, self._ifaces()) if self._can_touch_network() else {}
        return {"ok": True, **extra}

    def startup_cleanup(self) -> None:
        """Called once when the daemon starts: remove anything a previous run left behind."""
        if self._can_touch_network():
            cleanup.panic(self.store.dir, self._ifaces())

    def _select(self, member: str) -> None:
        self._api("PUT", "/proxies/global", {"name": member})

    def switch_global(self, exit_id: str) -> dict:
        with self.lock:
            d = self.store.data
            exit_ = d["exits"].get(exit_id)
            if exit_id != "direct" and not exit_id.startswith("auto:") and not exit_:
                return {"ok": False, "error": f"unknown exit {exit_id}"}
            d["global"] = "" if exit_id == "direct" else exit_id
            self.store.save()
            if not self.running():
                return {"ok": True}
            if exit_ and exit_["kind"] == "wireguard" and not self._wg_loaded_in_running(exit_id):
                return self.apply()  # endpoint is not part of the running config: restart with it loaded
            if exit_ and exit_["kind"] == "openvpn":
                r = self._vpn_up(exit_)
                if not r["ok"]:
                    return r
                self._ensure_bypass(exit_)
            try:
                self._select(singbox.member_for(d, exit_id))
            except NET_ERRORS as e:
                return {"ok": False, "error": f"clash api: {e}"}
            if not exit_ or exit_["kind"] != "openvpn":
                self._vpn_down()
            return {"ok": True}

    def set_lane(self, lane: str, paused: bool) -> dict:
        """Flip one lane between its target and a plain bypass, live, without touching anything else."""
        with self.lock:
            d = self.store.data
            if lane == "global":
                d["global_paused"] = bool(paused)
                tag = "global"
                member = "direct" if paused or not d["global"] else singbox.member_for(d, d["global"])
            else:
                r = next((x for x in d["routes"] if x["id"] == lane), None)
                if r is None:
                    return {"ok": False, "error": f"unknown lane {lane}"}
                r["paused"] = bool(paused)
                tag = singbox.rule_tag(lane)
                member = "direct" if paused else self._selector_target(tag)
            self.store.save()
            if not self.running() or not member:
                return {"ok": True}
            try:
                self._api("PUT", f"/proxies/{urllib.parse.quote(tag, safe='')}", {"name": member})
            except NET_ERRORS as e:
                return {"ok": False, "error": f"clash api: {e}"}
            return {"ok": True}

    def _selector_target(self, tag: str) -> str:
        """First member of a rule selector in the running config = the rule's real target."""
        try:
            cfg = json.loads(self.cfg_path.read_text())
        except (OSError, ValueError):
            return ""
        return next((o["outbounds"][0] for o in cfg["outbounds"] if o["tag"] == tag), "")

    def _start_watchdog(self) -> None:
        self.watch_stop.set()  # retire the previous watchdog (apply() restarts sing-box without a disconnect)
        self.watch_stop = stop = threading.Event()
        threading.Thread(target=self._watch, args=(stop,), daemon=True, name="routeraft-watchdog").start()

    def _watch(self, stop: threading.Event) -> None:
        """Detect a dead sing-box (clean up) or a dead global exit (warn, or bypass if configured)."""
        while not stop.wait(self.store.data["settings"]["health_interval"]):
            if self.sb is not None and self.sb.poll() is not None:
                self.event = "sing-box stopped unexpectedly. Normal networking has been restored."
                self.disconnect()
                return
            d = self.store.data
            if not self.running() or d["global_paused"] or not d["global"]:
                self.health.update(ok=None, failures=0, ms=None)
                continue
            r = self.delay("global")  # a selector's delay is the delay of whatever it currently selects
            if r.get("ok") and r.get("ms"):
                self.health.update(ok=True, failures=0, ms=r["ms"], failover=False)
                continue
            self.health["failures"] += 1
            self.health.update(ok=False, ms=None)
            if self.health["failures"] >= 3 and d["settings"]["failover"] == "bypass" and not self.health["failover"]:
                self.set_lane("global", True)
                self.health["failover"] = True
                self.event = "The global exit stopped responding. Traffic is bypassing the tunnel until you resume it."

    def _wg_loaded_in_running(self, exit_id: str) -> bool:
        try:
            return exit_id in {e["tag"] for e in json.loads(self.cfg_path.read_text()).get("endpoints", [])}
        except (OSError, ValueError):
            return False

    def _ensure_bypass(self, exit_: dict) -> None:
        """The bypass rule for an OpenVPN server's address lives in the config; if it is missing, restart."""
        try:
            cfg = json.loads(self.cfg_path.read_text())
        except (OSError, ValueError):
            return
        need = {r["host"] for r in exit_.get("remotes", [])} | {exit_["server"]}
        have = {x for r in cfg["route"]["rules"] for x in (r.get("ip_cidr") or []) + (r.get("domain") or [])}
        if not need <= have:
            self.apply()

    def apply(self) -> dict:
        """Routing map / exits changed: rebuild the config and restart sing-box if it is running."""
        with self.lock:
            was = self.running()
            self.write_config()
            err = self.check_config()
            if err:
                return {"ok": False, "error": err}
            if was:  # restart in place; stopped_services stay stopped across the restart
                self._terminate(self.sb)
                self.sb = None
                return self.connect()
            return {"ok": True}

    def delay(self, member: str) -> dict:
        if not self.running():
            return {"ok": False, "error": "not connected"}
        q = urllib.parse.urlencode({"url": self.store.data["settings"]["test_url"], "timeout": 5000})
        try:
            r = self._api("GET", f"/proxies/{urllib.parse.quote(member, safe='')}/delay?{q}", timeout=8)
            return {"ok": True, "ms": r.get("delay")}
        except urllib.error.HTTPError:
            return {"ok": True, "ms": None}
        except NET_ERRORS as e:
            return {"ok": False, "error": str(e)}

    # ------------------------------------------------------------ OpenVPN
    def _ovpn_cmd(self, exit_: dict, iface: str, auth: str | None) -> list[str]:
        exe = which("openvpn")
        cmd = [exe, "--config", exit_["ovpn_path"], "--dev", iface, "--dev-type", "tun",
               "--route-nopull", "--pull-filter", "ignore", "redirect-gateway",
               "--pull-filter", "ignore", "dhcp-option", "--pull-filter", "ignore", "block-outside-dns",
               "--connect-retry", "2", "--connect-retry-max", "3", "--script-security", "1"]
        if exit_.get("ovpn_dir"):
            cmd += ["--cd", exit_["ovpn_dir"]]
        if auth:
            cmd += ["--auth-user-pass", auth]
        return cmd

    def _provider_auth(self, provider: str) -> str | None:
        c = self.store.data["providers"].get(provider) or self.store.data["providers"]["manual"]
        if not (c.get("username") and c.get("password")):
            return None
        p = self.store.profiles / f"auth-{provider}.txt"
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"{c['username']}\n{c['password']}\n")
        return str(p)

    def _wait_iface(self, proc: subprocess.Popen, iface: str, secs: int = 30) -> dict:
        for _ in range(secs * 2):
            time.sleep(0.5)
            if proc.poll() is not None:
                return {"ok": False, "error": "openvpn exited; see logs"}
            if Path(f"/sys/class/net/{iface}").exists():
                return {"ok": True}
        return {"ok": False, "error": f"tunnel {iface} did not come up in {secs}s; see logs"}

    def _vpn_up(self, exit_: dict) -> dict:
        if self._alive(self.vpn) and self.vpn_exit == exit_["id"]:
            return {"ok": True}
        self._vpn_down()
        if self.dry_run:
            return {"ok": True}
        if not which("openvpn"):
            return {"ok": False, "error": "openvpn is not installed"}
        auth = self._provider_auth(exit_["provider"]) if exit_.get("needs_auth") else None
        if exit_.get("needs_auth") and not auth:
            return {"ok": False, "error": f"no credentials saved for provider '{exit_['provider']}'"}
        iface = self.store.data["settings"]["vpn_iface"]
        log = open(self.logdir / "openvpn-global.log", "ab")
        self.vpn = subprocess.Popen(self._ovpn_cmd(exit_, iface, auth), stdout=log, stderr=log, start_new_session=True)
        cleanup.record_pid(self.store.dir, "openvpn-global", self.vpn.pid)
        self.vpn_exit = exit_["id"]
        r = self._wait_iface(self.vpn, iface)
        if not r["ok"]:
            self._vpn_down()
        return r

    def _vpn_down(self) -> None:
        self._terminate(self.vpn)
        self.vpn, self.vpn_exit = None, ""
        cleanup.forget_pid(self.store.dir, "openvpn-global")

    def corp_up(self) -> dict:
        c = self.store.data["corp"]
        if self._alive(self.corp):
            return {"ok": True}
        if not which("openvpn") or not c["ovpn_path"]:
            return {"ok": False, "error": "company OpenVPN not configured/installed"}
        if self.dry_run:
            return {"ok": True}
        auth = c["auth_file"] or None
        log = open(self.logdir / "openvpn-corp.log", "ab")
        self.corp = subprocess.Popen(self._ovpn_cmd({"ovpn_path": c["ovpn_path"]}, c["interface"], auth),
                                     stdout=log, stderr=log, start_new_session=True)
        cleanup.record_pid(self.store.dir, "openvpn-corp", self.corp.pid)
        r = self._wait_iface(self.corp, c["interface"])
        if not r["ok"]:
            self.corp_down()
        return r

    def corp_down(self) -> dict:
        self._terminate(self.corp)
        self.corp = None
        cleanup.forget_pid(self.store.dir, "openvpn-corp")
        return {"ok": True}

    # ------------------------------------------------------------ imports
    def import_wireguard(self, text: str, name: str, provider: str = "manual") -> list[str]:
        return self.store.add_exits([parsers.parse_wireguard(text, name, provider)])

    def import_ovpn(self, text: str, name: str, provider: str = "", src_dir: str = "") -> str:
        e = parsers.parse_ovpn(text, name, provider)
        e["ovpn_path"] = ""
        eid = self.store.add_exits([e], save=False)[0]
        dest = self.store.profiles / f"{eid}.ovpn"
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        self.store.data["exits"][eid]["ovpn_path"] = str(dest)
        if e["external_files"] and src_dir:  # config references ca/cert/key files next to it
            self.store.data["exits"][eid]["ovpn_dir"] = src_dir
        self.store.save()
        return eid

    def import_path(self, path: str, provider: str = "") -> dict:
        """Import a file, a folder (recursive) or a .zip of .ovpn / WireGuard .conf files."""
        root = Path(path).expanduser()
        if not root.exists():
            return {"ok": False, "error": f"not found: {root}"}
        items: list[tuple[str, str, str]] = []  # (name, text, src_dir)
        if root.suffix == ".zip":
            with zipfile.ZipFile(root) as z:
                for zi in z.infolist()[:5000]:
                    if zi.filename.lower().endswith((".ovpn", ".conf")) and zi.file_size < 1_000_000:
                        items.append((Path(zi.filename).stem, z.read(zi).decode("utf-8", "replace"), ""))
        else:
            files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.suffix.lower() in (".ovpn", ".conf"))
            for p in files[:5000]:
                if p.stat().st_size < 1_000_000:
                    items.append((p.stem, p.read_text(errors="replace"), str(p.parent)))
        added = {"openvpn": 0, "wireguard": 0}
        failed: list[str] = []
        wg: list[dict] = []
        for name, text, src in items:
            try:
                if "[Interface]" in text and "[Peer]" in text:
                    wg.append(parsers.parse_wireguard(text, name, provider or "manual"))
                    added["wireguard"] += 1
                else:
                    self.import_ovpn(text, name, provider, src)
                    added["openvpn"] += 1
            except (ValueError, KeyError) as e:
                failed.append(f"{name}: {e}")
        if wg:
            self.store.add_exits(wg)
        r = self.apply()
        return {"ok": True, "added": added, "failed": failed[:20], "failed_count": len(failed), **({"error": r["error"]} if not r["ok"] else {})}

    def import_subscription(self, sub_id: str, name: str, url: str = "", text: str = "") -> dict:
        d = self.store.data
        if url and not text:
            req = urllib.request.Request(url, headers={"User-Agent": "RouteRaft/0.2 sing-box"})
            with urllib.request.urlopen(req, timeout=30) as r:
                text = r.read().decode("utf-8", "replace")
        provider = f"sub:{sub_id}"
        exits, skipped = parsers.parse_subscription(text, provider)
        if not exits:
            return {"ok": False, "error": "no usable nodes found", "skipped": skipped[:20]}
        old_global = d["global"]
        d["subscriptions"][sub_id] = {"name": name, "url": url}
        self.store.remove_provider_exits(provider) if any(e.get("provider") == provider for e in d["exits"].values()) else None
        d["global"] = old_global if old_global in d["exits"] else ""
        self.store.add_exits(exits)
        r = self.apply()
        return {"ok": r["ok"], "added": len(exits), "skipped": skipped[:20], "skipped_count": len(skipped),
                **({"error": r["error"]} if not r["ok"] else {})}

    def update_rules(self) -> dict:
        out = {}
        for tag, url in self.store.data["settings"]["rule_sets"].items():
            try:
                with urllib.request.urlopen(url, timeout=30) as r:
                    (self.rule_dir / f"{tag}.srs").write_bytes(r.read())
                out[tag] = "ok"
            except NET_ERRORS as e:
                out[tag] = f"failed: {e}"
        return out

    def logs(self, name: str = "sing-box", lines: int = 200) -> str:
        p = self.logdir / {"corp": "openvpn-corp.log", "vpn": "openvpn-global.log"}.get(name, "sing-box.log")
        return "\n".join(p.read_text(errors="replace").splitlines()[-lines:]) if p.exists() else ""

    @staticmethod
    def _terminate(p: subprocess.Popen | None) -> None:
        if p is None or p.poll() is not None:
            return
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(8)
        except subprocess.TimeoutExpired:
            p.kill()
