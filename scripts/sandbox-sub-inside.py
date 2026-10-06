"""Runs INSIDE the sandbox container (see sandbox-sub.sh): import a real subscription and test its nodes.

Every node is tested the way a user would use it: it becomes the global exit of the real daemon and a
request is made through the real sing-box TUN. The exit country comes from Cloudflare's trace endpoint.
Nothing sensitive is printed: IPs are masked, and hosts / UUIDs / passwords are never read into the report.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.dont_write_bytecode = True
STATE = Path("/tmp/state")
UI = "http://127.0.0.1:8787"
LIMIT = int(os.environ.get("NODE_LIMIT", "12"))
TRACE = "https://1.1.1.1/cdn-cgi/trace"
TOKEN = ""


def mask(text: str) -> str:
    return re.sub(r"\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b", r"\1.x.x", text)


def api(method: str, path: str, body: dict | None = None, timeout: float = 60):
    req = urllib.request.Request(UI + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-RouteRaft-Token": TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}")


def trace(timeout: int = 12) -> dict:
    """Fetch Cloudflare's trace through whatever the sandbox's routing currently does."""
    p = subprocess.run(["curl", "-sS", "-k", "-m", str(timeout), TRACE], capture_output=True, text=True)
    if p.returncode != 0:
        return {}
    return dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)


def log_summary(limit: int = 12) -> list[str]:
    """Aggregate sing-box log lines with hosts, IPs and ids removed, so failures can be read without leaking anything."""
    from collections import Counter
    counts: Counter[str] = Counter()
    for line in Path(STATE / "logs/sing-box.log").read_text(errors="replace").splitlines():
        line = re.sub(r"^\S+ \d{4}-\d\d-\d\d \d\d:\d\d:\d\d ", "", line)
        line = re.sub(r"\[\d+ \d+ms\]|\[\d+\]", "[id]", line)
        line = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}(:\d+)?\b", "<ip>", line)
        line = re.sub(r"\b[\w-]+(\.[\w-]+)+(:\d+)?\b", "<host>", line)
        line = re.sub(r"outbound/vless\[[^\]]*\]", "outbound/vless[node]", line)
        counts[line[:170]] += 1
    return [f"{n:>4} x {msg}" for msg, n in counts.most_common(limit)]


def rules_clean() -> bool:
    rules = subprocess.run(["ip", "rule"], capture_output=True, text=True).stdout
    tun = subprocess.run(["ip", "link", "show", "rr0"], capture_output=True, text=True).returncode == 0
    return not tun and not re.search(r"^9\d{3}:", rules, re.M)


def main() -> int:
    global TOKEN
    raw = Path("/sub/sub.txt").read_text().strip()
    is_url = len(raw.splitlines()) == 1 and raw.startswith(("http://", "https://"))

    # ---- state for an unattended run: no rollback prompt, nothing to stop, short health interval
    sys.path.insert(0, "/work")
    from routeraft.config import Store  # noqa: E402
    st = Store(STATE)
    st.data["settings"].update(stop_conflicting=[], rollback_seconds=0, health_interval=5, tun_exclude=[],
                               log_level=os.environ.get("SB_LOG", "info"))
    st.save()

    daemon = subprocess.Popen([sys.executable, "-m", "routeraft", "--state-dir", str(STATE), "serve"],
                              cwd="/work", stdout=open("/tmp/daemon.log", "w"), stderr=subprocess.STDOUT)
    try:
        for _ in range(30):
            try:
                html = urllib.request.urlopen(UI + "/", timeout=2).read().decode()
                TOKEN = re.search(r'const TOKEN = "([^"]+)"', html).group(1)
                break
            except (OSError, AttributeError):
                time.sleep(0.5)
        else:
            print("daemon did not start"); return 2

        print(f"== sandbox: {subprocess.run(['sing-box', 'version'], capture_output=True, text=True).stdout.splitlines()[0]}")
        direct = trace()
        print(f"\n[0] direct baseline (before the tunnel): country={direct.get('loc', '?')} ip={mask(direct.get('ip', '?'))}")
        if not direct:
            print("    the sandbox has no internet right now; try again in a minute"); return 2

        print("\n[1] import")
        res = api("POST", "/api/import/subscription", {"name": "Sub", "url": raw} if is_url else {"name": "Sub", "text": raw})
        if not res.get("ok"):
            print("    import failed:", mask(str(res.get("error", res))[:300])); return 1
        print(f"    imported {res['added']} nodes, skipped {res.get('skipped_count', 0)}")
        for reason in res.get("skipped", [])[:8]:
            print(f"      skipped: {reason}")
        exits = [e for e in api("GET", "/api/state")["state"]["exits"].values()]
        by_proto: dict[str, int] = {}
        for e in exits:
            key = f"{e['protocol']}/{e['transport']}"
            by_proto[key] = by_proto.get(key, 0) + 1
        print("    protocols in this subscription: " + ", ".join(f"{k} x{v}" for k, v in sorted(by_proto.items())))

        print("\n[2] connect")
        # Pick distinct protocol/transport combinations first so every kind gets exercised within the limit.
        picked, seen = [], set()
        for e in exits:
            k = (e["protocol"], e["transport"])
            if k not in seen:
                seen.add(k); picked.append(e)
        picked += [e for e in exits if e not in picked]
        picked = picked[:LIMIT]
        api("POST", "/api/global", {"exit": picked[0]["id"]})
        r = api("POST", "/api/connect")
        print("    connect:", "ok" if r.get("ok") else f"FAILED: {mask(str(r.get('error'))[:300])}")
        if not r.get("ok"):
            for line in Path(STATE / "logs/sing-box.log").read_text().splitlines()[-12:]:
                print("      log:", mask(line[:200]))
            return 1

        print(f"\n[3] per-node test through the tunnel ({len(picked)} of {len(exits)} nodes)")
        print(f"    {'#':>2}  {'node':<30} {'protocol':<20} {'result':<8} {'exit':<5} {'latency':>8}")
        working = []
        for i, e in enumerate(picked, 1):
            switched = api("POST", "/api/global", {"exit": e["id"]}).get("ok") is True
            time.sleep(0.8)
            t = trace() if switched else {}
            d = api("GET", f"/api/delay/{e['id']}", timeout=20) if switched else {}
            ok = switched and bool(t)
            if ok:
                working.append((e, t))
            ms = d.get("ms")
            print(f"    {i:>2}  {e['name'][:30]:<30} {e['protocol'] + '/' + e['transport']:<20} {'OK' if ok else 'no':<8} "
                  f"{t.get('loc', '-'):<5} {(str(ms) + ' ms') if ms else '-':>8}")

        if not working:
            print("\nNo node carried traffic. sing-box log, aggregated (hosts and ids removed):")
            for line in log_summary():
                print("   ", line)
            return 1

        # The lane proof needs a node whose exit address differs from the direct one, otherwise bypass vs tunnel
        # cannot be told apart (the host may already be behind a proxy such as v2rayA's transparent mode).
        distinct = [(e, t) for e, t in working if t.get("ip") != direct.get("ip")]
        checks: list[tuple[str, bool]] = []
        if not distinct:
            print("\n[4] routing proof skipped: every working node exits at the same address as the direct connection")
        else:
            node, t = distinct[0]
            print(f"\n[4] routing proof with '{node['name'][:30]}': exit={t.get('loc')} vs direct={direct.get('loc')}")
            api("POST", "/api/global", {"exit": node["id"]})
            api("POST", "/api/routes", {"routes": [{"id": "probe", "name": "Probe", "enabled": True, "exit": "global", "domain_suffix": [],
                                                     "domain": [], "ip_cidr": ["1.1.1.1/32"], "rule_set": [], "process_name": []}]})
            for _ in range(20):
                if api("GET", "/api/state")["status"]["running"]:
                    break
                time.sleep(0.5)
            via = trace(); checks.append(("rule routes the probe destination through the node", bool(via) and via.get("ip") != direct.get("ip")))
            api("POST", "/api/lane", {"lane": "probe", "paused": True}); time.sleep(0.8)
            byp = trace(); checks.append(("pausing the rule bypasses the tunnel (live, back to the direct address)", bool(byp) and byp.get("ip") == direct.get("ip")))
            api("POST", "/api/lane", {"lane": "probe", "paused": False}); time.sleep(0.8)
            res_ = trace(); checks.append(("resuming sends it through the node again", bool(res_) and res_.get("ip") != direct.get("ip")))
            for name, ok in checks:
                print(f"    {'PASS' if ok else 'FAIL'}  {name}")

        print("\n[5] clean shutdown")
        api("POST", "/api/disconnect")
        time.sleep(1)
        clean = rules_clean()
        back = bool(trace())
        print(f"    {'PASS' if clean else 'FAIL'}  tunnel and rules removed")
        print(f"    {'PASS' if back else 'FAIL'}  direct internet works again")

        total_ok = len(working)
        print(f"\n== {total_ok}/{len(picked)} tested nodes carried traffic; lane/bypass checks "
              f"{'skipped' if not checks else 'all passed' if all(ok for _, ok in checks) else 'FAILED'}")
        return 0 if (total_ok and all(ok for _, ok in checks) and clean and back) else 1
    finally:
        daemon.terminate()
        try:
            daemon.wait(5)
        except subprocess.TimeoutExpired:
            daemon.kill()
        subprocess.run([sys.executable, "-m", "routeraft", "--state-dir", str(STATE), "panic"], cwd="/work", capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
