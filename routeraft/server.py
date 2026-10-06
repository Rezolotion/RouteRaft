"""Local web UI + JSON API. Binds to 127.0.0.1 only.

The daemon runs as root, so the API is guarded against drive-by requests from web pages:
  * Host header must be 127.0.0.1/localhost (blocks DNS rebinding)
  * mutating calls need the per-install token, which only same-origin JS can read
  * Origin, when present, must be our own
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from . import parsers, providers, singbox
from .config import Store
from .supervisor import Supervisor


def make_handler(store: Store, sup: Supervisor):
    port = store.data["settings"]["ui_port"]
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}

    class H(BaseHTTPRequestHandler):
        server_version = "RouteRaft"

        def log_message(self, *a):  # quiet
            pass

        # ---- plumbing
        def _send(self, code: int, body, ctype="application/json"):
            raw = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(raw)

        def _guard(self, mutating: bool) -> bool:
            if self.headers.get("Host", "") not in allowed_hosts:
                self._send(403, {"error": "bad host"})
                return False
            origin = self.headers.get("Origin")
            if origin and origin not in allowed_origins:
                self._send(403, {"error": "bad origin"})
                return False
            if mutating and self.headers.get("X-RouteRaft-Token") != store.data["ui_token"]:
                self._send(403, {"error": "bad token"})
                return False
            return True

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 5_000_000:
                raise ValueError("body too large")
            return json.loads(self.rfile.read(n) or b"{}")

        # ---- routes
        def do_GET(self):
            if not self._guard(False):
                return
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                html = resources.files("routeraft").joinpath("web/index.html").read_text()
                html = html.replace("__TOKEN__", store.data["ui_token"])
                return self._send(200, html.encode(), "text/html")
            if path == "/api/state":
                return self._send(200, {"state": store.public(), "status": sup.status()})
            m = re.fullmatch(r"/api/delay/(.+)", path)
            if m:
                member = singbox.member_for(store.data, urllib.parse.unquote(m.group(1)))
                return self._send(200, sup.delay(member))
            if path == "/api/providers/status":
                return self._send(200, providers.all_status())
            if path == "/api/logs":
                return self._send(200, {k: sup.logs(k) for k in ("sing-box", "vpn", "corp")})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._guard(True):
                return
            try:
                b = self._body()
                self._send(200, self._post(self.path.split("?")[0], b))
            except (ValueError, KeyError, json.JSONDecodeError, urllib.error.URLError) as e:
                self._send(400, {"ok": False, "error": f"{type(e).__name__}: {e}"})

        def do_DELETE(self):
            if not self._guard(True):
                return
            m = re.fullmatch(r"/api/exits/([\w.\-:]+)", self.path)
            if not m:
                return self._send(404, {"error": "not found"})
            store.remove_exit(m.group(1))
            self._send(200, sup.apply())

        def _post(self, path: str, b: dict) -> dict:
            s = store.data
            if path == "/api/connect":
                return sup.connect()
            if path == "/api/disconnect":
                return sup.disconnect()
            if path == "/api/global":  # the dropdown in the middle of the diagram
                return sup.switch_global(b["exit"])
            if path == "/api/routes":  # replace the whole routing map
                s["routes"] = b["routes"]
                store.save()
                return sup.apply()
            if path == "/api/panic":
                return sup.panic()
            if path == "/api/lane":  # live per-lane switch: {lane: "global" | <rule id>, paused: bool}
                return sup.set_lane(b["lane"], bool(b["paused"]))
            if path == "/api/confirm":
                return sup.confirm()
            if path == "/api/import/wireguard":
                ids = sup.import_wireguard(b["text"], b.get("name") or "wireguard", b.get("provider") or "manual")
                return {"ok": True, "ids": ids, **sup.apply()}
            if path == "/api/import/ovpn":
                eid = sup.import_ovpn(b["text"], b.get("name") or "openvpn", b.get("provider") or "")
                return {"ok": True, "ids": [eid], **sup.apply()}
            if path == "/api/import/path":  # folder / zip / file on this machine
                return sup.import_path(b["path"], b.get("provider") or "")
            if path == "/api/import/subscription":
                sid = parsers.slug(b.get("id") or b.get("name") or "sub")
                return sup.import_subscription(sid, b.get("name") or sid, b.get("url") or "", b.get("text") or "")
            if path == "/api/subscription/refresh":
                sub = s["subscriptions"][b["id"]]
                return sup.import_subscription(b["id"], sub["name"], sub["url"])
            if path == "/api/providers":
                if b["provider"] not in s["providers"]:
                    return {"ok": False, "error": "unknown provider"}
                prov = s["providers"][b["provider"]]
                prov["username"] = b.get("username", prov["username"])
                if "password" in b:  # blank field in the UI means "keep the saved one"
                    prov["password"] = b["password"]
                store.save()
                return {"ok": True}
            if path == "/api/favorites":
                s["favorites"] = [i for i in b["ids"] if i in s["exits"]]
                store.save()
                return sup.apply()
            if path == "/api/exits/purge":
                return {"ok": True, "removed": store.remove_provider_exits(b["provider"]), **sup.apply()}
            if path == "/api/corp":
                c = s["corp"]
                for k in ("enabled", "ovpn_path", "auth_file", "server", "server_port", "dns"):
                    if k in b:
                        c[k] = b[k]
                if c["ovpn_path"] and not c["server"]:
                    try:
                        r = parsers.parse_ovpn_remote(open(c["ovpn_path"]).read())
                        if r:
                            c["server"], c["server_port"] = r
                    except OSError as e:
                        return {"ok": False, "error": str(e)}
                store.save()
                return sup.apply()
            if path == "/api/corp/up":
                return sup.corp_up()
            if path == "/api/corp/down":
                return sup.corp_down()
            if path == "/api/update-rules":
                return {"ok": True, "result": sup.update_rules()}
            return {"ok": False, "error": "unknown endpoint"}

    return H


def serve(store: Store, sup: Supervisor) -> None:
    port = store.data["settings"]["ui_port"]
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(store, sup))
    print(f"RouteRaft UI: http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        sup.disconnect()
