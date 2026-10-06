import base64
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from routeraft import cleanup, parsers, singbox
from routeraft.config import Store
from routeraft.supervisor import Supervisor

UUID = "11111111-2222-3333-4444-555555555555"
WG = """[Interface]
PrivateKey = AAAA
Address = 10.14.0.2/16
DNS = 162.252.172.57
[Peer]
PublicKey = BBBB
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = de-1.example.com:51820
"""
OVPN = """client
dev tun
proto {proto}
remote {host} 1194
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
x
-----END CERTIFICATE-----
</ca>
"""
LINKS = {
    "vless-ws": f"vless://{UUID}@a.example.com:443?type=ws&security=tls&sni=a.example.com&path=%2Fws&host=a.example.com&fp=chrome#%F0%9F%87%A9%F0%9F%87%AA%20Node%20A",
    "vless-reality": f"vless://{UUID}@b.example.com:443?type=tcp&security=reality&sni=x.com&pbk=PUB&sid=ab&fp=chrome&flow=xtls-rprx-vision#Node%20B",
    "vless-grpc": f"vless://{UUID}@c.example.com:443?type=grpc&serviceName=svc&security=tls#grpc",
    "trojan": "trojan://secretpw@t.example.com:443?sni=t.example.com&type=ws&path=%2Ft#Trojan",
    "ss-sip002": "ss://" + base64.urlsafe_b64encode(b"aes-256-gcm:pw123").decode().rstrip("=") + "@s.example.com:8388#SS",
    "ss-legacy": "ss://" + base64.b64encode(b"chacha20-ietf-poly1305:pw@l.example.com:8389").decode() + "#Legacy",
    "hy2": "hysteria2://authpw@h.example.com:443?sni=h.example.com&obfs=salamander&obfs-password=op&insecure=1#Hy2",
    "hy1": "hysteria://hy.example.com:443?auth=a&upmbps=20&downmbps=80&peer=hy.example.com#Hy1",
    "tuic": f"tuic://{UUID}:pw@tu.example.com:443?congestion_control=bbr&alpn=h3&sni=tu.example.com#TUIC",
    "anytls": "anytls://pw@at.example.com:443?sni=at.example.com#AnyTLS",
    "socks": "socks5://u:p@sk.example.com:1080#Socks",
}
VMESS_JSON = {"v": "2", "ps": "VMess WS", "add": "v.example.com", "port": "443", "id": UUID, "aid": "0",
              "scy": "auto", "net": "ws", "type": "none", "host": "v.example.com", "path": "/v", "tls": "tls", "sni": "v.example.com"}
LINKS["vmess"] = "vmess://" + base64.b64encode(json.dumps(VMESS_JSON).encode()).decode()

CLASH = """
proxies:
  - {name: "clash-vless", type: vless, server: c1.example.com, port: 443, uuid: %s, tls: true, network: ws, ws-opts: {path: /w, headers: {Host: c1.example.com}}}
  - {name: "clash-ss", type: ss, server: c2.example.com, port: 8388, cipher: aes-128-gcm, password: pw}
  - {name: "clash-hy2", type: hysteria2, server: c3.example.com, port: 443, password: pw, sni: c3.example.com}
  - {name: "clash-kcp", type: vmess, server: c4.example.com, port: 443, uuid: %s, alterId: 0, cipher: auto, network: kcp}
""" % (UUID, UUID)


def fresh():
    return Supervisor(Store(Path(tempfile.mkdtemp())), dry_run=True)


class Links(unittest.TestCase):
    def test_every_link_scheme_parses_to_a_singbox_outbound(self):
        expect = {"vless-ws": "vless", "vless-reality": "vless", "vless-grpc": "vless", "trojan": "trojan",
                  "ss-sip002": "shadowsocks", "ss-legacy": "shadowsocks", "hy2": "hysteria2", "hy1": "hysteria",
                  "tuic": "tuic", "anytls": "anytls", "socks": "socks", "vmess": "vmess"}
        for k, typ in expect.items():
            e = parsers.parse_link(LINKS[k])
            self.assertEqual(e["outbound"]["type"], typ, k)
            self.assertTrue(e["outbound"]["server"] and e["outbound"]["server_port"], k)

    def test_details(self):
        ws = parsers.parse_link(LINKS["vless-ws"])
        self.assertEqual(ws["outbound"]["transport"]["type"], "ws")
        self.assertEqual(ws["country"], "DE")  # from the flag emoji
        re_ = parsers.parse_link(LINKS["vless-reality"])["outbound"]
        self.assertEqual(re_["tls"]["reality"]["public_key"], "PUB")
        self.assertEqual(re_["flow"], "xtls-rprx-vision")
        hy2 = parsers.parse_link(LINKS["hy2"])["outbound"]
        self.assertEqual(hy2["obfs"], {"type": "salamander", "password": "op"})
        self.assertTrue(hy2["tls"]["insecure"])
        ss = parsers.parse_link(LINKS["ss-sip002"])["outbound"]
        self.assertEqual((ss["method"], ss["password"]), ("aes-256-gcm", "pw123"))
        ss2 = parsers.parse_link(LINKS["ss-legacy"])["outbound"]
        self.assertEqual((ss2["server"], ss2["server_port"]), ("l.example.com", 8389))
        vm = parsers.parse_link(LINKS["vmess"])["outbound"]
        self.assertEqual(vm["transport"]["path"], "/v")
        self.assertEqual(vm["tls"]["server_name"], "v.example.com")

    def test_unsupported_transport_is_reported_not_silently_dropped(self):
        link = f"vless://{UUID}@x.example.com:443?type=xhttp&security=tls#X"
        with self.assertRaises(parsers.Unsupported):
            parsers.parse_link(link)
        exits, skipped = parsers.parse_subscription(link + "\n" + LINKS["trojan"])
        self.assertEqual(len(exits), 1)
        self.assertEqual(len(skipped), 1)


class Subscriptions(unittest.TestCase):
    def test_base64_and_dedupe(self):
        body = base64.b64encode("\n".join([LINKS["vless-ws"], LINKS["vless-ws"], LINKS["trojan"]]).encode()).decode()
        exits, _ = parsers.parse_subscription(body, "sub:x")
        self.assertEqual(len(exits), 3)
        self.assertEqual(len({e["id"] for e in exits}), 3)
        self.assertTrue(all(e["provider"] == "sub:x" for e in exits))

    def test_clash_yaml(self):
        exits, skipped = parsers.parse_subscription(CLASH)
        self.assertEqual([e["protocol"] for e in exits], ["vless", "shadowsocks", "hysteria2"])
        self.assertEqual(exits[0]["outbound"]["transport"]["path"], "/w")
        self.assertEqual(len(skipped), 1)  # mKCP

    def test_singbox_json(self):
        doc = {"outbounds": [{"type": "direct", "tag": "direct"}, {"type": "selector", "tag": "s", "outbounds": []},
                             {"type": "trojan", "tag": "my-trojan", "server": "j.example.com", "server_port": 443, "password": "p"}]}
        exits, _ = parsers.parse_subscription(json.dumps(doc))
        self.assertEqual(len(exits), 1)
        self.assertEqual(exits[0]["name"], "my-trojan")


class Files(unittest.TestCase):
    def test_wireguard_and_ovpn_meta(self):
        e = parsers.parse_wireguard(WG, "Surfshark DE")
        self.assertEqual(e["endpoint"]["peers"][0]["port"], 51820)
        u = parsers.parse_ovpn(OVPN.format(proto="udp", host="de-fra.prod.surfshark.com"), "de-fra_udp")
        t = parsers.parse_ovpn(OVPN.format(proto="tcp-client", host="de-fra.prod.surfshark.com"), "de-fra_tcp")
        self.assertEqual((u["transport"], t["transport"]), ("udp", "tcp"))
        self.assertEqual((u["provider"], u["country"], u["needs_auth"]), ("surfshark", "DE", True))

    def test_folder_and_zip_import(self):
        sup = fresh()
        d = Path(tempfile.mkdtemp())
        for n, proto in (("us-nyc_udp", "udp"), ("us-nyc_tcp", "tcp")):
            (d / f"{n}.ovpn").write_text(OVPN.format(proto=proto, host="us-nyc.prod.surfshark.com"))
        (d / "Windscribe-DE.conf").write_text(WG)
        (d / "junk.txt").write_text("ignore me")
        r = sup.import_path(str(d))
        self.assertEqual(r["added"], {"openvpn": 2, "wireguard": 1})
        z = d / "pack.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("ca-tor_udp.ovpn", OVPN.format(proto="udp", host="ca-tor.prod.surfshark.com"))
        self.assertEqual(sup.import_path(str(z))["added"]["openvpn"], 1)
        mode = Path(next(e["ovpn_path"] for e in sup.store.data["exits"].values() if e["kind"] == "openvpn")).stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


class Build(unittest.TestCase):
    def setUp(self):
        self.sup = fresh()
        self.st = self.sup.store
        self.st.add_exits([parsers.parse_wireguard(WG, "Surfshark-DE", "surfshark"),
                           parsers.parse_wireguard(WG.replace("de-1", "nl-1"), "Windscribe-NL", "windscribe")])
        exits, _ = parsers.parse_subscription("\n".join([LINKS["vless-ws"], LINKS["trojan"], LINKS["hy2"]]), "sub:s1")
        self.st.add_exits(exits)
        self.sup.import_ovpn(OVPN.format(proto="udp", host="198.51.100.7"), "de-fra_udp", "surfshark")
        self.d = self.st.data

    def cfg(self):
        return singbox.build(self.d)

    def test_all_kinds_reach_the_selector(self):
        sel = next(o for o in self.cfg()["outbounds"] if o["tag"] == "global")["outbounds"]
        for m in ("Surfshark-DE", "ovpn", "direct", "auto:sub:s1"):
            self.assertIn(m, sel)
        self.assertTrue(any(m.startswith("Node") or m == "Trojan" for m in sel))

    def test_wireguard_only_favorites_and_selected_are_loaded(self):
        self.d["global"] = "Surfshark-DE"
        self.assertEqual([e["tag"] for e in self.cfg()["endpoints"]], ["Surfshark-DE"])
        self.d["favorites"] = ["Windscribe-NL"]
        self.assertEqual(sorted(e["tag"] for e in self.cfg()["endpoints"]), ["Surfshark-DE", "Windscribe-NL"])

    def test_openvpn_global_binds_interface_and_bypasses_its_server(self):
        self.d["global"] = "de-fra_udp"
        cfg = self.cfg()
        ov = next(o for o in cfg["outbounds"] if o["tag"] == "ovpn")
        self.assertEqual(ov["bind_interface"], "rr-vpn0")
        self.assertEqual(next(o for o in cfg["outbounds"] if o["tag"] == "global")["default"], "ovpn")
        self.assertTrue(any(r.get("ip_cidr") == ["198.51.100.7"] and r["outbound"] == "direct" for r in cfg["route"]["rules"]))

    def test_swap_global_changes_only_the_selector_default_and_loaded_endpoint(self):
        self.d["global"] = "Surfshark-DE"
        a = self.cfg()
        self.d["global"] = "Trojan"
        b = self.cfg()
        for c in (a, b):
            c["outbounds"] = [o for o in c["outbounds"] if o["tag"] != "global"]
            c.pop("endpoints")
        self.assertEqual(a, b)

    def test_iran_direct_final_global_and_corp_precedes_private(self):
        self.d["corp"].update(enabled=True, ovpn_path="/x.ovpn", server="203.0.113.5", dns="192.168.100.1")
        self.d["routes"][1].update(domain_suffix=[".corp.example"], ip_cidr=["192.168.100.0/24"])
        cfg = self.cfg()
        rules = cfg["route"]["rules"]
        self.assertEqual(cfg["route"]["final"], "global")
        self.assertEqual(next(r for r in rules if r.get("domain_suffix") == [".ir"])["outbound"], "direct")
        corp_i = next(i for i, r in enumerate(rules) if r.get("outbound") == "rule:corp")
        priv_i = next(i for i, r in enumerate(rules) if r.get("ip_is_private"))
        self.assertLess(corp_i, priv_i)

    def test_every_rule_references_an_existing_outbound(self):
        self.d["routes"][0]["exit"] = "Windscribe-NL"  # pinned but not loaded -> falls back to global
        cfg = self.cfg()
        tags = {o["tag"] for o in cfg["outbounds"]} | {e["tag"] for e in cfg["endpoints"]}
        for r in cfg["route"]["rules"]:
            if "outbound" in r:
                self.assertIn(r["outbound"], tags)

    def test_public_view_has_no_secrets(self):
        self.d["providers"]["surfshark"].update(username="svc-user", password="svc-pass-123")
        pub = json.dumps(self.st.public())
        for secret in ("AAAA", UUID, "secretpw", "authpw", "svc-pass-123", self.d["api_secret"], self.d["ui_token"], "profiles/"):
            self.assertNotIn(secret, pub)
        self.assertTrue(self.st.public()["providers"]["surfshark"]["has_credentials"])

    def test_state_file_is_private_and_removal_repoints_routes(self):
        self.st.save()
        self.assertEqual(self.st.path.stat().st_mode & 0o777, 0o600)
        self.d["routes"][0]["exit"] = "Surfshark-DE"
        self.st.remove_exit("Surfshark-DE")
        self.assertEqual(self.d["routes"][0]["exit"], "global")


class LiveSwitches(unittest.TestCase):
    def setUp(self):
        self.sup = fresh()
        self.sup.store.add_exits([parsers.parse_wireguard(WG, "A")])
        self.d = self.sup.store.data
        self.d["corp"].update(enabled=True, ovpn_path="/x.ovpn", dns="10.0.0.53")
        self.d["routes"][1].update(domain_suffix=[".corp.example"])

    def sel(self, cfg, tag):
        return next((o for o in cfg["outbounds"] if o["tag"] == tag), None)

    def test_rules_with_a_tunnel_target_get_a_two_way_selector(self):
        cfg = singbox.build(self.d)
        s = self.sel(cfg, "rule:corp")
        self.assertEqual((s["type"], s["outbounds"], s["default"]), ("selector", ["corp", "direct"], "corp"))
        self.assertIsNone(self.sel(cfg, "rule:iran"))  # direct-target rules need no switch

    def test_paused_rule_defaults_to_direct_and_dns_follows_the_switch(self):
        self.d["routes"][1]["paused"] = True
        cfg = singbox.build(self.d)
        self.assertEqual(self.sel(cfg, "rule:corp")["default"], "direct")
        dns = next(x for x in cfg["dns"]["servers"] if x["tag"] == "dns-corp")
        self.assertEqual((dns["server"], dns["detour"]), ("10.0.0.53", "rule:corp"))

    def test_global_pause_defaults_the_selector_to_direct(self):
        self.d["global"] = "A"
        self.assertEqual(self.sel(singbox.build(self.d), "global")["default"], "A")
        self.d["global_paused"] = True
        self.assertEqual(self.sel(singbox.build(self.d), "global")["default"], "direct")

    def test_pause_does_not_look_like_a_new_config_to_the_rollback_guard(self):
        h1 = self.sup.config_hash(self.sup.build())
        self.d["routes"][1]["paused"] = True
        self.d["global_paused"] = True
        self.assertEqual(h1, self.sup.config_hash(self.sup.build()))

    def test_set_lane_persists_when_not_running(self):
        self.assertTrue(self.sup.set_lane("corp", True)["ok"])
        self.assertTrue(self.d["routes"][1]["paused"])
        self.assertTrue(self.sup.set_lane("global", True)["ok"])
        self.assertTrue(self.d["global_paused"])
        self.assertFalse(self.sup.set_lane("nope", True)["ok"])


class FakeRun:
    """Stands in for subprocess.run so tests never touch the real network stack."""
    def __init__(self, fail=()):
        self.calls, self.fail, self.rule_budget = [], set(fail), 2

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        rc = 0
        if cmd[:3] in (["ip", "-4", "rule"], ["ip", "-6", "rule"]):
            self.rule_budget -= 1  # pretend exactly one rule exists per family, then none
            rc = 0 if cmd[-1] == "9000" and self.rule_budget >= 0 else 1
        if tuple(cmd) in self.fail:
            rc = 1
        return type("R", (), {"returncode": rc})()


class Cleanup(unittest.TestCase):
    def test_clean_network_is_idempotent_and_scoped_to_singbox(self):
        run = FakeRun()
        done = cleanup.clean_network(["definitely-not-an-interface"], run)
        deleted = [c for c in run.calls if c[2:4] == ["rule", "del"]]
        self.assertTrue(deleted and all(9000 <= int(c[-1]) <= 9010 for c in deleted))
        self.assertTrue(any(c == ["ip", "-4", "route", "flush", "table", "2022"] for c in run.calls))
        self.assertFalse(any(c[:3] == ["ip", "link", "del"] for c in run.calls))  # interface absent -> untouched
        self.assertTrue(any("rule priority 9000" in d for d in done))

    def test_removes_an_interface_only_if_it_exists(self):
        run = FakeRun()
        cleanup.clean_network(["lo"], run)  # `lo` exists on every Linux box; the fake runner makes this safe
        self.assertIn(["ip", "link", "del", "lo"], run.calls)

    def test_kill_leftovers_ignores_unrelated_or_recycled_pids(self):
        import os
        d = Path(tempfile.mkdtemp())
        cleanup.record_pid(d, "sing-box", os.getpid())  # this test process: not sing-box/openvpn
        self.assertEqual(cleanup.kill_leftovers(d), [])
        self.assertFalse((d / cleanup.PIDFILE).exists())

    def test_restore_services_starts_only_what_we_stopped(self):
        d = Path(tempfile.mkdtemp())
        cleanup.record_stopped(d, ["v2raya"])
        run = FakeRun()
        self.assertEqual(cleanup.restore_services(d, run), ["v2raya"])
        self.assertEqual(run.calls, [["systemctl", "start", "v2raya"]])
        self.assertEqual(cleanup.restore_services(d, run), [])  # second call is a no-op

    def test_panic_in_dry_run_touches_nothing(self):
        sup = fresh()
        self.assertEqual(sup.panic(), {"ok": True})


class Rollback(unittest.TestCase):
    def test_config_hash_ignores_selector_default_and_secret(self):
        sup = fresh()
        sup.store.add_exits([parsers.parse_wireguard(WG, "A"), parsers.parse_wireguard(WG, "B")])
        sup.store.data["global"] = "A"
        h1 = sup.config_hash(sup.build())
        sup.store.data["global"] = "B"
        sup.store.data["api_secret"] = "other"
        self.assertNotEqual(h1, sup.config_hash(sup.build()))  # B is loaded instead of A -> really different config
        sup.store.data["favorites"] = ["A", "B"]
        h2 = sup.config_hash(sup.build())
        sup.store.data["global"] = "A"
        self.assertEqual(h2, sup.config_hash(sup.build()))  # same loaded set, only the default moved


if __name__ == "__main__":
    unittest.main()
