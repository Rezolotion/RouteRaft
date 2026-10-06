import base64
import json
import tempfile
import unittest
from pathlib import Path

from routeraft import parsers, singbox
from routeraft.config import Store

WG = """[Interface]
PrivateKey = AAAA
Address = 10.14.0.2/16
DNS = 162.252.172.57, 149.154.159.92
[Peer]
PublicKey = BBBB
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = de-1.example.com:51820
"""
VLESS_WS = "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?type=ws&security=tls&sni=a.example.com&path=%2Fws&host=a.example.com&fp=chrome#Node%20A"
VLESS_RE = "vless://11111111-2222-3333-4444-555555555555@b.example.com:443?type=tcp&security=reality&sni=x.com&pbk=PUB&sid=ab&fp=chrome&flow=xtls-rprx-vision#Node%20B"


def fresh():
    return Store(Path(tempfile.mkdtemp()))


class Parsers(unittest.TestCase):
    def test_wireguard(self):
        e = parsers.parse_wireguard(WG, "Surfshark DE")
        self.assertEqual(e["server"], "de-1.example.com")
        self.assertEqual(e["server_port"], 51820)
        self.assertEqual(e["address"], ["10.14.0.2/16"])

    def test_subscription_base64_and_dedupe(self):
        body = base64.b64encode(("\n".join([VLESS_WS, VLESS_RE, VLESS_WS, "vmess://ignored"])).encode()).decode()
        ex = parsers.parse_subscription(body)
        self.assertEqual(len(ex), 3)
        self.assertEqual(len({e["id"] for e in ex}), 3)

    def test_ovpn_remote(self):
        self.assertEqual(parsers.parse_ovpn_remote("client\nremote vpn.corp.example 443 tcp\n"), ("vpn.corp.example", 443))


class Build(unittest.TestCase):
    def setUp(self):
        self.st = fresh()
        self.st.add_exits([parsers.parse_wireguard(WG, "Surfshark DE")])
        self.st.add_exits(parsers.parse_subscription(VLESS_WS + "\n" + VLESS_RE))

    def test_selector_contains_every_exit_and_default(self):
        cfg = singbox.build(self.st.data)
        sel = next(o for o in cfg["outbounds"] if o["tag"] == "global")
        self.assertIn("Surfshark-DE", sel["outbounds"])
        self.assertIn("auto-vless", sel["outbounds"])
        self.assertEqual(sel["default"], "Surfshark-DE")  # first selectable becomes global
        self.assertEqual(cfg["endpoints"][0]["type"], "wireguard")

    def test_swap_global_is_one_field(self):
        a = singbox.build(self.st.data)
        self.st.data["global"] = "Node-A"
        b = singbox.build(self.st.data)
        a["outbounds"] = [o for o in a["outbounds"] if o["tag"] != "global"]
        b["outbounds"] = [o for o in b["outbounds"] if o["tag"] != "global"]
        self.assertEqual(a, b)  # nothing but the selector default changes

    def test_iran_goes_direct_and_final_is_global(self):
        cfg = singbox.build(self.st.data)
        iran = [r for r in cfg["route"]["rules"] if r.get("domain_suffix") == [".ir"]][0]
        self.assertEqual(iran["outbound"], "direct")
        self.assertEqual(cfg["route"]["final"], "global")

    def test_corp_rules_precede_private_direct(self):
        d = self.st.data
        d["corp"].update(enabled=True, ovpn_path="/x.ovpn", server="203.0.113.5", dns="192.168.100.1")
        d["routes"][1]["domain_suffix"] = [".corp.example"]
        d["routes"][1]["ip_cidr"] = ["192.168.100.0/24"]
        cfg = singbox.build(d)
        rules = cfg["route"]["rules"]
        corp_i = next(i for i, r in enumerate(rules) if r.get("outbound") == "corp")
        priv_i = next(i for i, r in enumerate(rules) if r.get("ip_is_private"))
        self.assertLess(corp_i, priv_i)
        self.assertTrue(any(o.get("bind_interface") == "tun-corp" for o in cfg["outbounds"]))
        # company server stays off the tunnel
        self.assertTrue(any(r.get("ip_cidr") == ["203.0.113.5"] and r["outbound"] == "direct" for r in rules))
        self.assertTrue(any(s["tag"] == "dns-corp" for s in cfg["dns"]["servers"]))

    def test_corp_disabled_never_references_corp_outbound(self):
        d = self.st.data
        d["routes"][1]["domain_suffix"] = [".corp.example"]
        cfg = singbox.build(d)
        tags = {o["tag"] for o in cfg["outbounds"]} | {e["tag"] for e in cfg["endpoints"]}
        for r in cfg["route"]["rules"]:
            if "outbound" in r:
                self.assertIn(r["outbound"], tags)

    def test_no_secrets_in_public_view(self):
        pub = json.dumps(self.st.public())
        self.assertNotIn("AAAA", pub)
        self.assertNotIn("11111111-2222", pub)
        self.assertNotIn(self.st.data["api_secret"], pub)
        self.assertNotIn(self.st.data["ui_token"], pub)

    def test_state_file_is_private(self):
        self.st.save()
        self.assertEqual(self.st.path.stat().st_mode & 0o777, 0o600)

    def test_removing_exit_repoints_routes(self):
        self.st.data["routes"][0]["exit"] = "Node-A"
        self.st.remove_exit("Node-A")
        self.assertEqual(self.st.data["routes"][0]["exit"], "global")


if __name__ == "__main__":
    unittest.main()
