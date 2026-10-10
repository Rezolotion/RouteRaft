"""Second engine: Xray, for the nodes sing-box cannot run (XHTTP, mKCP, VLESS Encryption / ML-KEM).

Same idea as OpenVPN: a helper process hosts what sing-box cannot, and sing-box reaches it through a
local interface. Here that interface is one loopback SOCKS5 port per node, so a node is still a normal
selector member in sing-box: switching exits stays instant and the routing map never knows which engine
carries a node. Xray's own sockets bypass the TUN through the `process_name` rule in singbox.build().
"""
from __future__ import annotations

LISTEN = "127.0.0.1"


def exits_of(state: dict) -> list[str]:
    """Stable, sorted ids of every Xray-engine exit."""
    return sorted(i for i, e in state["exits"].items() if e["kind"] == "xray")


def port_for(state: dict, exit_id: str) -> int:
    """Deterministic loopback port for a node: base + its position in the sorted id list."""
    return state["settings"]["xray_base_port"] + exits_of(state).index(exit_id)


def build(state: dict) -> dict:
    """Xray config: per node one SOCKS inbound routed to exactly its own outbound."""
    inbounds, outbounds, rules = [], [], []
    for i in exits_of(state):
        tag = f"n{port_for(state, i)}"
        inbounds.append({"tag": f"in-{tag}", "listen": LISTEN, "port": port_for(state, i), "protocol": "socks",
                         "settings": {"auth": "noauth", "udp": True, "ip": LISTEN}})
        outbounds.append({**state["exits"][i]["outbound"], "tag": f"out-{tag}"})
        rules.append({"type": "field", "inboundTag": [f"in-{tag}"], "outboundTag": f"out-{tag}"})
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds,
            "outbounds": outbounds + [{"protocol": "blackhole", "tag": "block"}],
            "routing": {"domainStrategy": "AsIs", "rules": rules}}
