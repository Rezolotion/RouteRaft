"""CLI: routeraft serve | build | import-wg | import-sub | update-rules"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

from . import parsers, singbox
from .config import Store
from .server import serve
from .supervisor import Supervisor


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="routeraft")
    ap.add_argument("--state-dir", default="/var/lib/routeraft")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the daemon + web UI")
    s.add_argument("--dry-run", action="store_true", help="never touch the network; only write configs")
    sub.add_parser("build", help="print the generated sing-box config")
    w = sub.add_parser("import-wg", help="import a WireGuard .conf (Surfshark/Windscribe)")
    w.add_argument("file")
    w.add_argument("--name")
    v = sub.add_parser("import-sub", help="import a V2Ray subscription URL or file")
    v.add_argument("source")
    sub.add_parser("update-rules", help="download the Iran rule sets into the cache")
    a = ap.parse_args(argv)

    store = Store(Path(a.state_dir))
    sup = Supervisor(store, dry_run=getattr(a, "dry_run", False))

    if a.cmd == "serve":
        serve(store, sup)
    elif a.cmd == "build":
        print(json.dumps(singbox.build(store.data, sup.rule_dir), indent=2))
    elif a.cmd == "import-wg":
        p = Path(a.file)
        ids = store.add_exits([parsers.parse_wireguard(p.read_text(), a.name or p.stem)])
        print("imported:", ", ".join(ids))
    elif a.cmd == "import-sub":
        if a.source.startswith(("http://", "https://")):
            with urllib.request.urlopen(a.source, timeout=30) as r:
                text = r.read().decode("utf-8", "replace")
        else:
            text = Path(a.source).read_text()
        exits = parsers.parse_subscription(text)
        for old in [i for i, e in store.data["exits"].items() if e["type"] == "vless"]:
            store.data["exits"].pop(old)
        print(f"imported {len(store.add_exits(exits))} vless nodes")
    elif a.cmd == "update-rules":
        print(json.dumps(sup.update_rules(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
