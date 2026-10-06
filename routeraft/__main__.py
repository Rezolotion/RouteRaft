"""CLI: routeraft serve | build | import-path | import-wg | import-sub | update-rules"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import parsers
from .config import Store
from .server import serve
from .supervisor import Supervisor


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="routeraft")
    ap.add_argument("--state-dir", default="/var/lib/routeraft")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the daemon + web UI")
    s.add_argument("--dry-run", action="store_true", help="never touch the network; only write configs")
    sub.add_parser("build", help="print the generated sing-box config (contains secrets)")
    i = sub.add_parser("import-path", help="import a folder / .zip / file of .ovpn and WireGuard .conf")
    i.add_argument("path")
    i.add_argument("--provider", default="", help="surfshark | windscribe | manual (default: detect)")
    w = sub.add_parser("import-wg", help="import one WireGuard .conf")
    w.add_argument("file")
    w.add_argument("--name")
    w.add_argument("--provider", default="manual")
    v = sub.add_parser("import-sub", help="import a subscription URL or file (links / Clash YAML / sing-box JSON)")
    v.add_argument("source")
    v.add_argument("--name", default="sub")
    sub.add_parser("update-rules", help="download the Iran rule sets into the cache")
    a = ap.parse_args(argv)

    store = Store(Path(a.state_dir))
    sup = Supervisor(store, dry_run=getattr(a, "dry_run", False))

    if a.cmd == "serve":
        serve(store, sup)
    elif a.cmd == "build":
        print(json.dumps(sup.build(), indent=2))
    elif a.cmd == "import-path":
        print(json.dumps(sup.import_path(a.path, a.provider), indent=2, ensure_ascii=False))
    elif a.cmd == "import-wg":
        p = Path(a.file)
        print("imported:", sup.import_wireguard(p.read_text(), a.name or p.stem, a.provider))
    elif a.cmd == "import-sub":
        url = a.source if a.source.startswith(("http://", "https://")) else ""
        text = "" if url else Path(a.source).read_text()
        print(json.dumps(sup.import_subscription(parsers.slug(a.name), a.name, url, text), indent=2, ensure_ascii=False))
    elif a.cmd == "update-rules":
        print(json.dumps(sup.update_rules(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
