# RouteRaft

**A modular split-tunnel manager for Linux.** One TUN captures the whole machine; a routing map decides, per destination, whether traffic leaves through a commercial VPN, a V2Ray-family node, your corporate VPN, or your own ISP. Swapping Surfshark for Windscribe, or one subscription for another, changes a single field and never touches your rules.

Built on [sing-box](https://sing-box.sagernet.org/). RouteRaft is the control plane: it compiles your exits and rules into a sing-box configuration, supervises the processes that sing-box cannot host (OpenVPN), and exposes a local web UI.

```
                      ┌──────────── rules, first match wins ────────────┐
 this machine ─ TUN ─▶│ domestic sites ───────────────────────▶ direct  │
                      │ corporate domains / ranges ───────────▶ corp    │
                      │ everything else ──────────────────────▶ global ─┼─▶ exactly one of:
                      └──────────────────────────────────────────────────┘     WireGuard · OpenVPN (UDP/TCP)
                                                                               VLESS · VMess · Trojan · Shadowsocks
                                                                               Hysteria · Hysteria2 · TUIC · AnyTLS
```

## Why

Some destinations must be reached from a foreign IP, some only from a domestic one, and some only through the company network. Doing that with one tool per provider means re-plumbing routes by hand every time you change provider. RouteRaft separates the two concerns:

| Concept | Meaning |
|---|---|
| **Exit** | Something traffic can leave through: a WireGuard peer, an OpenVPN profile, or a sing-box outbound. |
| **Global slot** | The single exit used for everything no rule claims. Switching it is one dropdown and, for most exits, needs no restart. |
| **Rule** | Match (`domain_suffix`, `domain`, `ip_cidr`, `rule_set`, `process_name`) → target (`global`, `direct`, `corp`, or a specific exit). |

## Supported protocols

| Family | Variants | Runs as |
|---|---|---|
| WireGuard | Any `.conf` (Surfshark, Windscribe, Mullvad, self-hosted) | sing-box endpoint |
| OpenVPN | Any `.ovpn`, UDP and TCP, per-provider credentials | supervised `openvpn` process |
| V2Ray family | VLESS (TCP, WS, gRPC, HTTP/2, HTTPUpgrade; TLS, REALITY, XTLS Vision), VMess, Trojan, Shadowsocks (incl. obfs / v2ray-plugin) | sing-box outbound |
| QUIC family | Hysteria, Hysteria2 (Salamander obfs, port hopping), TUIC v5, AnyTLS | sing-box outbound |
| Plain proxies | SOCKS5, HTTP(S) | sing-box outbound |

Subscription formats: base64 or plain share-link lists, Clash / Mihomo YAML, and sing-box JSON. Nodes that sing-box cannot run (for example xHTTP or mKCP transports) are skipped **and reported**, never silently dropped.

## Features

- **Bulk import.** Point RouteRaft at a folder or `.zip` of hundreds of `.ovpn` / `.conf` files; exits are grouped by provider and country, searchable, and filterable by protocol.
- **Fast switching.** Favorite WireGuard exits stay loaded for instant selection; V2Ray nodes are always loaded; OpenVPN exits start on demand.
- **Latency-based exit.** A "fastest node" exit per subscription (sing-box `urltest`).
- **DNS follows the route.** Domestic names resolve on your ISP resolver, corporate names on the corporate DNS, the rest over DoH through the global exit. No split-brain leaks.
- **Safe by default.** Whenever a configuration you have not confirmed goes live, RouteRaft starts a countdown and disconnects automatically unless you confirm that connectivity works. A bad rule cannot leave you stranded offline.
- **No lock-in.** State is a single JSON file; the generated sing-box configuration is a normal file you can inspect with `routeraft build`.

## Requirements

- Linux with systemd, root privileges for the daemon (TUN device, OpenVPN)
- Python 3.11+, `python3-yaml` (only for Clash subscriptions)
- sing-box 1.12 or newer (developed and tested against 1.14)
- `openvpn` (only if you use OpenVPN exits)

## Install

```bash
# 1. sing-box from the official SagerNet apt repository (Debian / Ubuntu)
sudo bash packaging/install-singbox.sh

# 2. RouteRaft as a service
sudo mkdir -p /opt/routeraft && sudo cp -r routeraft pyproject.toml /opt/routeraft/
sudo cp packaging/routeraft.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now routeraft
```

Open <http://127.0.0.1:8787>.

On connect, services listed in `settings.stop_conflicting` (default: `v2raya`) are stopped because they compete for the TUN device and `/etc/resolv.conf`; they are started again on disconnect.

## Usage

Everything is available in the web UI. The CLI covers headless setups:

```bash
routeraft import-path ~/Downloads/surfshark-configs      # folder, .zip or single file
routeraft import-wg ~/Downloads/windscribe-de.conf --provider windscribe
routeraft import-sub https://example.com/sub --name "My subscription"
routeraft update-rules                                   # cache the domestic rule sets
routeraft build                                          # print the generated sing-box config
```

OpenVPN profiles use *service credentials* (not your account login). Save them once under **Accounts**. The corporate OpenVPN profile is configured separately under **Corporate VPN** and only carries traffic that your rules route to `corp`.

## How OpenVPN fits in

sing-box cannot speak OpenVPN, so each OpenVPN exit runs as its own `openvpn` process on a fixed interface (`rr-vpn0` for the active global exit, `tun-corp` for the corporate tunnel). Profiles are started with `--route-nopull` and the pushed redirect and DNS options are ignored, so OpenVPN never touches your routing table; sing-box reaches the tunnel through a `direct` outbound bound to that interface. The VPN server's own address is excluded from the TUN, which prevents VPN-in-VPN loops.

## Development

```bash
python3 -m unittest discover -s tests -v                       # unit tests
python3 -m routeraft --state-dir dev-state serve --dry-run     # UI and configs only; never touches the network
bash scripts/sandbox.sh                                        # live end-to-end suite in a throwaway container
```

`--dry-run` writes configurations and serves the UI without starting sing-box or OpenVPN.

`scripts/sandbox.sh` runs the real daemon and the real sing-box inside a Docker container with its own network namespace, so the TUN device, policy rules and DNS handling exist only there and the host network is never touched. It covers connect, the auto-rollback, confirmation, live lane switching, recovery after `kill -9` of sing-box and of the daemon, and the panic button. It needs Docker, a local `debian:12` image and a Debian 12 host (the host's `/usr` is mounted read-only into the container).

### Rule sets

The domestic rule sets (`geosite-ir`, `geoip-ir`) are cached files, never fetched by sing-box at startup, because a failed download there is fatal and downloads are unreliable on filtered networks. RouteRaft tries to refresh missing sets before connecting and otherwise starts without them; explicit domain suffixes such as `.ir` keep matching. Refresh them any time with `routeraft update-rules`.

## Security model

- The daemon runs as root and serves its UI on `127.0.0.1` only.
- Every state-changing request needs a per-install token that only same-origin JavaScript can read, and `Host` / `Origin` headers are validated (DNS-rebinding and CSRF protection).
- Keys, UUIDs, passwords and profile paths are never returned by the API. `state.json` and imported profiles are mode `0600`.
- The UI makes no external requests; no fonts, scripts or analytics are loaded.
- The folder importer reads only `.ovpn`, `.conf` and `.zip` files.

## Status

Pre-release (v0.2). Core, parsers, config compiler, web UI and unit tests are complete. Not yet verified end to end against a live TUN: OpenVPN interface binding, interaction with Docker's `strict_route`, and exact field names against the installed sing-box (the daemon runs `sing-box check` before every start). Planned: obfuscated transports (Stealth / WStunnel via stunnel and wstunnel), IKEv2, optional kill switch.

## License

[MIT](LICENSE)
