#!/usr/bin/env bash
# Runs INSIDE the sandbox container (see sandbox.sh). Exercises the real daemon + real sing-box.
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1
S=/tmp/state; mkdir -p "$S"
PASS=0; FAIL=0; SKIP=0
ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
no()   { echo "  FAIL  $1${2:+  ($2)}"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $1"; SKIP=$((SKIP+1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else no "$d"; fi; }
code()  { curl -sS -m 10 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || true; }
reach() { local c; c=$(code -k https://1.1.1.1/); [[ "$c" =~ ^[23] ]]; }          # raw IP, no DNS involved
reach_dns() { [ "$(code https://www.gstatic.com/generate_204)" = "204" ]; }       # needs DNS through the tunnel
rules()  { ip rule | grep -cE '^9[0-9]{3}:' || true; }
has_tun() { ip link show rr0 >/dev/null 2>&1; }
clean()  { ! has_tun && [ "$(rules)" = "0" ]; }
wait_for() { local n=$1; shift; for _ in $(seq "$n"); do "$@" && return 0; sleep 1; done; return 1; }

TOKEN=""; UI=http://127.0.0.1:8787
api()   { curl -s -m 20 -H "X-RouteRaft-Token: $TOKEN" -H 'Content-Type: application/json' -X POST "$UI$1" -d "${2:-{\}}"; }
state() { curl -s -m 5 "$UI/api/state"; }
jget()  { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)" 2>/dev/null; }
start_daemon() {
  python3 -m routeraft --state-dir "$S" serve >/tmp/daemon.log 2>&1 & DPID=$!
  wait_for 15 curl -sf "$UI/" -o /dev/null || { echo "daemon did not start"; cat /tmp/daemon.log; exit 2; }
  TOKEN=$(curl -s "$UI/" | grep -o 'const TOKEN = "[^"]*"' | cut -d'"' -f2)
}

echo "== sandbox: $(sing-box version | head -1), $(python3 --version), kernel $(uname -r)"
python3 - <<EOF
from pathlib import Path
from routeraft.config import Store
st = Store(Path("$S")); s = st.data["settings"]
s.update(stop_conflicting=[], rollback_seconds=8, health_interval=3, failover="warn", tun_exclude=[])
st.save()
EOF

echo; echo "[0] baseline (container network, before RouteRaft)"
[ "$(rules)" = "0" ] && ok "no sing-box rules present" || no "unexpected rules present"
if wait_for 25 reach; then ok "internet reachable by IP"; BASE_NET=1; else skip "internet by IP not reachable from this sandbox; connectivity checks are skipped"; BASE_NET=0; fi
if [ $BASE_NET = 1 ] && wait_for 10 reach_dns; then BASE_DNS=1; else BASE_DNS=0; skip "DNS-based fetch unavailable at baseline; DNS checks skipped"; fi

start_daemon

echo; echo "[1] connect (global = direct), unconfirmed config arms the rollback"
R=$(api /api/connect)
echo "$R" | grep -q '"ok": true' && ok "POST /api/connect ok" || no "connect" "$R"
RB=$(state | jget "d['status']['rollback_in']")
[ "${RB:-0}" -gt 0 ] && ok "rollback countdown armed (${RB}s)" || no "rollback not armed" "$RB"
has_tun && ok "TUN device rr0 exists" || no "TUN device rr0 missing"
[ "$(rules)" -ge 1 ] && ok "policy rules installed ($(rules))" || no "no policy rules"
ip route get 8.8.8.8 2>/dev/null | grep -q 'dev rr0' && ok "public traffic is routed into the TUN" || no "public traffic not routed into TUN" "$(ip route get 8.8.8.8 2>&1 | head -1)"
GW=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
ip route get "${GW:-172.17.0.1}" 2>/dev/null | grep -q 'dev rr0' && no "LAN gateway routed into TUN" || ok "LAN gateway stays on the physical interface"
[ $BASE_NET = 1 ] && { wait_for 8 reach && ok "internet still works through the tunnel (IP)" || no "internet lost after connect (IP)"; }
[ $BASE_DNS = 1 ] && { wait_for 8 reach_dns && ok "DNS + HTTPS work through the tunnel" || no "DNS/HTTPS broken after connect"; }

echo; echo "[2] unconfirmed config is rolled back automatically"
wait_for 14 bash -c "! curl -s -m 3 $UI/api/state | grep -q '\"running\": true'" && ok "disconnected itself after the countdown" || no "still running after countdown"
wait_for 6 bash -c "$(declare -f clean rules has_tun); clean" && ok "tunnel + rules removed" || no "leftovers after rollback"
[ $BASE_NET = 1 ] && { wait_for 12 reach && ok "internet works after rollback" || no "internet broken after rollback"; }

echo; echo "[3] confirm keeps the config"
api /api/connect >/dev/null
api /api/confirm >/dev/null
sleep 10
state | grep -q '"running": true' && ok "still connected after the rollback window (confirmed)" || no "dropped despite confirmation"

echo; echo "[4] live lane switch through the clash API (no restart)"
api /api/routes '{"routes":[{"id":"r1","name":"Probe","enabled":true,"exit":"global","domain_suffix":["example.com"],"domain":[],"ip_cidr":[],"rule_set":[],"process_name":[]}]}' >/dev/null
wait_for 15 bash -c "curl -s -m 3 $UI/api/state | grep -q '\"running\": true'" && ok "applied rules and sing-box restarted" || no "not running after applying rules"
RB=$(state | jget "d['status']['rollback_in']"); [ "${RB:-0}" -gt 0 ] && ok "changed config re-arms the rollback (${RB}s)" || no "changed config did not re-arm rollback"
api /api/confirm >/dev/null
SECRET=$(python3 -c "import json; print(json.load(open('$S/state.json'))['api_secret'])")
sel() { curl -s -m 5 -H "Authorization: Bearer $SECRET" "http://127.0.0.1:9090/proxies/rule:r1" | jget "d.get('now')"; }
[ "$(sel)" = "global" ] && ok "rule selector starts on its target" || no "selector initial state" "$(sel)"
R=$(api /api/lane '{"lane":"r1","paused":true}'); echo "$R" | grep -q '"ok": true' && ok "POST /api/lane ok" || no "lane pause" "$R"
[ "$(sel)" = "direct" ] && ok "paused rule now bypasses the tunnel (live)" || no "selector did not flip" "$(sel)"
api /api/lane '{"lane":"r1","paused":false}' >/dev/null
[ "$(sel)" = "global" ] && ok "resumed rule returns to its target (live)" || no "selector did not flip back"
[ $BASE_NET = 1 ] && { reach && ok "internet unaffected by lane switching" || no "internet broken by lane switching"; }

echo; echo "[5] kill -9 sing-box: watchdog restores normal networking"
pkill -9 sing-box
wait_for 20 bash -c "$(declare -f clean rules has_tun); clean" && ok "tunnel + rules cleaned up after a hard kill" || no "leftovers after kill -9" "tun=$(ip link show rr0 2>&1 | head -1) rules=$(rules)"
EV=$(state | jget "d['status']['event']")
[ -n "$EV" ] && ok "user is told what happened: \"$EV\"" || no "no event message"
[ $BASE_NET = 1 ] && { wait_for 8 reach && ok "internet works again" || no "internet broken after kill -9"; }

echo; echo "[6] daemon killed while connected: the ExecStopPost command recovers"
api /api/connect >/dev/null; api /api/confirm >/dev/null
has_tun && ok "connected again" || no "reconnect failed"
kill -9 "$DPID"; sleep 1
has_tun && ok "(precondition) leftovers exist after daemon death" || skip "no leftovers to clean (sing-box exited with its parent)"
python3 -m routeraft --state-dir "$S" panic >/tmp/panic.out 2>&1
wait_for 8 bash -c "$(declare -f clean rules has_tun); clean" && ok "routeraft panic removed everything" || no "panic left leftovers" "$(cat /tmp/panic.out | head -3)"
pgrep -x sing-box >/dev/null && no "sing-box still running after panic" || ok "sing-box process stopped"
[ $BASE_NET = 1 ] && { wait_for 12 reach && ok "internet works after panic" || no "internet broken after panic"; }

echo; echo "[7] panic button via the API"
start_daemon
api /api/connect >/dev/null; api /api/confirm >/dev/null
R=$(api /api/panic); echo "$R" | grep -q '"ok": true' && ok "POST /api/panic ok" || no "panic api" "$R"
wait_for 8 bash -c "$(declare -f clean rules has_tun); clean" && ok "clean after panic button" || no "leftovers after panic button"
kill "$DPID" 2>/dev/null

echo; echo "== $PASS passed, $FAIL failed, $SKIP skipped"
if [ "$FAIL" != "0" ]; then
  echo; echo "---- sing-box log (last 25 lines) ----"; tail -25 "$S/logs/sing-box.log" 2>/dev/null
  echo "---- daemon log (last 10 lines) ----"; tail -10 /tmp/daemon.log 2>/dev/null
fi
[ "$FAIL" = "0" ]
