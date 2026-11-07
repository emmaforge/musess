#!/usr/bin/env bash
# musess direction-5 (speculative transport) prototype test.
#
# Legs (all on 127.0.0.1, ALL PORTS OFFSET +300 from the project
# defaults so this line never collides with the other lines' runs
# or with stale default-port listeners):
#   direct   - curl straight to the dest stand-in
#   ss2022   - curl -> client SOCKS :11382 -> ss2022 -> server :14746
#   musess   - curl -> client SOCKS :11380 -> musess baseline -> :14743
#   musess-off - same, early_request=false, SOCKS :11383
#   warm     - warm_pool=2, SOCKS :11385
#   zerortt  - zero_rtt=true (client+server), SOCKS :11386
#   race     - primary + faster alternate shim in parallel, SOCKS :11387
#   all      - warm_pool=2 + zero_rtt + race, SOCKS :11388
#
# Settings: none | delay25 | delay100 | burst
#   burst = delay25 + hold-prob 0.30 + hold-ms 300 through the shim.
#   This is the project's delay/HOLD model, NOT packet loss: the shim
#   never drops a byte; a held chunk stalls the chunks behind it,
#   which emulates the head-of-line stall a lost TCP segment causes.
#   True random packet loss cannot be produced in this sandbox
#   (tc/netem is not permitted: `ip link add` fails with Operation
#   not permitted), so burst is the closest loss-stall proxy
#   available here and is labelled as such everywhere.
#
# Phases per leg per setting (identical fetch counts, so shim byte
# totals are comparable):
#   A: TTFB: 1 warmup + 3 rounds x 5 measured small HTTPS fetches
#      (15 samples -> p50/p95), then 3 rounds x 10 sequential small
#      fetches (total time per round -> median; a stall shows up as
#      a long round or a failed fetch).
#   B: bulk: 3 rounds x 32 MiB download (median Mbps) for the
#      musess/SS2022 goodput ratio table.
# Shim byte totals are captured per leg per phase (shims are restarted
# per leg-phase), so extra traffic % = (leg bytes - baseline bytes) /
# baseline bytes for the same phase and fetch counts.
#
# Bench hygiene: preflight checks every offset port is free (aborts
# with the occupant instead of running on a stolen port); every shim
# start is verified by its "shim listening on" log line; a delay
# sanity check aborts the run if the baseline musess TTFB median does
# not scale with the setting's delay (shim not in path -> numbers void).
set -u
cd "$(dirname "$0")"
TESTDIR=$(pwd)
IMPLDIR=$(dirname "$TESTDIR")
TMPROOT="$IMPLDIR/.tmp"
mkdir -p "$TMPROOT"
WORK=$(mktemp -d "$TMPROOT/spec-XXXXXX")
echo "workdir: $WORK"
echo "impairment: user-space shim, delay/hold model (NOT packet loss); tc/netem not permitted in sandbox"

export GOTOOLCHAIN=local TMPDIR="$TMPROOT"
GO="$HOME/workspace/go-1.24.7/bin/go"
[ -x "$GO" ] || GO="$(command -v go || true)"
[ -n "$GO" ] || { echo "FATAL: no go toolchain"; exit 2; }

BIN="$TMPROOT/sing-box-musess"
[ -x "$BIN" ] || { echo "FATAL: sing-box binary not found at $BIN (build the prototype first)"; exit 2; }
echo "binary: $($BIN version | head -1)"

(cd helper && "$GO" build -o "$WORK/helper" .) || { echo "FATAL: helper build failed"; exit 2; }
HELPER="$WORK/helper"
RESULTS="$WORK/results.tsv"
: > "$RESULTS"

# --- ports (+300 offsets) ---------------------------------------------------
DEST_PORT=18743
MUSESS_PORT=14743
SS_PORT=14746
BULK_PORT=19301
SHIM_MUSESS=15751
SHIM_MUSESS_FAST=15753
SHIM_SS=15752
SHIM_DIRECT=15750
SOCKS_BASE=11380
SOCKS_OFF=11383
SOCKS_SS=11382
SOCKS_WARM=11385
SOCKS_ZRT=11386
SOCKS_RACE=11387
SOCKS_ALL=11388
BYTES=33554432   # 32 MiB bulk

# --- preflight: all offset ports must be free --------------------------------
echo "preflight: checking offset ports are free..."
OCCUPIED=0
for p in $DEST_PORT $MUSESS_PORT $SS_PORT $BULK_PORT $SHIM_MUSESS $SHIM_MUSESS_FAST $SHIM_SS $SHIM_DIRECT $SOCKS_BASE $SOCKS_OFF $SOCKS_SS $SOCKS_WARM $SOCKS_ZRT $SOCKS_RACE $SOCKS_ALL; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "PREFLIGHT-FAIL: port $p is occupied:"; ss -ltnp 2>/dev/null | grep ":$p " || true
    OCCUPIED=1
  fi
done
[ "$OCCUPIED" = 1 ] && { echo "FATAL: resolve the occupants above (do not run on a stolen port)"; exit 2; }
echo "preflight: all offset ports free"

# --- certs + configs ----------------------------------------------------------
WM="$WORK/musess"; mkdir -p "$WM"
cd "$WM"
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 2 -nodes \
  -subj "/CN=musess-spec-ca" >/dev/null 2>&1
for name in dest server-local; do
  openssl req -newkey rsa:2048 -keyout "$name-key.pem" -out "$name.csr" -nodes \
    -subj "/CN=dest.test" >/dev/null 2>&1
  printf "subjectAltName=DNS:dest.test,IP:127.0.0.1\n" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "$name.pem" -days 2 -extfile "$name.ext" >/dev/null 2>&1
done
TOKEN="<redacted>"
printf '%s' "$TOKEN" > body.txt
KEYS=$("$HELPER" keygen)
SERVER_PRIVATE=$(printf '%s\n' "$KEYS" | sed -n 's/^private=//p')
SERVER_PUBLIC=$(printf '%s\n' "$KEYS" | sed -n 's/^public=//p')
sed -e "s|__WORKDIR__|$WM|g" -e "s|__SERVER_PRIVATE_KEY__|$SERVER_PRIVATE|g" \
  "$TESTDIR/server.json" > "$WM/server.json"
# Server enables zero_rtt application of transport state; baseline
# legs are unaffected (the server only parses a 0-RTT frame when the
# client sends one, and the frame can never authenticate or route).
# NOTE: the server.json template hardcodes listen_port 14443 (the
# project default) — override it to the +300 offset here, or this
# line silently binds the default port and collides with other lines.
python3 - "$WM/server.json" "$MUSESS_PORT" "$DEST_PORT" <<'EOF'
import json, sys
p = sys.argv[1]
cfg = json.load(open(p))
for ib in cfg["inbounds"]:
    if ib["type"] == "musess":
        ib["zero_rtt"] = True
        ib["listen_port"] = int(sys.argv[2])
        # Template hardcodes dest_port 18443 (project default); the
        # dest stand-in in this script listens on the offset port,
        # so unauthenticated forwarding must point there too.
        ib["dest_port"] = int(sys.argv[3])
json.dump(cfg, open(p, "w"), indent=2)
EOF

mkclient() { # $1=outfile $2=socks_port $3=server_port $4=extra-python
  sed -e "s|__SERVER_PORT__|$3|g" -e "s|__SERVER_PUBLIC_KEY__|$SERVER_PUBLIC|g" \
    "$TESTDIR/client.json" > "$1"
  python3 - "$1" "$2" "$4" <<'EOF'
import json, sys
path, socks, extra = sys.argv[1], int(sys.argv[2]), sys.argv[3]
cfg = json.load(open(path))
cfg["inbounds"][0]["listen_port"] = socks
for ob in cfg["outbounds"]:
    if ob["type"] == "musess":
        if extra == "off":
            ob["early_request"] = False
        elif extra == "warm":
            ob["warm_pool"] = 2
            ob["warm_pool_idle_seconds"] = 30
        elif extra == "zrt":
            ob["zero_rtt"] = True
        elif extra == "race":
            ob["race_servers"] = ["__FAST__"]
        elif extra == "all":
            ob["warm_pool"] = 2
            ob["warm_pool_idle_seconds"] = 30
            ob["zero_rtt"] = True
            ob["race_servers"] = ["__FAST__"]
json.dump(cfg, open(path, "w"), indent=2)
EOF
}
# NOTE: mkclient writes __FAST__ literally for race legs; fix it up per
# setting below with sed after the call (the fast shim port is fixed).
mkclient "$WM/client-base-direct.json"  $SOCKS_BASE $MUSESS_PORT base
mkclient "$WM/client-base-shim.json"    $SOCKS_BASE $SHIM_MUSESS base
mkclient "$WM/client-off-direct.json"   $SOCKS_OFF  $MUSESS_PORT off
mkclient "$WM/client-off-shim.json"     $SOCKS_OFF  $SHIM_MUSESS off
mkclient "$WM/client-warm-direct.json"  $SOCKS_WARM $MUSESS_PORT warm
mkclient "$WM/client-warm-shim.json"    $SOCKS_WARM $SHIM_MUSESS warm
mkclient "$WM/client-zrt-direct.json"   $SOCKS_ZRT  $MUSESS_PORT zrt
mkclient "$WM/client-zrt-shim.json"     $SOCKS_ZRT  $SHIM_MUSESS zrt
mkclient "$WM/client-race-direct.json"  $SOCKS_RACE $MUSESS_PORT race
mkclient "$WM/client-race-shim.json"    $SOCKS_RACE $SHIM_MUSESS race
mkclient "$WM/client-all-direct.json"   $SOCKS_ALL  $MUSESS_PORT all
mkclient "$WM/client-all-shim.json"     $SOCKS_ALL  $SHIM_MUSESS all
sed -i "s|__FAST__|127.0.0.1:$SHIM_MUSESS_FAST|g" "$WM"/client-race-*.json "$WM"/client-all-*.json
# In the none setting there is no fast shim: the alternate leg dials the
# server directly, same as the primary (a genuine parallel second dial,
# not a dial to a dead port).
python3 - "$WM/client-race-direct.json" "$WM/client-all-direct.json" "$MUSESS_PORT" <<'EOF'
import json, sys
for path in sys.argv[1:3]:
    cfg = json.load(open(path))
    for ob in cfg["outbounds"]:
        if ob["type"] == "musess":
            ob["race_servers"] = ["127.0.0.1:%s" % sys.argv[3]]
    json.dump(cfg, open(path, "w"), indent=2)
EOF

WS="$WORK/ss2022"; mkdir -p "$WS"
cp "$TESTDIR/ss2022-server.json" "$WS/server.json"
python3 - "$WS/server.json" "$SS_PORT" <<'EOF'
import json, sys
p = sys.argv[1]
cfg = json.load(open(p))
for ib in cfg["inbounds"]:
    ib["listen_port"] = int(sys.argv[2])
json.dump(cfg, open(p, "w"), indent=2)
EOF
sed -e "s|__SERVER_PORT__|$SS_PORT|g" -e "s|11082|$SOCKS_SS|g" "$TESTDIR/ss2022-client.json" > "$WS/client-direct.json"
sed -e "s|__SERVER_PORT__|$SHIM_SS|g" -e "s|11082|$SOCKS_SS|g" "$TESTDIR/ss2022-client.json" > "$WS/client-shim.json"

for cfg in "$WM/server.json" "$WM"/client-*.json "$WS/server.json" "$WS/client-direct.json" "$WS/client-shim.json"; do
  "$BIN" check -c "$cfg" >/dev/null || { echo "FATAL: config check failed: $cfg"; exit 2; }
done
echo "all configs: OK"
# Config-port assertion: the generated server configs must bind the
# +300 offset ports, never the project defaults (a template with a
# hardcoded listen_port once made this script bind 14443/14446 while
# another line's probe was using them — caught by wait_port, no leg
# ran, but the bind itself was a hygiene miss; this assertion makes
# it impossible to repeat silently).
python3 - "$WM/server.json" "$WS/server.json" "$MUSESS_PORT" "$SS_PORT" "$DEST_PORT" <<'EOF'
import json, sys
mus, ss, mp, sp, dp = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
mib = json.load(open(mus))["inbounds"][0]
sport = json.load(open(ss))["inbounds"][0]["listen_port"]
assert mib["listen_port"] == mp, f"musess server listen_port {mib['listen_port']} != {mp}"
assert sport == sp, f"ss2022 server listen_port {sport} != {sp}"
assert mib["dest_port"] == dp, f"musess server dest_port {mib['dest_port']} != {dp}"
print(f"config-port assertion: musess server={mib['listen_port']} dest_port={mib['dest_port']} ss2022 server={sport} (offsets, not defaults)")
EOF
[ $? -ne 0 ] && exit 2

# --- process management -------------------------------------------------------
PIDS=()
cleanup() { for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done; }
trap cleanup EXIT
LEG_PIDS=()
stop_leg() {
  for pid in "${LEG_PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  for pid in "${LEG_PIDS[@]:-}"; do wait "$pid" 2>/dev/null; done
  LEG_PIDS=()
}
# check_servers_alive: the long-lived services (dest, musess server,
# ss server, bulkserver) must still be listening after every leg. A
# run in which a server died mid-setting must abort loudly instead
# of recording failures caused by the dead server as protocol data.
# (First full run: the musess server went silent at the start of the
# burst setting for an unidentified cause, which voided every musess
# burst leg. This watchdog makes a repeat impossible to miss.)
check_servers_alive() { # $1=leg $2=setting
  for p in $DEST_PORT $MUSESS_PORT $SS_PORT $BULK_PORT; do
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
      echo "WATCHDOG-FAIL: long-lived service on port $p is gone after leg=$1 setting=$2"
      echo "last musess-server log:"; tail -n 15 "$WORK/musess-server.log"
      echo "last dest log:"; tail -n 5 "$WORK/dest.log"
      return 1
    fi
  done
  return 0
}
wait_port() {
  for _ in $(seq 1 75); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 0.2
  done
  echo "FATAL: port $1 never came up"; return 1
}
check_shim_log() { # $1=logfile $2=listen-port
  for _ in $(seq 1 50); do
    grep -q "shim listening on 127.0.0.1:$2 " "$1" 2>/dev/null && return 0
    sleep 0.2
  done
  echo "FATAL: shim on $2 never logged a successful bind:"; tail -n 5 "$1"; return 1
}
shim_bytes() { # $1=logfile -> total bytes (up+down) or empty
  grep -o "bytes client->target=[0-9]* target->client=[0-9]*" "$1" 2>/dev/null | tail -1 | \
    awk '{ up=$2; down=$3; gsub(/.*=/,"",up); gsub(/.*=/,"",down); print up+down }'
}

# --- long-lived services ------------------------------------------------------
"$HELPER" dest -addr 127.0.0.1:$DEST_PORT -cert "$WM/dest.pem" -key "$WM/dest-key.pem" \
  -body "$WM/body.txt" -sidlog "$WM/dest-sids.log" > "$WORK/dest.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WM/server.json" > "$WORK/musess-server.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WS/server.json" > "$WORK/ss-server.log" 2>&1 &
PIDS+=($!)
"$HELPER" bulkserver -port $BULK_PORT > "$WORK/bulkserver.log" 2>&1 &
PIDS+=($!)
wait_port $DEST_PORT && wait_port $MUSESS_PORT && wait_port $SS_PORT && wait_port $BULK_PORT \
  || { tail -n 20 "$WORK"/*.log; exit 2; }
echo "servers up: dest=$DEST_PORT musess=$MUSESS_PORT ss2022=$SS_PORT bulk=$BULK_PORT"

# --- fetch helpers ------------------------------------------------------------
fetch_ttfb() { # curl extra args...; prints time_starttransfer; exit != 0 on curl error
  rm -f /tmp/spec-ttfb-body.txt
  curl -s --max-time 20 --cacert "$WM/ca.pem" --resolve dest.test:$DEST_PORT:127.0.0.1 \
    -o /tmp/spec-ttfb-body.txt -w '%{time_starttransfer}' "$@" https://dest.test:$DEST_PORT/
}
fetch_ok() { # curl args...; 0 iff body == TOKEN
  rm -f /tmp/spec-ttfb-body.txt
  curl -s --max-time 20 --cacert "$WM/ca.pem" --resolve dest.test:$DEST_PORT:127.0.0.1 \
    -o /tmp/spec-ttfb-body.txt "$@" https://dest.test:$DEST_PORT/ >/dev/null 2>&1 || return 1
  [ "$(cat /tmp/spec-ttfb-body.txt 2>/dev/null)" = "$TOKEN" ]
}

# run_ttfb_rounds $1=leg $2=setting $3..=curl args
# Appends 15 samples to $RESULTS as "ttfb <setting> <leg> <seconds>".
run_ttfb_rounds() {
  local leg=$1 setting=$2; shift 2
  fetch_ttfb "$@" >/dev/null 2>&1  # warmup (unchecked)
  for _ in 1 2 3; do
    for _ in 1 2 3 4 5; do
      local t rc
      t=$(fetch_ttfb "$@" 2>/tmp/spec-ttfb-err.txt); rc=$?
      if [ "$rc" -ne 0 ] || ! [ -f /tmp/spec-ttfb-body.txt ] || [ "$(cat /tmp/spec-ttfb-body.txt)" != "$TOKEN" ]; then
        echo "leg=$leg setting=$setting TTFB-FAIL rc=$rc err=$(head -c 200 /tmp/spec-ttfb-err.txt 2>/dev/null | tr '\n' ' ')"
        printf 'ttfb\t%s\t%s\tFAIL\n' "$setting" "$leg" >> "$RESULTS"
      else
        printf 'ttfb\t%s\t%s\t%s\n' "$setting" "$leg" "$t" >> "$RESULTS"
      fi
    done
  done
}

# run_seq_rounds $1=leg $2=setting $3..=curl args
# 3 rounds x 10 sequential fetches; appends total seconds per round.
run_seq_rounds() {
  local leg=$1 setting=$2; shift 2
  for _ in 1 2 3; do
    local start end total fails=0
    start=$(date +%s%N)
    for _ in $(seq 1 10); do fetch_ok "$@" || fails=$((fails+1)); done
    end=$(date +%s%N)
    total=$(awk -v s="$start" -v e="$end" 'BEGIN { printf "%.3f", (e-s)/1e9 }')
    printf 'seq10\t%s\t%s\t%s\tfails=%d\n' "$setting" "$leg" "$total" "$fails" >> "$RESULTS"
    echo "leg=$leg setting=$setting seq10 total=${total}s fails=$fails"
  done
}

# run_bulk_rounds $1=leg $2=setting $3=socks-port-or-empty
run_bulk_rounds() {
  local leg=$1 setting=$2 socks=$3 direct_addr=$4
  for _ in 1 2 3; do
    local out rc mbps seconds
    if [ -n "$socks" ]; then
      out=$(timeout 90 "$HELPER" bulkclient -bytes $BYTES -socks "127.0.0.1:$socks" -addr "127.0.0.1:$BULK_PORT" 2>&1); rc=$?
    else
      # Direct leg: impaired settings go through the direct shim,
      # the none setting goes straight at the bulkserver.
      out=$(timeout 90 "$HELPER" bulkclient -bytes $BYTES -addr "127.0.0.1:$direct_addr" 2>&1); rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
      echo "leg=$leg setting=$setting BULK-FAIL rc=$rc out=$out"
      printf 'bulk\t%s\t%s\tFAIL\n' "$setting" "$leg" >> "$RESULTS"
      continue
    fi
    mbps=$(printf '%s\n' "$out" | sed -n 's/.*mbps=\([0-9.]*\).*/\1/p')
    seconds=$(printf '%s\n' "$out" | sed -n 's/.*seconds=\([0-9.]*\).*/\1/p')
    printf 'bulk\t%s\t%s\t%s\t%s\n' "$setting" "$leg" "$mbps" "$seconds" >> "$RESULTS"
    echo "leg=$leg setting=$setting bulk mbps=$mbps seconds=$seconds"
  done
}

# --- per-leg runners ----------------------------------------------------------
# Each leg starts its own shim(s) + client so shim byte totals are
# attributable to that leg alone. $1=setting $2=shim-args-name.
LEG=""; SETTING=""
start_leg_shims() { # $1=leg-kind (base|ss|race) $2=setting
  local kind=$1 setting=$2
  case "$setting" in
    none) SHIM_ARGS=() ; FAST_ARGS=() ; SS_ARGS=() ;;
    delay25) SHIM_ARGS=(-delay-ms 25) ; FAST_ARGS=(-delay-ms 10) ; SS_ARGS=(-delay-ms 25) ;;
    delay100) SHIM_ARGS=(-delay-ms 100) ; FAST_ARGS=(-delay-ms 25) ; SS_ARGS=(-delay-ms 100) ;;
    burst) SHIM_ARGS=(-delay-ms 25 -hold-prob 0.30 -hold-ms 300) ; FAST_ARGS=(-delay-ms 25) ; SS_ARGS=(-delay-ms 25 -hold-prob 0.30 -hold-ms 300) ;;
  esac
  case "$kind" in
    base|ss)
      if [ "$setting" != none ]; then
        if [ "$kind" = ss ]; then
          "$HELPER" shim -listen 127.0.0.1:$SHIM_SS -target 127.0.0.1:$SS_PORT "${SS_ARGS[@]}" > "$WORK/shim-ss-$LEG-$setting-$PHASE.log" 2>&1 &
        else
          "$HELPER" shim -listen 127.0.0.1:$SHIM_MUSESS -target 127.0.0.1:$MUSESS_PORT "${SHIM_ARGS[@]}" > "$WORK/shim-musess-$LEG-$setting-$PHASE.log" 2>&1 &
        fi
        LEG_PIDS+=($!)
      fi
      ;;
    race)
      if [ "$setting" != none ]; then
        "$HELPER" shim -listen 127.0.0.1:$SHIM_MUSESS -target 127.0.0.1:$MUSESS_PORT "${SHIM_ARGS[@]}" > "$WORK/shim-musess-$LEG-$setting-$PHASE.log" 2>&1 &
        LEG_PIDS+=($!)
        "$HELPER" shim -listen 127.0.0.1:$SHIM_MUSESS_FAST -target 127.0.0.1:$MUSESS_PORT "${FAST_ARGS[@]}" > "$WORK/shim-fast-$LEG-$setting-$PHASE.log" 2>&1 &
        LEG_PIDS+=($!)
      fi
      ;;
  esac
  if [ "$setting" != none ]; then
    case "$kind" in
      base) wait_port $SHIM_MUSESS && check_shim_log "$WORK/shim-musess-$LEG-$setting-$PHASE.log" $SHIM_MUSESS || return 1 ;;
      ss) wait_port $SHIM_SS && check_shim_log "$WORK/shim-ss-$LEG-$setting-$PHASE.log" $SHIM_SS || return 1 ;;
      race) wait_port $SHIM_MUSESS && wait_port $SHIM_MUSESS_FAST \
        && check_shim_log "$WORK/shim-musess-$LEG-$setting-$PHASE.log" $SHIM_MUSESS \
        && check_shim_log "$WORK/shim-fast-$LEG-$setting-$PHASE.log" $SHIM_MUSESS_FAST || return 1 ;;
    esac
  fi
  return 0
}

# run_leg $1=leg $2=setting $3=kind $4=client-config $5=socks-port $6=curl-mode
# curl-mode: direct | socks (uses $5)
run_leg() {
  local leg=$1 setting=$2 kind=$3 cfg=$4 socks=$5 mode=$6
  LEG="$leg"; SETTING="$setting"; PHASE="A"
  local shimlog="" fastlog=""
  # --- phase A: TTFB + sequential ---
  if [ "$mode" = socks ]; then
    start_leg_shims "$kind" "$setting" || exit 2
  fi
  if [ "$mode" = socks ]; then
    "$BIN" run -c "$cfg" > "$WORK/client-$leg-$setting.log" 2>&1 &
    LEG_PIDS+=($!)
    wait_port "$socks" || { tail -n 20 "$WORK/client-$leg-$setting.log"; exit 2; }
    case "$leg" in warm|all)
      case "$setting" in delay100) sleep 3;; delay25|burst) sleep 2;; *) sleep 1;; esac ;;
    esac
    run_ttfb_rounds "$leg" "$setting" --socks5 "127.0.0.1:$socks"
    run_seq_rounds "$leg" "$setting" --socks5 "127.0.0.1:$socks"
  else
    # direct leg: no client process; bulk direct shim handled in phase B.
    run_ttfb_rounds "$leg" "$setting" --noproxy '*'
    run_seq_rounds "$leg" "$setting" --noproxy '*'
  fi
  stop_leg
  # shim totals for phase A
  local bytes_a=""
  case "$kind" in
    base) bytes_a=$(shim_bytes "$WORK/shim-musess-$leg-$setting-$PHASE.log") ;;
    ss) bytes_a=$(shim_bytes "$WORK/shim-ss-$leg-$setting-$PHASE.log") ;;
    race)
      local b1 b2
      b1=$(shim_bytes "$WORK/shim-musess-$leg-$setting-$PHASE.log"); b2=$(shim_bytes "$WORK/shim-fast-$leg-$setting-$PHASE.log")
      bytes_a=$(( ${b1:-0} + ${b2:-0} ))
      printf 'racefast\t%s\t%s\t%s\n' "$setting" "$leg" "${b2:-0}" >> "$RESULTS"
      ;;
  esac
  [ -n "$bytes_a" ] && printf 'bytesA\t%s\t%s\t%s\n' "$setting" "$leg" "$bytes_a" >> "$RESULTS"
  echo "leg=$leg setting=$setting phaseA shim_bytes=${bytes_a:-n/a}"
  # --- phase B: bulk ---
  PHASE="B"
  if [ "$mode" = socks ]; then
    start_leg_shims "$kind" "$setting" || exit 2
    "$BIN" run -c "$cfg" > "$WORK/client-$leg-$setting-bulk.log" 2>&1 &
    LEG_PIDS+=($!)
    wait_port "$socks" || { tail -n 20 "$WORK/client-$leg-$setting-bulk.log"; exit 2; }
    case "$leg" in warm|all)
      case "$setting" in delay100) sleep 3;; delay25|burst) sleep 2;; *) sleep 1;; esac ;;
    esac
    run_bulk_rounds "$leg" "$setting" "$socks" ""
    stop_leg
  else
    # direct bulk goes through its own shim so the direct leg is impaired too
    if [ "$setting" != none ]; then
      case "$setting" in
        delay25) D_ARGS=(-delay-ms 25) ;;
        delay100) D_ARGS=(-delay-ms 100) ;;
        burst) D_ARGS=(-delay-ms 25 -hold-prob 0.30 -hold-ms 300) ;;
      esac
      "$HELPER" shim -listen 127.0.0.1:$SHIM_DIRECT -target 127.0.0.1:$BULK_PORT "${D_ARGS[@]}" > "$WORK/shim-direct-$leg-$setting.log" 2>&1 &
      LEG_PIDS+=($!)
      wait_port $SHIM_DIRECT && check_shim_log "$WORK/shim-direct-$leg-$setting.log" $SHIM_DIRECT || exit 2
      DIRECT_ADDR=$SHIM_DIRECT
    else
      DIRECT_ADDR=$BULK_PORT
    fi
    run_bulk_rounds "$leg" "$setting" "" "$DIRECT_ADDR"
    stop_leg
  fi
  local bytes_b=""
  case "$kind" in
    base) bytes_b=$(shim_bytes "$WORK/shim-musess-$leg-$setting-$PHASE.log") ;;
    ss) bytes_b=$(shim_bytes "$WORK/shim-ss-$leg-$setting-$PHASE.log") ;;
    race)
      local b1 b2
      b1=$(shim_bytes "$WORK/shim-musess-$leg-$setting-$PHASE.log"); b2=$(shim_bytes "$WORK/shim-fast-$leg-$setting-$PHASE.log")
      bytes_b=$(( ${b1:-0} + ${b2:-0} ))
      ;;
  esac
  [ -n "$bytes_b" ] && printf 'bytesB\t%s\t%s\t%s\n' "$setting" "$leg" "$bytes_b" >> "$RESULTS"
  echo "leg=$leg setting=$setting phaseB shim_bytes=${bytes_b:-n/a}"
  check_servers_alive "$leg" "$setting" || exit 3
}

# --- main loop ----------------------------------------------------------------
for setting in none delay25 delay100 burst; do
  echo "=== setting=$setting ==="
  if [ "$setting" = none ]; then
    run_leg direct   "$setting" base "$WM/client-base-direct.json" "" direct
    run_leg ss2022   "$setting" ss   "$WS/client-direct.json"   $SOCKS_SS socks
    run_leg musess   "$setting" base "$WM/client-base-direct.json" $SOCKS_BASE socks
    run_leg musess-off "$setting" base "$WM/client-off-direct.json" $SOCKS_OFF socks
    run_leg warm     "$setting" base "$WM/client-warm-direct.json" $SOCKS_WARM socks
    run_leg zerortt  "$setting" base "$WM/client-zrt-direct.json"  $SOCKS_ZRT socks
    run_leg race     "$setting" race "$WM/client-race-direct.json" $SOCKS_RACE socks
    run_leg all      "$setting" race "$WM/client-all-direct.json"  $SOCKS_ALL socks
  else
    run_leg direct   "$setting" base "$WM/client-base-direct.json" "" direct
    run_leg ss2022   "$setting" ss   "$WS/client-shim.json"     $SOCKS_SS socks
    run_leg musess   "$setting" base "$WM/client-base-shim.json" $SOCKS_BASE socks
    run_leg musess-off "$setting" base "$WM/client-off-shim.json" $SOCKS_OFF socks
    run_leg warm     "$setting" base "$WM/client-warm-shim.json" $SOCKS_WARM socks
    run_leg zerortt  "$setting" base "$WM/client-zrt-shim.json"  $SOCKS_ZRT socks
    run_leg race     "$setting" race "$WM/client-race-shim.json" $SOCKS_RACE socks
    run_leg all      "$setting" race "$WM/client-all-shim.json"  $SOCKS_ALL socks
  fi
  # --- delay sanity: baseline musess TTFB median must scale with the setting.
  # (If the shim were not in the path, delay100 would look like none and
  # every number in this setting would be void.)
  python3 - "$RESULTS" "$setting" <<'EOF'
import statistics, sys
rows = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.startswith("ttfb\t")]
setting = sys.argv[2]
vals = [float(r[3]) for r in rows if r[1] == setting and r[2] == "musess" and r[3] != "FAIL"]
if not vals:
    print(f"SANITY-FAIL setting={setting}: no musess TTFB samples"); sys.exit(1)
med = statistics.median(vals)
bands = {"none": (0.0, 0.05), "delay25": (0.15, 0.30), "delay100": (0.60, 1.00), "burst": (0.15, 2.50)}
lo, hi = bands[setting]
print(f"sanity setting={setting}: musess TTFB median={med*1000:.0f}ms band=[{lo*1000:.0f},{hi*1000:.0f}]ms")
if not (lo <= med <= hi):
    print(f"SANITY-FAIL setting={setting}: median outside band, shim may not be in path"); sys.exit(1)
EOF
  [ $? -ne 0 ] && exit 2
done

echo "=== summary ==="
python3 - "$RESULTS" <<'EOF'
import statistics
from collections import defaultdict

def p95(vals):
    s = sorted(vals)
    if not s: return float("nan")
    i = min(len(s) - 1, max(0, int(len(s) * 0.95 + 0.5) - 1))
    return s[i]

rows = [l.rstrip("\n").split("\t") for l in open(__import__("sys").argv[1])]
ttfb = defaultdict(list); seq = defaultdict(list); bulk = defaultdict(list)
bytesA = {}; bytesB = {}; racefast = {}
for r in rows:
    if r[0] == "ttfb" and r[3] != "FAIL":
        ttfb[(r[1], r[2])].append(float(r[3]) * 1000)
    elif r[0] == "seq10":
        seq[(r[1], r[2])].append(float(r[3]))
    elif r[0] == "bulk" and r[3] != "FAIL":
        bulk[(r[1], r[2])].append(float(r[3]))
    elif r[0] == "bytesA":
        bytesA[(r[1], r[2])] = int(r[3])
    elif r[0] == "bytesB":
        bytesB[(r[1], r[2])] = int(r[3])
    elif r[0] == "racefast":
        racefast[(r[1], r[2])] = int(r[3])

settings = ["none", "delay25", "delay100", "burst"]
legs = ["direct", "ss2022", "musess", "musess-off", "warm", "zerortt", "race", "all"]
print("TTFB ms (n=15): setting leg p50 p95")
for s in settings:
    for leg in legs:
        v = ttfb.get((s, leg), [])
        if v:
            print(f"ttfb {s} {leg} n={len(v)} p50={statistics.median(v):.1f} p95={p95(v):.1f}")
print("SEQ10 total s (median of 3): setting leg median")
for s in settings:
    for leg in legs:
        v = seq.get((s, leg), [])
        if v:
            print(f"seq10 {s} {leg} median={statistics.median(v):.2f} rounds={['%.2f' % x for x in v]}")
print("BULK Mbps (median of 3): setting leg median ratio-vs-ss2022")
for s in settings:
    ss = statistics.median(bulk[(s, "ss2022")]) if bulk.get((s, "ss2022")) else float("nan")
    for leg in legs:
        v = bulk.get((s, leg), [])
        if v:
            m = statistics.median(v)
            print(f"bulk {s} {leg} median={m:.0f} ratio={m/ss:.3f} rounds={['%.0f' % x for x in v]}")
print("EXTRA TRAFFIC phaseA bytes (vs musess baseline, same fetch counts):")
for s in settings:
    base = bytesA.get((s, "musess"))
    if not base:
        continue
    for leg in legs:
        v = bytesA.get((s, leg))
        if v is not None:
            print(f"bytesA {s} {leg} total={v} extra_pct={(v-base)/base*100:+.1f}%")
    for leg in ("race", "all"):
        if (s, leg) in racefast:
            print(f"racefast-bytes {s} {leg} fast_shim_bytes={racefast[(s, leg)]}")
EOF
echo "speculative test done (workdir kept at $WORK for logs; results at $RESULTS)"
