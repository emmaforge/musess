#!/usr/bin/env bash
# musess mux-landing benchmark (rate-attack phase 2 follow-up).
#
# Legs (all on 127.0.0.1, OFFSET +100 ports — never the default
# segment, so parallel benches in other chats cannot collide):
#   stock  - musess, mux off (early_request default on), server
#            14543, SOCKS 11180
#   mux    - musess, mux on, SOCKS 11181
#   muxfec - musess, mux on + fec auto, SOCKS 11182
#   ss2022 - shadowsocks 2022-blake3-aes-128-gcm, server 14546,
#            SOCKS 11183
#   direct - no proxy (reference)
# One musess server serves all three musess legs (mux=true,
# fec=auto on the server: plain commandTCP streams and non-FEC
# clients are unaffected — dispatch is per-connection; this is
# verified by the stock leg reproducing the old stock numbers).
#
# Workloads (README phase-2 §3口径):
#   ttfb      = single 1 MiB transfer (setup-dominated) + HTTPS
#               first byte (curl time_starttransfer, small fetch)
#   bulk32 / bulk256 = single 32 / 256 MiB transfers
#   seq10     = 10 sequential 1 MiB transfers, wall-clock; warm
#               (session established) and cold (fresh client boot)
#   mixed     = bulk32 while a sibling bulk stream's consumer is
#               stalled (stallclient holds one stream unread):
#               the flow-control decoupling proof, mux vs stock
#
# Settings: none | delay25 | delay100 | loss25 | loss100.
# loss* = evening-peak model: delay + holds (10% of 16 KiB chunks
# held an extra 200 ms per direction) — the shim's delay/hold
# model, NOT packet loss (tc/netem unavailable). A held chunk
# stalls everything behind it on that TCP byte stream, which is
# exactly the no-progress stall a lost segment causes on TCP.
# Loss legs also record per-100ms progress (bulkclient -progress)
# and report no-progress stalls (max gap, gaps >200 ms).
#
# Bench hygiene (after the main-chat port-collision incident):
#  - preflight: ss -ltnp over every port in the offset set; any
#    LISTEN entry from a leftover helper/sing-box process is
#    killed and re-checked; if a port is still occupied the run
#    aborts instead of producing numbers on a dead shim.
#  - after starting a shim, its log must contain its bind line
#    ("shim listening on ..."); after each setting, the shim
#    exit lines must show forwarded bytes > 0 (proof the shim
#    was in the path).
#  - latency sanity per delay setting: the musess TTFB median
#    must exceed the one-way shim delay; otherwise the setting
#    is marked SHIM SANITY FAIL and its numbers are invalid.
#
# Each cell: 3 reps, median reported. Raw results in $WORK/results.txt.
set -u
cd "$(dirname "$0")"
TESTDIR=$(pwd)
IMPLDIR=$(dirname "$TESTDIR")
TMPROOT="$IMPLDIR/.tmp"
mkdir -p "$TMPROOT"
WORK=$(mktemp -d "$TMPROOT/bench-mux-XXXXXX")
echo "workdir: $WORK"
echo "impairment: user-space shim, delay/hold model (NOT packet loss)"
echo "ports: offset +100 (musess 14543, socks 11180-11183, shims 15550-15552, bulk 19101, dest 18543)"

export GOTOOLCHAIN=local TMPDIR="$TMPROOT"
# NOTE: do NOT export no_proxy='*' here (test-ttfb.sh lesson): it
# makes curl bypass --socks5, so proxied TTFB legs would silently
# measure the direct path. Direct curl gets --noproxy '*' per call;
# SOCKS curl runs with the sandbox proxy vars unset (see
# run_ttfb_https).
GO="$HOME/workspace/go-1.24.7/bin/go"
[ -x "$GO" ] || GO="$(command -v go || true)"
[ -n "$GO" ] || { echo "FATAL: no go toolchain"; exit 2; }

BIN="$TMPROOT/sing-box-musess"
if [ ! -x "$BIN" ]; then echo "FATAL: binary missing at $BIN (build it per impl/README.md)"; exit 2; fi
echo "binary: $($BIN version | head -1)"

(cd helper && "$GO" build -o "$WORK/helper" .) || { echo "FATAL: helper build failed"; exit 2; }
HELPER="$WORK/helper"

# --- ports (offset +100) -----------------------------------------------------
DEST_PORT=18543
MUSESS_PORT=14543
SS_PORT=14546
BULK_PORT=19101
SOCKS_STOCK=11180
SOCKS_MUX=11181
SOCKS_MUXFEC=11182
SOCKS_SS=11183
SHIM_DIRECT_PORT=15550
SHIM_MUSESS_PORT=15551
SHIM_SS_PORT=15552
ALL_PORTS="$DEST_PORT $MUSESS_PORT $SS_PORT $BULK_PORT $SOCKS_STOCK $SOCKS_MUX $SOCKS_MUXFEC $SOCKS_SS $SHIM_DIRECT_PORT $SHIM_MUSESS_PORT $SHIM_SS_PORT"

# --- hygiene: preflight ------------------------------------------------------
echo "--- preflight: port check (ss -ltnp) ---"
ss -ltnp 2>/dev/null | grep -E ":(18543|14543|14546|19101|1118[0-3]|1555[0-2])\b" || echo "no offset ports in use"
for p in $ALL_PORTS; do
  if ss -ltn 2>/dev/null | grep -q ":$p\b"; then
    echo "PORT $p OCCUPIED before start:"
    ss -ltnp 2>/dev/null | grep ":$p\b" || true
  fi
done
# Clear leftovers from earlier runs of THIS line only. The VM is
# shared with other musess lines: never pkill by bare binary name
# ("sing-box-musess" killed the multipath line's processes twice),
# and never pkill -f on a pattern that appears in the invoking
# shell's own command line (that kills the caller). Instead, kill
# only the PIDs ss reports as owning our ports, and only when their
# /proc cmdline contains this line's workdir.
clear_my_leftovers() {
  for p in "$@"; do
    for pid in $(ss -ltnp 2>/dev/null | grep ":$p\b" | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | sort -u); do
      cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
      case "$cmd" in
        *mux-landing*) kill "$pid" 2>/dev/null || true ;;
      esac
    done
  done
  sleep 1
}
clear_my_leftovers $ALL_PORTS
STILL_OCCUPIED=0
for p in $ALL_PORTS; do
  if ss -ltn 2>/dev/null | grep -q ":$p\b"; then
    echo "FATAL: port $p still occupied after clearing leftovers — aborting, do not run on a dead shim"
    ss -ltnp 2>/dev/null | grep ":$p\b" || true
    STILL_OCCUPIED=1
  fi
done
[ "$STILL_OCCUPIED" -eq 1 ] && exit 2
echo "preflight: all offset ports free"

# --- certs + configs ----------------------------------------------------------
WM="$WORK/musess"; mkdir -p "$WM"
cd "$WM"
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 2 -nodes \
  -subj "/CN=musess-bench-mux-ca" >/dev/null 2>&1
for name in dest server-local; do
  openssl req -newkey rsa:2048 -keyout "$name-key.pem" -out "$name.csr" -nodes \
    -subj "/CN=dest.test" >/dev/null 2>&1
  printf "subjectAltName=DNS:dest.test,IP:127.0.0.1\n" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "$name.pem" -days 2 -extfile "$name.ext" >/dev/null 2>&1
done
printf 'MUSESS-BENCH-MUX-DEST' > body.txt
KEYS=$("$HELPER" keygen)
SERVER_PRIVATE=$(printf '%s\n' "$KEYS" | sed -n 's/^private=//p')
SERVER_PUBLIC=$(printf '%s\n' "$KEYS" | sed -n 's/^public=//p')

# Server: ONE server serves all musess legs (mux=true, fec=auto).
# NOTE: server.json is a template with __WORKDIR__ /
# __SERVER_PRIVATE_KEY__ placeholders, so substitute textually
# before parsing as JSON.
python3 - "$TESTDIR/server.json" "$WM/server.json" "$WM" "$SERVER_PRIVATE" <<'EOF'
import json, sys
src, dst, work, priv = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
text = open(src).read().replace("__WORKDIR__", work).replace("__SERVER_PRIVATE_KEY__", priv)
cfg = json.loads(text)
cfg["inbounds"][0]["certificate_path"] = work + "/server-local.pem"
cfg["inbounds"][0]["key_path"] = work + "/server-local-key.pem"
cfg["inbounds"][0]["listen_port"] = 14543
cfg["inbounds"][0]["dest_port"] = 18543
cfg["inbounds"][0]["private_key"] = priv
cfg["inbounds"][0]["mux"] = True
cfg["inbounds"][0]["fec"] = "auto"
json.dump(cfg, open(dst, "w"), indent=2)
EOF

mkclient() { # $1=tag $2=socks_port $3=mux(true/false) $4=fec(""|auto) $5=server_port
  # NOTE: client.json is a template with a __SERVER_PORT__
  # placeholder — substitute textually before parsing as JSON.
  python3 - "$TESTDIR/client.json" "$WM/client-$1.json" "$2" "$3" "$4" "$5" "$SERVER_PUBLIC" <<'EOF'
import json, sys
src, dst, socks, mux, fec, sport, pub = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], int(sys.argv[6]), sys.argv[7]
text = open(src).read().replace("__SERVER_PORT__", str(sport))
cfg = json.loads(text)
cfg["inbounds"][0]["listen_port"] = socks
for ob in cfg["outbounds"]:
    if ob["type"] == "musess":
        ob["server_port"] = sport
        ob["public_key"] = pub
        if mux == "true":
            ob["mux"] = True
        if fec:
            ob["fec"] = fec
json.dump(cfg, open(dst, "w"), indent=2)
EOF
}
mkclient stock-direct $SOCKS_STOCK false "" $MUSESS_PORT
mkclient stock-shim   $SOCKS_STOCK false "" $SHIM_MUSESS_PORT
mkclient mux-direct   $SOCKS_MUX   true  "" $MUSESS_PORT
mkclient mux-shim     $SOCKS_MUX   true  "" $SHIM_MUSESS_PORT
mkclient muxfec-direct $SOCKS_MUXFEC true auto $MUSESS_PORT
mkclient muxfec-shim   $SOCKS_MUXFEC true auto $SHIM_MUSESS_PORT

WS="$WORK/ss2022"; mkdir -p "$WS"
cp "$TESTDIR/ss2022-server.json" "$WS/server.json"
sed -e "s|__SERVER_PORT__|$SS_PORT|g" "$TESTDIR/ss2022-client.json" > "$WS/client-direct.json"
sed -e "s|__SERVER_PORT__|$SHIM_SS_PORT|g" "$TESTDIR/ss2022-client.json" > "$WS/client-shim.json"
sed -i "s|\"listen_port\": 11082|\"listen_port\": $SOCKS_SS|" "$WS/client-direct.json" "$WS/client-shim.json"
# ss2022-server.json has listen_port 14446; move it to the offset port.
sed -i "s|\"listen_port\":14446|\"listen_port\":$SS_PORT|" "$WS/server.json"

for cfg in "$WM/server.json" "$WM"/client-*.json "$WS/server.json" "$WS/client-direct.json" "$WS/client-shim.json"; do
  "$BIN" check -c "$cfg" >/dev/null || { echo "FATAL: config check failed: $cfg"; exit 2; }
done
echo "all configs: OK"

# --- process management -------------------------------------------------------
PIDS=()
cleanup() { for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done; }
trap cleanup EXIT
SETTING_PIDS=()
stop_setting() {
  for pid in "${SETTING_PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  for pid in "${SETTING_PIDS[@]:-}"; do wait "$pid" 2>/dev/null; done
  SETTING_PIDS=()
}
wait_port() {
  for _ in $(seq 1 75); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 0.2
  done
  echo "FATAL: port $1 never came up"; return 1
}
median() { printf '%s\n' "$@" | sort -n | awk '{ a[NR]=$1 } END { print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2) }'; }

RESULTS="$WORK/results.txt"
: > "$RESULTS"
record() { echo "$1" | tee -a "$RESULTS"; }

"$HELPER" dest -addr 127.0.0.1:$DEST_PORT -cert "$WM/dest.pem" -key "$WM/dest-key.pem" \
  -body "$WM/body.txt" -sidlog "$WM/dest-sids.log" > "$WORK/dest.log" 2>&1 &
PIDS+=($!)
"$HELPER" bulkserver -port $BULK_PORT > "$WORK/bulkserver.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WM/server.json" > "$WORK/musess-server.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WS/server.json" > "$WORK/ss-server.log" 2>&1 &
PIDS+=($!)
wait_port $DEST_PORT && wait_port $BULK_PORT && wait_port $MUSESS_PORT && wait_port $SS_PORT \
  || { tail -n 20 "$WORK"/*.log; exit 2; }
echo "servers up: dest=$DEST_PORT bulk=$BULK_PORT musess=$MUSESS_PORT ss2022=$SS_PORT"

# --- leg runners ---------------------------------------------------------------
# run_bulk <leg> <socks_port|direct> <bytes> <setting> <rep> [progress_file]
run_bulk() {
  local leg=$1 socks=$2 bytes=$3 setting=$4 rep=$5 progress=${6:-}
  local out rc seconds mbps
  if [ "$socks" = direct ]; then
    if [ -n "$progress" ]; then
      out=$(timeout 90 "$HELPER" bulkclient -bytes "$bytes" -addr "$DIRECT_ADDR" -progress "$progress" 2>&1); rc=$?
    else
      out=$(timeout 90 "$HELPER" bulkclient -bytes "$bytes" -addr "$DIRECT_ADDR" 2>&1); rc=$?
    fi
  else
    if [ -n "$progress" ]; then
      out=$(timeout 90 "$HELPER" bulkclient -bytes "$bytes" -socks "127.0.0.1:$socks" -addr "127.0.0.1:$BULK_PORT" -progress "$progress" 2>&1); rc=$?
    else
      out=$(timeout 90 "$HELPER" bulkclient -bytes "$bytes" -socks "127.0.0.1:$socks" -addr "127.0.0.1:$BULK_PORT" 2>&1); rc=$?
    fi
  fi
  if [ $rc -eq 124 ]; then
    record "setting=$setting leg=$leg workload=bulk$bytes rep=$rep seconds=90.000 mbps=0.00 stalled=yes"
  elif [ $rc -ne 0 ]; then
    record "setting=$setting leg=$leg workload=bulk$bytes rep=$rep FAILED rc=$rc output: $out"
  else
    seconds=$(printf '%s\n' "$out" | sed -n 's/.*seconds=\([0-9.]*\).*/\1/p')
    mbps=$(printf '%s\n' "$out" | sed -n 's/.*mbps=\([0-9.]*\).*/\1/p')
    record "setting=$setting leg=$leg workload=bulk$bytes rep=$rep seconds=$seconds mbps=$mbps"
    if [ -n "$progress" ] && [ -f "$progress" ]; then
      python3 "$TESTDIR/stall-analyze.py" "$progress" | sed "s/^/setting=$setting leg=$leg rep=$rep stall /" | tee -a "$RESULTS"
    fi
  fi
}

# run_seq10 <leg> <socks_port|direct> <setting> <rep> — 10 sequential 1 MiB
run_seq10() {
  local leg=$1 socks=$2 setting=$3 rep=$4
  local total=0 per=() i s out rc
  for i in $(seq 1 10); do
    if [ "$socks" = direct ]; then
      out=$(timeout 60 "$HELPER" bulkclient -bytes 1048576 -addr "$DIRECT_ADDR" 2>&1); rc=$?
    else
      out=$(timeout 60 "$HELPER" bulkclient -bytes 1048576 -socks "127.0.0.1:$socks" -addr "127.0.0.1:$BULK_PORT" 2>&1); rc=$?
    fi
    if [ $rc -ne 0 ]; then record "setting=$setting leg=$leg workload=seq10 rep=$rep FAILED transfer $i rc=$rc: $out"; return; fi
    s=$(printf '%s\n' "$out" | sed -n 's/.*seconds=\([0-9.]*\).*/\1/p')
    per+=("$s")
    total=$(python3 -c "print(f'{$total + float(\"$s\"):.3f}')")
  done
  local eff_mbps
  eff_mbps=$(python3 -c "print(f'{10*1048576*8/float(\"$total\")/1e6:.2f}')")
  record "setting=$setting leg=$leg workload=seq10 rep=$rep seconds=$total mbps=$eff_mbps per_transfer=${per[*]}"
}

# run_ttfb_https <leg> <setting> <rep> <curl-args...> — 1 warmup + 3 samples, median.
# Curl runs with the sandbox proxy vars unset so --socks5 is never
# bypassed by env; the direct leg additionally gets --noproxy '*'.
run_ttfb_https() {
  local leg=$1 setting=$2 rep=$3; shift 3
  local samples=() t
  env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY curl -s --max-time 15 --cacert "$WM/ca.pem" --resolve dest.test:$DEST_PORT:127.0.0.1 \
    -o /tmp/mux-ttfb-body.txt -w '%{time_starttransfer}' "$@" https://dest.test:$DEST_PORT/ >/dev/null 2>&1
  for _ in 1 2 3; do
    t=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY curl -s --max-time 15 --cacert "$WM/ca.pem" --resolve dest.test:$DEST_PORT:127.0.0.1 \
      -o /tmp/mux-ttfb-body.txt -w '%{time_starttransfer}' "$@" https://dest.test:$DEST_PORT/)
    if [ "$(cat /tmp/mux-ttfb-body.txt 2>/dev/null)" != "MUSESS-BENCH-MUX-DEST" ]; then
      record "setting=$setting leg=$leg workload=ttfb_https rep=$rep FAILED wrong body"; return
    fi
    samples+=("$t")
  done
  local med
  med=$(median "${samples[@]}")
  record "setting=$setting leg=$leg workload=ttfb_https rep=$rep seconds=$med samples=${samples[*]}"
  echo "$med" >> "$WORK/ttfb-$setting-$leg.txt"
}

# --- settings matrix -----------------------------------------------------------
REPS=3
for setting in none delay25 delay100 loss25 loss100; do
  echo "================ setting=$setting ================"
  echo "load before setting: $(uptime)"
  case $setting in
    none)     DESC="none";                        SHIM_ARGS=(); DELAY_MS=0 ;;
    delay25)  DESC="delay25ms";                   SHIM_ARGS=(-delay-ms 25); DELAY_MS=25 ;;
    delay100) DESC="delay100ms";                  SHIM_ARGS=(-delay-ms 100); DELAY_MS=100 ;;
    loss25)   DESC="delay25ms+hold0.10x200ms";    SHIM_ARGS=(-delay-ms 25 -hold-prob 0.10 -hold-ms 200); DELAY_MS=25 ;;
    loss100)  DESC="delay100ms+hold0.10x200ms";   SHIM_ARGS=(-delay-ms 100 -hold-prob 0.10 -hold-ms 200); DELAY_MS=100 ;;
  esac

  if [ "$setting" = none ]; then
    CLIENT_SUFFIX=direct
    DIRECT_ADDR="127.0.0.1:$BULK_PORT"
    "$BIN" run -c "$WM/client-stock-direct.json" > "$WORK/client-stock-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-mux-direct.json" > "$WORK/client-mux-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-muxfec-direct.json" > "$WORK/client-muxfec-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WS/client-direct.json" > "$WORK/ss-client-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    wait_port $SOCKS_STOCK && wait_port $SOCKS_MUX && wait_port $SOCKS_MUXFEC && wait_port $SOCKS_SS \
      || { tail -n 20 "$WORK"/*-$setting.log; exit 2; }
  else
    CLIENT_SUFFIX=shim
    DIRECT_ADDR="127.0.0.1:$SHIM_DIRECT_PORT"
    "$HELPER" shim -listen 127.0.0.1:$SHIM_DIRECT_PORT -target 127.0.0.1:$BULK_PORT \
      "${SHIM_ARGS[@]}" > "$WORK/shim-direct-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$HELPER" shim -listen 127.0.0.1:$SHIM_MUSESS_PORT -target 127.0.0.1:$MUSESS_PORT \
      "${SHIM_ARGS[@]}" > "$WORK/shim-musess-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$HELPER" shim -listen 127.0.0.1:$SHIM_SS_PORT -target 127.0.0.1:$SS_PORT \
      "${SHIM_ARGS[@]}" > "$WORK/shim-ss-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    sleep 0.5
    # Hygiene: every shim must show its bind line, or the setting is void.
    for s in direct musess ss; do
      if grep -q "shim listening on" "$WORK/shim-$s-$setting.log"; then
        echo "shim-$s: $(grep 'shim listening on' "$WORK/shim-$s-$setting.log")"
      else
        echo "FATAL: shim-$s did not bind (no 'shim listening on' in its log) — setting $setting VOID"
        cat "$WORK/shim-$s-$setting.log"; exit 2
      fi
    done
    "$BIN" run -c "$WM/client-stock-shim.json" > "$WORK/client-stock-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-mux-shim.json" > "$WORK/client-mux-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-muxfec-shim.json" > "$WORK/client-muxfec-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WS/client-shim.json" > "$WORK/ss-client-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    wait_port $SHIM_DIRECT_PORT && wait_port $SHIM_MUSESS_PORT && wait_port $SHIM_SS_PORT \
      && wait_port $SOCKS_STOCK && wait_port $SOCKS_MUX && wait_port $SOCKS_MUXFEC && wait_port $SOCKS_SS \
      || { tail -n 20 "$WORK"/*-$setting.log; exit 2; }
  fi
  echo "setting $setting up: clients stock=$SOCKS_STOCK mux=$SOCKS_MUX muxfec=$SOCKS_MUXFEC ss=$SOCKS_SS"

  # Warm the mux sessions (ttfb workload doubles as the warm-up:
  # the session is established by the first 1 MiB transfer).
  for rep in 1 2 3; do
    run_bulk direct direct 1048576 "$setting" "$rep"
    run_bulk ss2022 $SOCKS_SS 1048576 "$setting" "$rep"
    run_bulk stock $SOCKS_STOCK 1048576 "$setting" "$rep"
    run_bulk mux $SOCKS_MUX 1048576 "$setting" "$rep"
    run_bulk muxfec $SOCKS_MUXFEC 1048576 "$setting" "$rep"
    run_ttfb_https direct "$setting" "$rep" --noproxy '*'
    run_ttfb_https ss2022 "$setting" "$rep" --socks5 127.0.0.1:$SOCKS_SS
    run_ttfb_https stock "$setting" "$rep" --socks5 127.0.0.1:$SOCKS_STOCK
    run_ttfb_https mux "$setting" "$rep" --socks5 127.0.0.1:$SOCKS_MUX
    run_ttfb_https muxfec "$setting" "$rep" --socks5 127.0.0.1:$SOCKS_MUXFEC
  done

  # Latency sanity: in a delay setting the musess TTFB median must
  # exceed the one-way shim delay — otherwise the shim was not in
  # the path and the setting's numbers are void.
  if [ "$DELAY_MS" -gt 0 ]; then
    for leg in stock mux muxfec; do
      [ -s "$WORK/ttfb-$setting-$leg.txt" ] || { echo "shim sanity: setting=$setting leg=$leg has no TTFB samples — cannot verify shim in path"; continue; }
      med=$(median $(cat "$WORK/ttfb-$setting-$leg.txt" 2>/dev/null))
      med_ms=$(python3 -c "print(f'{float(\"$med\")*1000:.0f}')")
      if [ "$med_ms" -gt "$DELAY_MS" ]; then
        echo "shim sanity: setting=$setting leg=$leg ttfb_median=${med}s (${med_ms}ms) > one-way delay ${DELAY_MS}ms — shim in path OK"
      else
        echo "SHIM SANITY FAIL: setting=$setting leg=$leg ttfb_median=${med}s (${med_ms}ms) <= delay ${DELAY_MS}ms — NUMBERS FOR THIS SETTING ARE VOID"
        record "setting=$setting SHIM_SANITY_FAIL leg=$leg ttfb_median=$med delay_ms=$DELAY_MS"
      fi
    done
  fi

  for rep in 1 2 3; do
    run_bulk direct direct 33554432 "$setting" "$rep"
    run_bulk ss2022 $SOCKS_SS 33554432 "$setting" "$rep"
    run_bulk stock $SOCKS_STOCK 33554432 "$setting" "$rep"
    run_bulk mux $SOCKS_MUX 33554432 "$setting" "$rep"
    run_bulk muxfec $SOCKS_MUXFEC 33554432 "$setting" "$rep"
  done

  for rep in 1 2 3; do
    run_bulk direct direct 268435456 "$setting" "$rep"
    run_bulk ss2022 $SOCKS_SS 268435456 "$setting" "$rep"
    run_bulk stock $SOCKS_STOCK 268435456 "$setting" "$rep"
    run_bulk mux $SOCKS_MUX 268435456 "$setting" "$rep"
    run_bulk muxfec $SOCKS_MUXFEC 268435456 "$setting" "$rep"
  done

  # seq10 warm (sessions already warm from the ttfb/bulk runs above)
  for rep in 1 2 3; do
    run_seq10 direct direct "$setting" "$rep"
    run_seq10 ss2022 $SOCKS_SS "$setting" "$rep"
    run_seq10 stock $SOCKS_STOCK "$setting" "$rep"
    run_seq10 mux $SOCKS_MUX "$setting" "$rep"
    run_seq10 muxfec $SOCKS_MUXFEC "$setting" "$rep"
  done

  # seq10 cold: stop all setting clients, reboot them, and run
  # cold seq10 for the three musess legs first (before any other
  # transfer warms them). ss2022 has no session to warm, so its
  # warm numbers are its cold numbers.
  stop_setting
  if [ "$setting" = none ]; then
    "$BIN" run -c "$WM/client-stock-direct.json" > "$WORK/client-stock-$setting-cold.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-mux-direct.json" > "$WORK/client-mux-$setting-cold.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-muxfec-direct.json" > "$WORK/client-muxfec-$setting-cold.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WS/client-direct.json" > "$WORK/ss-client-$setting-cold.log" 2>&1 &
    SETTING_PIDS+=($!)
    DIRECT_ADDR="127.0.0.1:$BULK_PORT"
  else
    "$HELPER" shim -listen 127.0.0.1:$SHIM_DIRECT_PORT -target 127.0.0.1:$BULK_PORT \
      "${SHIM_ARGS[@]}" > "$WORK/shim-direct-$setting-cold.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$HELPER" shim -listen 127.0.0.1:$SHIM_MUSESS_PORT -target 127.0.0.1:$MUSESS_PORT \
      "${SHIM_ARGS[@]}" > "$WORK/shim-musess-$setting-cold.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$HELPER" shim -listen 127.0.0.1:$SHIM_SS_PORT -target 127.0.0.1:$SS_PORT \
      "${SHIM_ARGS[@]}" > "$WORK/shim-ss-$setting-cold.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-stock-shim.json" > "$WORK/client-stock-$setting-cold.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-mux-shim.json" > "$WORK/client-mux-$setting-cold.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-muxfec-shim.json" > "$WORK/client-muxfec-$setting-cold.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WS/client-shim.json" > "$WORK/ss-client-$setting-cold.log" 2>&1 &
    SETTING_PIDS+=($!)
    DIRECT_ADDR="127.0.0.1:$SHIM_DIRECT_PORT"
  fi
  if [ "$setting" != none ]; then
    wait_port $SHIM_DIRECT_PORT && wait_port $SHIM_MUSESS_PORT && wait_port $SHIM_SS_PORT \
      || { tail -n 20 "$WORK"/*-$setting-cold.log; exit 2; }
  fi
  wait_port $SOCKS_STOCK && wait_port $SOCKS_MUX && wait_port $SOCKS_MUXFEC && wait_port $SOCKS_SS \
    || { tail -n 20 "$WORK"/*-$setting-cold.log; exit 2; }
  for rep in 1 2 3; do
    # Cold = first transfer after boot: reboot the musess clients
    # before each cold rep (ss2022 has no session to warm).
    if [ "$rep" -gt 1 ]; then
      pkill -f "run -c $WM/client-" 2>/dev/null || true
      # Wait until the SOCKS ports are actually free: a new client
      # that binds while the old one still holds the port exits,
      # and wait_port would then time out on a dead client.
      for _ in $(seq 1 25); do
        if ! ss -ltn 2>/dev/null | grep -q ":$SOCKS_STOCK\b" \
          && ! ss -ltn 2>/dev/null | grep -q ":$SOCKS_MUX\b" \
          && ! ss -ltn 2>/dev/null | grep -q ":$SOCKS_MUXFEC\b"; then break; fi
        sleep 0.2
      done
      if [ "$setting" = none ]; then
        "$BIN" run -c "$WM/client-stock-direct.json" > "$WORK/client-stock-$setting-cold.log" 2>&1 &
        SETTING_PIDS+=($!)
        "$BIN" run -c "$WM/client-mux-direct.json" > "$WORK/client-mux-$setting-cold.log" 2>&1 &
        SETTING_PIDS+=($!)
        "$BIN" run -c "$WM/client-muxfec-direct.json" > "$WORK/client-muxfec-$setting-cold.log" 2>&1 &
        SETTING_PIDS+=($!)
      else
        "$BIN" run -c "$WM/client-stock-shim.json" > "$WORK/client-stock-$setting-cold.log" 2>&1 &
        SETTING_PIDS+=($!)
        "$BIN" run -c "$WM/client-mux-shim.json" > "$WORK/client-mux-$setting-cold.log" 2>&1 &
        SETTING_PIDS+=($!)
        "$BIN" run -c "$WM/client-muxfec-shim.json" > "$WORK/client-muxfec-$setting-cold.log" 2>&1 &
        SETTING_PIDS+=($!)
      fi
      wait_port $SOCKS_STOCK && wait_port $SOCKS_MUX && wait_port $SOCKS_MUXFEC || exit 2
    fi
    # NOTE: record cold under workload=seq10cold.
    for leg in stock mux muxfec; do
      case $leg in
        stock) PORT=$SOCKS_STOCK;; mux) PORT=$SOCKS_MUX;; muxfec) PORT=$SOCKS_MUXFEC;;
      esac
      total=0; per=()
      for i in $(seq 1 10); do
        out=$(timeout 60 "$HELPER" bulkclient -bytes 1048576 -socks "127.0.0.1:$PORT" -addr "127.0.0.1:$BULK_PORT" 2>&1); rc=$?
        if [ $rc -ne 0 ]; then record "setting=$setting leg=$leg workload=seq10cold rep=$rep FAILED transfer $i rc=$rc: $out"; break; fi
        s=$(printf '%s\n' "$out" | sed -n 's/.*seconds=\([0-9.]*\).*/\1/p')
        per+=("$s"); total=$(python3 -c "print(f'{$total + float(\"$s\"):.3f}')")
      done
      eff=$(python3 -c "print(f'{10*1048576*8/float(\"$total\")/1e6:.2f}')")
      record "setting=$setting leg=$leg workload=seq10cold rep=$rep seconds=$total mbps=$eff per_transfer=${per[*]}"
    done
  done

  # Mixed load (flow-control decoupling), only where it matters:
  # delay100 and loss25. bulk32 with a stalled sibling stream.
  case $setting in
    delay100|loss25)
      for rep in 1 2 3; do
        for leg in stock mux; do
          case $leg in stock) PORT=$SOCKS_STOCK;; mux) PORT=$SOCKS_MUX;; esac
          "$HELPER" stallclient -socks "127.0.0.1:$PORT" -addr "127.0.0.1:$BULK_PORT" \
            -read-bytes 1024 -hold-seconds 30 > "$WORK/stall-$setting-$leg-$rep.log" 2>&1 &
          STALL_PID=$!
          sleep 1
          if ! kill -0 $STALL_PID 2>/dev/null; then
            record "setting=$setting leg=$leg workload=mixed rep=$rep FAILED stallclient died: $(cat "$WORK/stall-$setting-$leg-$rep.log")"
          else
            out=$(timeout 90 "$HELPER" bulkclient -bytes 33554432 -socks "127.0.0.1:$PORT" -addr "127.0.0.1:$BULK_PORT" 2>&1); rc=$?
            if [ $rc -ne 0 ]; then
              record "setting=$setting leg=$leg workload=mixed rep=$rep FAILED rc=$rc: $out"
            else
              s=$(printf '%s\n' "$out" | sed -n 's/.*seconds=\([0-9.]*\).*/\1/p')
              m=$(printf '%s\n' "$out" | sed -n 's/.*mbps=\([0-9.]*\).*/\1/p')
              record "setting=$setting leg=$leg workload=mixed rep=$rep seconds=$s mbps=$m (sibling stream stalled)"
            fi
          fi
          kill $STALL_PID 2>/dev/null; wait $STALL_PID 2>/dev/null
        done
      done
      ;;
  esac

  # Loss legs: progress-tracked bulk32 for the no-progress stall metric.
  case $setting in
    loss25|loss100)
      for rep in 1 2 3; do
        for leg in stock mux muxfec ss2022; do
          case $leg in
            stock) PORT=$SOCKS_STOCK;; mux) PORT=$SOCKS_MUX;; muxfec) PORT=$SOCKS_MUXFEC;; ss2022) PORT=$SOCKS_SS;;
          esac
          run_bulk "$leg" "$PORT" 33554432 "$setting" "lossprog-$rep" "$WORK/progress-$setting-$leg-$rep.txt"
        done
      done
      ;;
  esac

  # Shim exit proof: bytes forwarded per shim (must be > 0).
  stop_setting
  if [ "$setting" != none ]; then
    for s in direct musess ss; do
      echo "shim-$s exit: $(grep -h 'shim exit:' "$WORK/shim-$s-$setting.log" "$WORK/shim-$s-$setting-cold.log" 2>/dev/null | tail -2 | tr '\n' ' ')"
    done
  fi
done

echo "bench done (workdir kept at $WORK for logs)"
echo "results: $RESULTS"
wc -l "$RESULTS"
