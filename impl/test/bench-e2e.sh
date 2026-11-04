#!/usr/bin/env bash
# musess milestone-2 bulk-transfer benchmark.
#
# Legs (all on 127.0.0.1), each measured with a 32 MiB download from a
# bulkserver (helper bulkserver, :19001) via helper bulkclient:
#   direct  - bulkclient -> bulkserver (no proxy)
#   ss2022  - bulkclient -> client sing-box SOCKS :11082 -> shadowsocks
#             2022-blake3-aes-128-gcm -> server sing-box :14446 -> bulkserver
#   musess  - bulkclient -> client sing-box SOCKS :11080 -> musess ->
#             server sing-box :14443 -> bulkserver   (FEC off: the musess
#             configs used here carry no fec option)
#
# Impairment is applied by the user-space helper `shim`, placed between
# the proxy client and the proxy server for the proxied legs (the client
# sing-box is started with a config whose server_port points at the
# shim; the shim forwards to the real server port), and between
# bulkclient and bulkserver for the direct leg.
#
# IMPORTANT - impairment model: the shim is a DELAY/HOLD model, not
# packet loss and not netem (tc/netem is not permitted in this
# sandbox). It never drops, duplicates or reorders bytes. Each read
# chunk is released no earlier than arrival + delay-ms; each chunk
# independently, with probability hold-prob, gets an extra hold-ms on
# its release time, and because chunks are released strictly in order,
# a held chunk stalls the chunks behind it - emulating the
# head-of-line stall a lost segment causes on a TCP byte stream.
# Settings: none | delay 25ms | delay 100ms | delay 25ms + hold-prob
# 0.05 hold-ms 60.
#
# This script builds nothing except the test helper: it requires the
# sing-box binary at impl/.tmp/sing-box-musess (see impl/README.md).
# A leg that takes >90s is killed and reported as stalled.
set -u
cd "$(dirname "$0")"
TESTDIR=$(pwd)
IMPLDIR=$(dirname "$TESTDIR")
TMPROOT="$IMPLDIR/.tmp"
mkdir -p "$TMPROOT"
WORK=$(mktemp -d "$TMPROOT/bench-e2e-XXXXXX")
echo "workdir: $WORK"
echo "impairment: user-space shim, delay/hold model (NOT packet loss)"

export GOTOOLCHAIN=local TMPDIR="$TMPROOT"
export no_proxy='*' NO_PROXY='*'
GO=""
for cand in /home/hatch/workspace/.go-tmp/go/bin/go "$(command -v go || true)"; do
  if [ -n "$cand" ] && [ -x "$cand" ]; then GO="$cand"; break; fi
done
if [ -z "$GO" ]; then echo "FATAL: no go toolchain found (needed to build the test helper)"; exit 2; fi

BIN="$TMPROOT/sing-box-musess"
if [ ! -x "$BIN" ]; then
  echo "FATAL: sing-box binary not found at $BIN"
  echo "Build it first (this script builds nothing); from impl/:"
  echo "  export PATH=/home/hatch/workspace/.go-tmp/go/bin:\$PATH GOTOOLCHAIN=local TMPDIR=\$PWD/.tmp"
  echo "  cd sing-box && go build -trimpath -ldflags \"-X 'github.com/sagernet/sing-box/constant.Version=1.14.0-alpha.2-musess-m1' \$(cat release/LDFLAGS) -s -w -buildid=\" -tags \"\$(cat release/DEFAULT_BUILD_TAGS_OTHERS)\" -o ../.tmp/sing-box-musess ./cmd/sing-box"
  exit 2
fi
echo "binary: $($BIN version | head -1)"

(cd helper && "$GO" build -o "$WORK/helper" .) || { echo "FATAL: helper build failed"; exit 2; }
HELPER="$WORK/helper"

# --- ports -------------------------------------------------------------------
# musess pair reuses the run-e2e.sh ports (server 14443, dest 18443,
# client socks 11080). ss2022 pair, bulkserver and shims use fresh ones.
BULK_PORT=19001
SS_SERVER_PORT=14446
SHIM_DIRECT_PORT=15450   # -> bulkserver 19001
SHIM_MUSESS_PORT=15451   # -> musess server 14443
SHIM_SS_PORT=15452       # -> ss2022 server 14446
BYTES=33554432           # 32 MiB

# --- musess workdir: certs + configs (run-e2e.sh pattern) --------------------
WM="$WORK/musess"; mkdir -p "$WM"
cd "$WM"
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 2 -nodes \
  -subj "/CN=musess-bench-e2e-ca" >/dev/null 2>&1
for name in dest server-local; do
  openssl req -newkey rsa:2048 -keyout "$name-key.pem" -out "$name.csr" -nodes \
    -subj "/CN=dest.test" >/dev/null 2>&1
  printf "subjectAltName=DNS:dest.test,IP:127.0.0.1\n" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "$name.pem" -days 2 -extfile "$name.ext" >/dev/null 2>&1
done
printf 'MUSESS-BENCH-DEST' > body.txt
KEYS=$("$HELPER" keygen)
SERVER_PRIVATE=$(printf '%s\n' "$KEYS" | sed -n 's/^private=//p')
SERVER_PUBLIC=$(printf '%s\n' "$KEYS" | sed -n 's/^public=//p')
sed -e "s|__WORKDIR__|$WM|g" -e "s|__SERVER_PRIVATE_KEY__|$SERVER_PRIVATE|g" \
  "$TESTDIR/server.json" > "$WM/server.json"
sed -e "s|__SERVER_PORT__|14443|g" -e "s|__SERVER_PUBLIC_KEY__|$SERVER_PUBLIC|g" \
  "$TESTDIR/client.json" > "$WM/client-direct.json"
sed -e "s|__SERVER_PORT__|$SHIM_MUSESS_PORT|g" -e "s|__SERVER_PUBLIC_KEY__|$SERVER_PUBLIC|g" \
  "$TESTDIR/client.json" > "$WM/client-shim.json"

# --- ss2022 workdir: configs ---------------------------------------------------
WS="$WORK/ss2022"; mkdir -p "$WS"
cp "$TESTDIR/ss2022-server.json" "$WS/server.json"
sed -e "s|__SERVER_PORT__|$SS_SERVER_PORT|g" "$TESTDIR/ss2022-client.json" > "$WS/client-direct.json"
sed -e "s|__SERVER_PORT__|$SHIM_SS_PORT|g" "$TESTDIR/ss2022-client.json" > "$WS/client-shim.json"

for cfg in "$WM/server.json" "$WM/client-direct.json" "$WM/client-shim.json" \
           "$WS/server.json" "$WS/client-direct.json" "$WS/client-shim.json"; do
  "$BIN" check -c "$cfg" >/dev/null || { echo "FATAL: config check failed: $cfg"; exit 2; }
done
echo "all configs: OK"

# --- process management --------------------------------------------------------
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

# --- long-lived services -------------------------------------------------------
"$HELPER" dest -addr 127.0.0.1:18443 -cert "$WM/dest.pem" -key "$WM/dest-key.pem" \
  -body "$WM/body.txt" -sidlog "$WM/dest-sids.log" > "$WORK/dest.log" 2>&1 &
PIDS+=($!)
"$HELPER" bulkserver -port $BULK_PORT > "$WORK/bulkserver.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WM/server.json" > "$WORK/musess-server.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WS/server.json" > "$WORK/ss-server.log" 2>&1 &
PIDS+=($!)
wait_port 18443 && wait_port $BULK_PORT && wait_port 14443 && wait_port $SS_SERVER_PORT \
  || { tail -n 20 "$WORK"/*.log; exit 2; }
echo "servers up: dest=18443 bulk=$BULK_PORT musess=14443 ss2022=$SS_SERVER_PORT"

run_leg() { # $1=leg $2=shim-desc $3..=bulkclient args
  local leg=$1 desc=$2; shift 2
  local out rc mbps seconds
  out=$(timeout 90 "$HELPER" bulkclient -bytes $BYTES "$@" 2>&1); rc=$?
  if [ $rc -eq 124 ]; then
    echo "leg=$leg shim=$desc mbps=0.00 seconds=90.000 stalled=yes (killed after 90s)"
  elif [ $rc -ne 0 ]; then
    echo "leg=$leg shim=$desc FAILED rc=$rc output: $out"
  else
    mbps=$(printf '%s\n' "$out" | sed -n 's/.*mbps=\([0-9.]*\).*/\1/p')
    seconds=$(printf '%s\n' "$out" | sed -n 's/.*seconds=\([0-9.]*\).*/\1/p')
    echo "leg=$leg shim=$desc mbps=$mbps seconds=$seconds"
  fi
}

# --- settings matrix -------------------------------------------------------------
for setting in none delay25 delay100 delay25hold; do
  case $setting in
    none)        DESC="none";                        SHIM_ARGS=() ;;
    delay25)     DESC="delay25ms";                   SHIM_ARGS=(-delay-ms 25) ;;
    delay100)    DESC="delay100ms";                  SHIM_ARGS=(-delay-ms 100) ;;
    delay25hold) DESC="delay25ms+hold0.05x60ms";     SHIM_ARGS=(-delay-ms 25 -hold-prob 0.05 -hold-ms 60) ;;
  esac

  if [ "$setting" = none ]; then
    "$BIN" run -c "$WM/client-direct.json" > "$WORK/musess-client-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WS/client-direct.json" > "$WORK/ss-client-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    DIRECT_ADDR="127.0.0.1:$BULK_PORT"
    wait_port 11080 && wait_port 11082 || { tail -n 20 "$WORK"/*-$setting.log; exit 2; }
  else
    "$HELPER" shim -listen 127.0.0.1:$SHIM_DIRECT_PORT -target 127.0.0.1:$BULK_PORT \
      "${SHIM_ARGS[@]}" > "$WORK/shim-direct-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$HELPER" shim -listen 127.0.0.1:$SHIM_MUSESS_PORT -target 127.0.0.1:14443 \
      "${SHIM_ARGS[@]}" > "$WORK/shim-musess-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$HELPER" shim -listen 127.0.0.1:$SHIM_SS_PORT -target 127.0.0.1:$SS_SERVER_PORT \
      "${SHIM_ARGS[@]}" > "$WORK/shim-ss-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-shim.json" > "$WORK/musess-client-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WS/client-shim.json" > "$WORK/ss-client-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    DIRECT_ADDR="127.0.0.1:$SHIM_DIRECT_PORT"
    wait_port $SHIM_DIRECT_PORT && wait_port $SHIM_MUSESS_PORT && wait_port $SHIM_SS_PORT \
      && wait_port 11080 && wait_port 11082 || { tail -n 20 "$WORK"/*-$setting.log; exit 2; }
  fi

  run_leg direct "$DESC" -addr "$DIRECT_ADDR"
  run_leg ss2022 "$DESC" -socks 127.0.0.1:11082 -addr "127.0.0.1:$BULK_PORT"
  run_leg musess "$DESC" -socks 127.0.0.1:11080 -addr "127.0.0.1:$BULK_PORT"

  stop_setting
done

echo "bench done (workdir kept at $WORK for logs)"
