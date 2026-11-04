#!/usr/bin/env bash
# musess milestone-2 FEC end-to-end test.
#
# Verifies the negotiated FEC data plane in the real binary:
#   (f1) both peers fec=auto: a 1MiB fetch through the tunnel is
#        byte-identical to the destination body
#   (f2) the negotiation actually happened (log markers on both
#        sides — a silently declined FEC must not pass as success)
#   (f3) a UDP probe is carried through the FEC packet plane to
#        the echo server (echo server log is the proof; the final
#        stock-socks hop back is blocked by this sandbox's UDP
#        policy — see run-e2e.sh's note on check (d))
#   (f4) server fec=off + client fec=auto: fetch still works over
#        plain framing and the client logs the decline
#   (f5) 1MiB fetch through a delay+hold shim between the two
#        sing-boxen, FEC on vs off (correctness under impairment)
#
# Ports are offset from run-e2e.sh so both can run in one checkout.
set -u
cd "$(dirname "$0")"
TESTDIR=$(pwd)
IMPLDIR=$(dirname "$TESTDIR")
TMPROOT="$IMPLDIR/.tmp"
mkdir -p "$TMPROOT"
WORK=$(mktemp -d "$TMPROOT/e2e-fec-XXXXXX")
echo "workdir: $WORK"

export GOTOOLCHAIN=local TMPDIR="$TMPROOT"
GO=""
for cand in /home/hatch/workspace/.go-tmp/go/bin/go "$(command -v go || true)"; do
  if [ -n "$cand" ] && [ -x "$cand" ]; then GO="$cand"; break; fi
done
if [ -z "$GO" ]; then echo "FATAL: no go toolchain found"; exit 2; fi
BIN="$TMPROOT/sing-box-musess"
if [ ! -x "$BIN" ]; then echo "FATAL: binary $BIN missing (build it per impl/README.md)"; exit 2; fi
echo "binary: $($BIN version | head -1)"
(cd helper && "$GO" build -o "$WORK/helper" .) || { echo "FATAL: helper build failed"; exit 2; }

# --- certificates (same fixture pattern as run-e2e.sh) ----------------------
cd "$WORK"
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 2 -nodes \
  -subj "/CN=musess-test-ca" >/dev/null 2>&1
for name in dest server-local; do
  openssl req -newkey rsa:2048 -keyout "$name-key.pem" -out "$name.csr" -nodes \
    -subj "/CN=dest.test" >/dev/null 2>&1
  printf "subjectAltName=DNS:dest.test,IP:127.0.0.1\n" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "$name.pem" -days 2 -extfile "$name.ext" >/dev/null 2>&1
done

# 1MiB body: repeated token lines (compressible patterns would hide
# corruption less well than random data, so use /dev/urandom output
# with a token trailer; cmp does the verification).
head -c 1048576 /dev/urandom > body.bin
TOKEN="MUSESS-FEC-OK-$(date +%s)"
printf '%s' "$TOKEN" >> body.bin

KEYS=$("$WORK/helper" keygen)
SERVER_PRIVATE=$(printf '%s\n' "$KEYS" | sed -n 's/^private=//p')
SERVER_PUBLIC=$(printf '%s\n' "$KEYS" | sed -n 's/^public=//p')

mkconfigs() { # $1 = server fec mode ("" for off), $2 = client fec mode
  sed -e "s|__WORKDIR__|$WORK|g" -e "s|__SERVER_PRIVATE_KEY__|$SERVER_PRIVATE|g" \
    -e "s|14443|14444|g" -e "s|18443|18444|g" "$TESTDIR/server.json" > "$WORK/server.json"
  sed -e "s|__SERVER_PORT__|14444|g" -e "s|__SERVER_PUBLIC_KEY__|$SERVER_PUBLIC|g" \
    -e "s|11080|11082|g" "$TESTDIR/client.json" > "$WORK/client.json"
  if [ -n "$1" ]; then
    sed -i "s|\"tag\": \"musess-in\"|\"fec\": \"$1\", \"tag\": \"musess-in\"|" "$WORK/server.json"
  fi
  if [ -n "$2" ]; then
    sed -i "s|\"tag\": \"musess-out\"|\"fec\": \"$2\", \"tag\": \"musess-out\"|" "$WORK/client.json"
  fi
  "$BIN" check -c "$WORK/server.json" >/dev/null && "$BIN" check -c "$WORK/client.json" >/dev/null \
    || { echo "FATAL: config check failed (server fec='$1' client fec='$2')"; exit 2; }
}

PIDS=()      # long-lived fixtures (dest, udpecho)
PAIR_PIDS=() # per-phase sing-box pairs
cleanup() { for pid in "${PAIR_PIDS[@]:-} ${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done; }
trap cleanup EXIT
wait_port() {
  for _ in $(seq 1 75); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 0.2
  done
  echo "FATAL: port $1 never came up"; return 1
}
PASS=0; FAIL=0
report() { if [ "$2" -eq 0 ]; then echo "PASS: $1"; PASS=$((PASS+1)); else echo "FAIL: $1"; FAIL=$((FAIL+1)); fi; }

start_pair() { # $1 = phase tag
  "$BIN" run -c "$WORK/server.json" > "$WORK/server-$1.log" 2>&1 &
  PAIR_PIDS+=($!)
  "$BIN" run -c "$WORK/client.json" > "$WORK/client-$1.log" 2>&1 &
  PAIR_PIDS+=($!)
  wait_port 14444 && wait_port 11082 || { tail -n 20 "$WORK"/*.log; exit 2; }
}
stop_pair() {
  for pid in "${PAIR_PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  PAIR_PIDS=()
  sleep 0.5
}

"$WORK/helper" dest -addr 127.0.0.1:18444 -cert "$WORK/dest.pem" -key "$WORK/dest-key.pem" \
  -body "$WORK/body.bin" -sidlog "$WORK/dest-sids.log" > "$WORK/dest.log" 2>&1 &
PIDS_DEST=$!
"$WORK/helper" udpecho -addr 127.0.0.1:15354 > "$WORK/udpecho.log" 2>&1 &
PIDS+=($PIDS_DEST $!)

# --- phase 1: FEC auto on both sides ----------------------------------------
mkconfigs auto auto
start_pair p1
wait_port 18444 || exit 2
curl -s --max-time 30 --socks5-hostname 127.0.0.1:11082 --cacert "$WORK/ca.pem" \
  -o "$WORK/fetched-p1.bin" https://dest.test:18444/
cmp -s "$WORK/fetched-p1.bin" "$WORK/body.bin"; report "(f1) 1MiB fetch through FEC tunnel is byte-identical" $?
grep -q "FEC negotiated with server" "$WORK/client-p1.log" && grep -q "FEC duplex active" "$WORK/server-p1.log"
report "(f2) FEC negotiation markers present in client and server logs" $?
"$WORK/helper" udpclient -socks 127.0.0.1:11082 -echo 127.0.0.1:15354 > "$WORK/udpclient-p1.log" 2>&1
sleep 0.5
grep -q "musess-udp-probe" "$WORK/udpecho.log"; report "(f3) UDP probe carried through FEC packet plane to echo server" $?
if grep -q "UDP TEST PASS" "$WORK/udpclient-p1.log"; then
  echo "note: (f3) full UDP round trip also passed in this environment"
else
  echo "note: (f3) full UDP round trip blocked at the final stock-socks hop by this sandbox's UDP policy (same as milestone-1 check (d)); tunnel carriage is proven by the echo server log"
fi
stop_pair

# --- phase 2: server declines ------------------------------------------------
mkconfigs "" auto
start_pair p2
curl -s --max-time 30 --socks5-hostname 127.0.0.1:11082 --cacert "$WORK/ca.pem" \
  -o "$WORK/fetched-p2.bin" https://dest.test:18444/
cmp -s "$WORK/fetched-p2.bin" "$WORK/body.bin" && grep -q "server declined FEC" "$WORK/client-p2.log"
report "(f4) fetch works over plain framing when the server declines FEC" $?
stop_pair

# --- phase 3: fetch through delay+hold shim, FEC on vs off -------------------
# The shim sits between the client and server sing-boxen (delay
# 25ms + 5% x 60ms stalls per direction — a delay/hold model, NOT
# packet loss; see bench-e2e.sh). This asserts the FEC record
# layer survives a stalled, high-RTT path end to end. Bulk
# throughput numbers live in bench-e2e.sh and the fec package
# harness (impl/README.md).
run_shimmed() { # $1 = server fec, $2 = client fec, $3 = tag
  mkconfigs "$1" "$2"
  sed -i "s|\"server_port\": 14444|\"server_port\": 16444|" "$WORK/client.json"
  "$WORK/helper" shim -listen 127.0.0.1:16444 -target 127.0.0.1:14444 \
    -delay-ms 25 -hold-prob 0.05 -hold-ms 60 > "$WORK/shim-$3.log" 2>&1 &
  local shim_pid=$!
  start_pair "shim-$3"
  curl -s --max-time 60 --socks5-hostname 127.0.0.1:11082 --cacert "$WORK/ca.pem" \
    -o "$WORK/fetched-shim-$3.bin" https://dest.test:18444/
  cmp -s "$WORK/fetched-shim-$3.bin" "$WORK/body.bin"
  report "(f5-$3) 1MiB fetch through delay+hold shim (server fec='$1' client fec='$2')" $?
  stop_pair
  kill "$shim_pid" 2>/dev/null
  sleep 0.3
}
run_shimmed auto auto on
run_shimmed "" "" off

echo "=================================================="
echo "fec e2e summary: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "ALL CHECKS PASSED" || exit 1
