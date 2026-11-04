#!/usr/bin/env bash
# musess milestone-1 end-to-end test.
#
# Topology (all on 127.0.0.1):
#   dest stand-in (HTTPS, :18443)  <- the "borrowed destination"
#   sing-box server (musess inbound :14443, direct outbound)
#   sing-box client (socks inbound :11080, musess outbound)
#   sniff relay (:15443 -> :14443) + second client (socks :11081) for capture
#   UDP echo (:15353) for the UDP relay smoke test
#
# Checks:
#   (a) fetch through the tunnel via the client's SOCKS port
#   (b) unauthenticated fetch direct to the server port gets the genuine dest
#   (c) replayed captured ClientHello is treated as unauthenticated (forwarded)
#   (d) UDP packet relay through the tunnel (smoke test)
set -u
cd "$(dirname "$0")"
TESTDIR=$(pwd)
IMPLDIR=$(dirname "$TESTDIR")
TMPROOT="$IMPLDIR/.tmp"
mkdir -p "$TMPROOT"
WORK=$(mktemp -d "$TMPROOT/e2e-XXXXXX")
echo "workdir: $WORK"

# --- toolchain -------------------------------------------------------------
export GOTOOLCHAIN=local TMPDIR="$TMPROOT"
GO=""
for cand in /home/hatch/workspace/.go-tmp/go/bin/go "$(command -v go || true)"; do
  if [ -n "$cand" ] && [ -x "$cand" ]; then GO="$cand"; break; fi
done
if [ -z "$GO" ]; then echo "FATAL: no go toolchain found"; exit 2; fi
echo "go: $($GO version)"

BIN="$TMPROOT/sing-box-musess"
if [ ! -x "$BIN" ]; then
  echo "building sing-box (musess)..."
  (cd "$IMPLDIR/sing-box" && "$GO" build -trimpath \
    -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=1.14.0-alpha.2-musess-m1' $(cat release/LDFLAGS) -s -w -buildid=" \
    -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" \
    -o "$BIN" ./cmd/sing-box) || { echo "FATAL: sing-box build failed"; exit 2; }
fi
echo "binary: $($BIN version | head -1)"

(cd helper && "$GO" build -o "$WORK/helper" .) || { echo "FATAL: helper build failed"; exit 2; }

# --- certificates ----------------------------------------------------------
# One throwaway CA signs two DIFFERENT certificates for the same name
# dest.test: the destination's own and the musess server's local one.
# Check (b) distinguishes them by fingerprint.
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
echo "dest cert fingerprint:         $(openssl x509 -in dest.pem -noout -fingerprint -sha256)"
echo "server-local cert fingerprint: $(openssl x509 -in server-local.pem -noout -fingerprint -sha256)"

TOKEN="MUSESS-DEST-OK-$(date +%s)"
printf '%s' "$TOKEN" > body.txt

# --- keys and configs ------------------------------------------------------
KEYS=$("$WORK/helper" keygen)
SERVER_PRIVATE=$(printf '%s\n' "$KEYS" | sed -n 's/^private=//p')
SERVER_PUBLIC=$(printf '%s\n' "$KEYS" | sed -n 's/^public=//p')
echo "server public key: $SERVER_PUBLIC"

sed -e "s|__WORKDIR__|$WORK|g" -e "s|__SERVER_PRIVATE_KEY__|$SERVER_PRIVATE|g" \
  "$TESTDIR/server.json" > "$WORK/server.json"
sed -e "s|__SERVER_PORT__|14443|g" -e "s|__SERVER_PUBLIC_KEY__|$SERVER_PUBLIC|g" \
  "$TESTDIR/client.json" > "$WORK/client.json"
sed -e "s|__SERVER_PORT__|15443|g" -e "s|__SERVER_PUBLIC_KEY__|$SERVER_PUBLIC|g" \
  -e "s|11080|11081|g" "$TESTDIR/client.json" > "$WORK/client-capture.json"

"$BIN" check -c "$WORK/server.json" && echo "server config: OK"
"$BIN" check -c "$WORK/client.json" && echo "client config: OK"

# --- start services --------------------------------------------------------
PIDS=()
cleanup() { for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done; }
trap cleanup EXIT

"$WORK/helper" dest -addr 127.0.0.1:18443 -cert "$WORK/dest.pem" -key "$WORK/dest-key.pem" \
  -body "$WORK/body.txt" -sidlog "$WORK/dest-sids.log" > "$WORK/dest.log" 2>&1 &
PIDS+=($!)
"$WORK/helper" udpecho -addr 127.0.0.1:15353 > "$WORK/udpecho.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WORK/server.json" > "$WORK/server.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WORK/client.json" > "$WORK/client.log" 2>&1 &
PIDS+=($!)

wait_port() {
  for _ in $(seq 1 75); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 0.2
  done
  echo "FATAL: port $1 never came up"; return 1
}
wait_port 18443 && wait_port 14443 && wait_port 11080 || { tail -n 20 "$WORK"/*.log; exit 2; }
echo "all services up"

PASS=0; FAIL=0
report() { # $1 = label, $2 = 0 ok
  if [ "$2" -eq 0 ]; then echo "PASS: $1"; PASS=$((PASS+1)); else echo "FAIL: $1"; FAIL=$((FAIL+1)); fi
}

# --- check (a): through the tunnel -----------------------------------------
BODY_A=$(curl -s --max-time 15 --socks5-hostname 127.0.0.1:11080 --cacert "$WORK/ca.pem" https://dest.test:18443/)
echo "(a) body via tunnel: $BODY_A"
[ "$BODY_A" = "$TOKEN" ]; report "(a) fetch through tunnel via SOCKS returns dest body" $?

# --- check (b): unauthenticated gets the genuine destination ---------------
BODY_B=$(curl -s --noproxy "*" --max-time 15 --cacert "$WORK/ca.pem" --resolve dest.test:14443:127.0.0.1 https://dest.test:14443/)
echo "(b) body direct, no auth: $BODY_B"
[ "$BODY_B" = "$TOKEN" ]; report "(b1) unauthenticated request returns dest body (forwarded)" $?
PRESENTED=$(echo | openssl s_client -connect 127.0.0.1:14443 -servername dest.test -showcerts 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null)
DEST_FP=$(openssl x509 -in "$WORK/dest.pem" -noout -fingerprint -sha256)
echo "(b) presented cert: $PRESENTED"
echo "(b) dest cert:      $DEST_FP"
[ "$PRESENTED" = "$DEST_FP" ]; report "(b2) presented certificate is the genuine destination certificate" $?

# --- check (c): replay is treated as unauthenticated ------------------------
"$WORK/helper" sniff -listen 127.0.0.1:15443 -target 127.0.0.1:14443 \
  -capture "$WORK/capture.bin" > "$WORK/sniff.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WORK/client-capture.json" > "$WORK/client-capture.log" 2>&1 &
PIDS+=($!)
wait_port 15443 && wait_port 11081 || { tail -n 20 "$WORK"/*.log; exit 2; }
BODY_C=$(curl -s --max-time 15 --socks5-hostname 127.0.0.1:11081 --cacert "$WORK/ca.pem" https://dest.test:18443/)
echo "(c) capture-phase body via tunnel: $BODY_C"
[ "$BODY_C" = "$TOKEN" ]; report "(c0) capture-phase tunnel fetch works" $?
sleep 0.5
SID=$("$WORK/helper" sid -file "$WORK/capture.bin")
echo "(c) captured auth session id: $SID"
BEFORE=0; [ -f "$WORK/dest-sids.log" ] && BEFORE=$(grep -c "^$SID\$" "$WORK/dest-sids.log" || true)
echo "(c) dest saw this session id before replay: $BEFORE time(s) (expect 0: original was terminated at the musess server)"
"$WORK/helper" replay -addr 127.0.0.1:14443 -file "$WORK/capture.bin"
sleep 0.5
AFTER=0; [ -f "$WORK/dest-sids.log" ] && AFTER=$(grep -c "^$SID\$" "$WORK/dest-sids.log" || true)
echo "(c) dest saw this session id after replay: $AFTER time(s) (expect >=1: replay was forwarded to dest)"
[ "$BEFORE" -eq 0 ] && [ "$AFTER" -ge 1 ]; report "(c) replayed ClientHello is forwarded to dest, not authenticated" $?

# --- check (d): UDP relay smoke test ---------------------------------------
# NOTE: in the Muse sandbox, sendto() on unconnected UDP sockets is
# rejected with EPERM by the network policy, which breaks the last
# stock-sing-box hop (socks UDP response) regardless of the outbound
# protocol - reproduced with a pure stock socks->direct configuration
# and no musess code involved. The musess tunnel itself was verified
# carrying the probe to the echo server and the reply back into the
# client outbound (see impl/README.md). On an unrestricted network
# this check passes end to end.
"$WORK/helper" udpclient -socks 127.0.0.1:11080 -echo 127.0.0.1:15353; report "(d) UDP packet relay through tunnel" $?

echo "=================================================="
echo "e2e summary: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
  echo "--- server log tail ---"; tail -30 "$WORK/server.log"
  echo "--- client log tail ---"; tail -30 "$WORK/client.log"
  exit 1
fi
echo "ALL CHECKS PASSED"
