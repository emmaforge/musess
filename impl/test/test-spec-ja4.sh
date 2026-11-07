#!/usr/bin/env bash
# musess direction-5 JA4 check: the outer ClientHello must be
# byte-identical (JA4) to the M1 baseline for every switch combo.
#
# Baseline set (from the M1 JA4 measurement; the two values differ
# only in extension count 16 vs 17 — uTLS GREASE varies per
# handshake, and both values occur in stock Chrome parrots too):
#   t13d0f10h2_8daaf6152771_36142f6fd6ef_0e284abb3885
#   t13d0f11h2_8daaf6152771_2d0528ac8a1e_0e284abb3885
# Every captured ClientHello's JA4 must be a member of this set.
#
# Method: capture-relay.py records the client->server stream; a
# small python splitter (using ja4.py's parser) extracts EVERY
# ClientHello in the capture and prints its JA4. The race combo
# sends two hellos (both through the relay); both must be in the set.
# All ports are the +300 offsets; the relay is restarted per combo
# for a clean capture file.
set -u
cd "$(dirname "$0")"
TESTDIR=$(pwd)
IMPLDIR=$(dirname "$TESTDIR")
TMPROOT="$IMPLDIR/.tmp"
mkdir -p "$TMPROOT"
WORK=$(mktemp -d "$TMPROOT/ja4spec-XXXXXX")
echo "workdir: $WORK"

export GOTOOLCHAIN=local TMPDIR="$TMPROOT"
GO="$HOME/workspace/go-1.24.7/bin/go"
[ -x "$GO" ] || GO="$(command -v go || true)"
BIN="$TMPROOT/sing-box-musess"
[ -x "$BIN" ] || { echo "FATAL: binary not found at $BIN"; exit 2; }
echo "binary: $($BIN version | head -1)"
(cd helper && "$GO" build -o "$WORK/helper" .) || { echo "FATAL: helper build failed"; exit 2; }
HELPER="$WORK/helper"

DEST_PORT=18743
MUSESS_PORT=14743
RELAY_PORT=15743
SOCKS=11380

for p in $DEST_PORT $MUSESS_PORT $RELAY_PORT $SOCKS; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
    echo "PREFLIGHT-FAIL: port $p occupied:"; ss -ltnp 2>/dev/null | grep ":$p " || true; exit 2
  fi
done
echo "preflight: offset ports free"

WM="$WORK/musess"; mkdir -p "$WM"
cd "$WM"
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 2 -nodes \
  -subj "/CN=musess-spec-ja4-ca" >/dev/null 2>&1
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
python3 - "$WM/server.json" "$MUSESS_PORT" "$DEST_PORT" <<'EOF'
import json, sys
p = sys.argv[1]
cfg = json.load(open(p))
for ib in cfg["inbounds"]:
    if ib["type"] == "musess":
        ib["zero_rtt"] = True
        # Template hardcodes listen_port 14443 (project default);
        # override to the +300 offset so this line never binds it.
        ib["listen_port"] = int(sys.argv[2])
        # Template hardcodes dest_port 18443; the dest stand-in
        # here listens on the offset port.
        ib["dest_port"] = int(sys.argv[3])
json.dump(cfg, open(p, "w"), indent=2)
EOF
python3 - "$WM/server.json" "$MUSESS_PORT" "$DEST_PORT" <<'EOF'
import json, sys
ib = json.load(open(sys.argv[1]))["inbounds"][0]
assert ib["listen_port"] == int(sys.argv[2]), f"musess server listen_port {ib['listen_port']} != {sys.argv[2]}"
assert ib["dest_port"] == int(sys.argv[3]), f"musess server dest_port {ib['dest_port']} != {sys.argv[3]}"
print(f"config-port assertion: musess server={ib['listen_port']} dest_port={ib['dest_port']} (offsets, not defaults)")
EOF

mkclient() { # $1=outfile $2=extra
  sed -e "s|__SERVER_PORT__|$RELAY_PORT|g" -e "s|__SERVER_PUBLIC_KEY__|$SERVER_PUBLIC|g" \
    "$TESTDIR/client.json" > "$1"
  python3 - "$1" "$2" <<'EOF'
import json, sys
path, extra = sys.argv[1], sys.argv[2]
cfg = json.load(open(path))
cfg["inbounds"][0]["listen_port"] = 11380
for ob in cfg["outbounds"]:
    if ob["type"] == "musess":
        if extra == "warm":
            ob["warm_pool"] = 2
            ob["warm_pool_idle_seconds"] = 30
        elif extra == "zrt":
            ob["zero_rtt"] = True
        elif extra == "race":
            ob["race_servers"] = ["127.0.0.1:15743"]
        elif extra == "all":
            ob["warm_pool"] = 2
            ob["warm_pool_idle_seconds"] = 30
            ob["zero_rtt"] = True
            ob["race_servers"] = ["127.0.0.1:15743"]
json.dump(cfg, open(path, "w"), indent=2)
EOF
}
mkclient "$WM/client-base.json" base
mkclient "$WM/client-warm.json" warm
mkclient "$WM/client-zrt.json" zrt
mkclient "$WM/client-race.json" race
mkclient "$WM/client-all.json" all
for cfg in "$WM/server.json" "$WM"/client-*.json; do
  "$BIN" check -c "$cfg" >/dev/null || { echo "FATAL: config check failed: $cfg"; exit 2; }
done
echo "all configs: OK"

PIDS=()
cleanup() { for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done; }
trap cleanup EXIT
wait_port() {
  for _ in $(seq 1 75); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 0.2
  done
  echo "FATAL: port $1 never came up"; return 1
}

"$HELPER" dest -addr 127.0.0.1:$DEST_PORT -cert "$WM/dest.pem" -key "$WM/dest-key.pem" \
  -body "$WM/body.txt" -sidlog "$WM/dest-sids.log" > "$WORK/dest.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WM/server.json" > "$WORK/musess-server.log" 2>&1 &
PIDS+=($!)
wait_port $DEST_PORT && wait_port $MUSESS_PORT || { tail -n 20 "$WORK"/*.log; exit 2; }
echo "servers up"

BASELINE="t13d0f10h2_8daaf6152771_36142f6fd6ef_0e284abb3885 t13d0f11h2_8daaf6152771_2d0528ac8a1e_0e284abb3885"
OVERALL=0
for combo in base warm zrt race all; do
  rm -f "$WORK/relay-c2s.bin" "$WORK/relay-s2c.bin"
  python3 ~/workspace/musess/capture-relay.py $RELAY_PORT $MUSESS_PORT \
    "$WORK/relay-c2s.bin" "$WORK/relay-s2c.bin" > "$WORK/relay-$combo.log" 2>&1 &
  RELAY_PID=$!
  "$BIN" run -c "$WM/client-$combo.json" > "$WORK/client-$combo.log" 2>&1 &
  CLIENT_PID=$!
  wait_port $RELAY_PORT && wait_port $SOCKS || { echo "combo=$combo ports failed"; OVERALL=1; kill $RELAY_PID $CLIENT_PID 2>/dev/null; continue; }
  case "$combo" in warm|all) sleep 2;; esac
  BODY=$(curl -s --max-time 15 --socks5-hostname 127.0.0.1:$SOCKS --cacert "$WM/ca.pem" --resolve dest.test:$DEST_PORT:127.0.0.1 https://dest.test:$DEST_PORT/)
  [ "$BODY" = "$TOKEN" ] && echo "combo=$combo tunnel fetch: OK" || { echo "combo=$combo tunnel fetch: FAIL"; OVERALL=1; }
  sleep 1
  kill $CLIENT_PID $RELAY_PID 2>/dev/null; wait $CLIENT_PID 2>/dev/null; wait $RELAY_PID 2>/dev/null
  python3 - "$WORK/relay-c2s.bin" "$BASELINE" "$combo" <<'EOF'
import sys
sys.path.insert(0, "/home/hatch/workspace/musess")
from ja4 import parse_client_hello, ja4

path, baseline, combo = sys.argv[1], set(sys.argv[2].split()), sys.argv[3]
data = open(path, "rb").read()
# Split the stream into TLS records; each ClientHello (handshake
# type 0x01) is fingerprinted on its own.
hellos, off = [], 0
while off + 5 <= len(data):
    if data[off] != 0x16:
        break
    ln = int.from_bytes(data[off+3:off+5], "big")
    rec = data[off:off+5+ln]
    if len(rec) >= 6 and rec[5] == 0x01:
        hellos.append(rec)
    off += 5 + ln
print(f"combo={combo}: {len(hellos)} ClientHello(s) in capture")
ok = True
for i, h in enumerate(hellos):
    try:
        fp = ja4(parse_client_hello(h))
    except Exception as e:
        print(f"combo={combo} hello#{i}: PARSE-FAIL {e}"); ok = False; continue
    mark = "OK" if fp in baseline else "MISMATCH"
    if fp not in baseline:
        ok = False
    print(f"combo={combo} hello#{i}: JA4={fp} {mark}")
if not hellos:
    ok = False
print(f"combo={combo}: {'PASS' if ok else 'FAIL'}")
sys.exit(0 if ok else 1)
EOF
  [ $? -ne 0 ] && OVERALL=1
done

[ "$OVERALL" = 0 ] && echo "JA4: ALL COMBOS PASS (every hello in baseline set)" || echo "JA4: FAILURES PRESENT"
echo "ja4 check done (workdir kept at $WORK)"
exit $OVERALL
