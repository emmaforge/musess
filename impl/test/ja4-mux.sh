#!/usr/bin/env bash
# musess mux-landing: JA4 check for mux on/off.
# The mux option must not change the outer ClientHello at all: the
# session handshake is byte-identical to the plain path (same
# command-0x03 request rides *inside* the TLS stream, after the
# handshake). Captures the real end-to-end ClientHello through the
# capture relay for a stock client and a mux client, computes JA4
# with ~/workspace/musess/ja4.py, and compares against the recorded
# baselines:
#   t13d0f10h2_8daaf6152771_36142f6fd6ef_0e284abb3885
#   t13d0f11h2_8daaf6152771_2d0528ac8a1e_0e284abb3885
# (the two values are the GREASE-driven extension-count variants
# of the same stock parrot hello.)
# Ports offset +100. Run sequentially with the bench.
set -u
cd "$(dirname "$0")"
TESTDIR=$(pwd)
IMPLDIR=$(dirname "$TESTDIR")
TMPROOT="$IMPLDIR/.tmp"
mkdir -p "$TMPROOT"
WORK=$(mktemp -d "$TMPROOT/ja4mux-XXXXXX")
echo "workdir: $WORK"

export PATH=$HOME/workspace/go-1.24.7/bin:$PATH GOTOOLCHAIN=local TMPDIR="$TMPROOT"
GO=$(command -v go)
BIN="$TMPROOT/sing-box-musess"
[ -x "$BIN" ] || { echo "FATAL: binary missing, build it first"; exit 2; }
(cd helper && "$GO" build -o "$WORK/helper" .) || exit 2

DEST_PORT=18543
MUSESS_PORT=14543
RELAY_PORT=15566
SOCKS_PORT=11180

echo "--- preflight ---"
# Scoped to this line only (see bench-mux.sh: the VM is shared with
# other musess lines; a bare "sing-box-musess" pkill killed the
# multipath line's processes twice). Kill only the PIDs ss reports
# as owning our ports, and only when their /proc cmdline contains
# this line's workdir (or, for the relay, its port).
clear_my_leftovers() {
  for p in "$@"; do
    for pid in $(ss -ltnp 2>/dev/null | grep ":$p\b" | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | sort -u); do
      cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
      case "$cmd" in
        *mux-landing*) kill "$pid" 2>/dev/null || true ;;
        *capture-relay.py*"$RELAY_PORT"*) kill "$pid" 2>/dev/null || true ;;
      esac
    done
  done
  sleep 1
}
clear_my_leftovers $DEST_PORT $MUSESS_PORT $RELAY_PORT $SOCKS_PORT
for p in $DEST_PORT $MUSESS_PORT $RELAY_PORT $SOCKS_PORT; do
  if ss -ltn 2>/dev/null | grep -q ":$p\b"; then echo "FATAL: port $p still occupied"; exit 2; fi
done
echo "preflight: ports free"

cd "$WORK"
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 2 -nodes -subj "/CN=musess-test-ca" >/dev/null 2>&1
for name in dest server-local; do
  openssl req -newkey rsa:2048 -keyout "$name-key.pem" -out "$name.csr" -nodes -subj "/CN=dest.test" >/dev/null 2>&1
  printf "subjectAltName=DNS:dest.test,IP:127.0.0.1\n" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out "$name.pem" -days 2 -extfile "$name.ext" >/dev/null 2>&1
done
TOKEN="MUSESS-JA4MUX-OK-$(date +%s)"
printf '%s' "$TOKEN" > body.txt
KEYS=$("$WORK/helper" keygen)
SERVER_PRIVATE=$(printf '%s\n' "$KEYS" | sed -n 's/^private=//p')
SERVER_PUBLIC=$(printf '%s\n' "$KEYS" | sed -n 's/^public=//p')

mkserver() { # $1=mux(true/false)
  python3 - "$TESTDIR/server.json" "$WORK/server-$1.json" "$WORK" "$SERVER_PRIVATE" "$1" <<'EOF'
import json, sys
src, dst, work, priv, mux = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
text = open(src).read().replace("__WORKDIR__", work).replace("__SERVER_PRIVATE_KEY__", priv)
cfg = json.loads(text)
cfg["inbounds"][0]["certificate_path"] = work + "/server-local.pem"
cfg["inbounds"][0]["key_path"] = work + "/server-local-key.pem"
cfg["inbounds"][0]["listen_port"] = 14543
cfg["inbounds"][0]["dest_port"] = 18543
cfg["inbounds"][0]["private_key"] = priv
if mux == "true":
    cfg["inbounds"][0]["mux"] = True
json.dump(cfg, open(dst, "w"), indent=2)
EOF
}
mkclient() { # $1=mux(true/false)
  python3 - "$TESTDIR/client.json" "$WORK/client-$1.json" "$1" "$SERVER_PUBLIC" <<'EOF'
import json, sys
src, dst, mux, pub = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
text = open(src).read().replace("__SERVER_PORT__", "15566")
cfg = json.loads(text)
cfg["inbounds"][0]["listen_port"] = 11180
for ob in cfg["outbounds"]:
    if ob["type"] == "musess":
        ob["public_key"] = pub
        if mux == "true":
            ob["mux"] = True
json.dump(cfg, open(dst, "w"), indent=2)
EOF
}
mkserver true; mkserver false
mkclient true; mkclient false
for cfg in "$WORK"/server-*.json "$WORK"/client-*.json; do
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

"$WORK/helper" dest -addr 127.0.0.1:$DEST_PORT -cert "$WORK/dest.pem" -key "$WORK/dest-key.pem" \
  -body "$WORK/body.txt" -sidlog "$WORK/dest-sids.log" > "$WORK/dest.log" 2>&1 &
PIDS+=($!)
wait_port $DEST_PORT || exit 2

run_leg() { # $1 = mux(true/false)
  local mux=$1
  echo "=== leg mux=$mux ==="
  "$BIN" run -c "$WORK/server-$mux.json" > "$WORK/server-$mux.log" 2>&1 &
  PIDS+=($!)
  python3 ~/workspace/musess/capture-relay.py $RELAY_PORT $MUSESS_PORT "$WORK/relay-c2s-$mux.bin" "$WORK/relay-s2c-$mux.bin" > "$WORK/relay-$mux.log" 2>&1 &
  PIDS+=($!)
  "$BIN" run -c "$WORK/client-$mux.json" > "$WORK/client-$mux.log" 2>&1 &
  PIDS+=($!)
  wait_port $MUSESS_PORT && wait_port $RELAY_PORT && wait_port $SOCKS_PORT || { tail -n 20 "$WORK"/*.log; exit 2; }
  BODY=$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY curl -s --max-time 15 --socks5-hostname 127.0.0.1:$SOCKS_PORT --cacert "$WORK/ca.pem" https://dest.test:$DEST_PORT/)
  echo "body via tunnel (mux=$mux): $BODY"
  [ "$BODY" = "$TOKEN" ] && echo "tunnel fetch mux=$mux: OK" || echo "tunnel fetch mux=$mux: FAIL"
  sleep 1
  ls -l "$WORK/relay-c2s-$mux.bin"
  # Stop this leg's sing-boxen + relay (leave dest running).
  pkill -f "run -c $WORK/server-$mux.json" 2>/dev/null || true
  pkill -f "run -c $WORK/client-$mux.json" 2>/dev/null || true
  pkill -f "capture-relay.py $RELAY_PORT" 2>/dev/null || true
  sleep 1
}

run_leg false
run_leg true

echo "=== JA4 ==="
python3 ~/workspace/musess/ja4.py "$WORK/relay-c2s-false.bin" "$WORK/relay-c2s-true.bin" | tee "$WORK/ja4.txt"
echo "--- baselines ---"
echo "t13d0f10h2_8daaf6152771_36142f6fd6ef_0e284abb3885"
echo "t13d0f11h2_8daaf6152771_2d0528ac8a1e_0e284abb3885"
for f in false true; do
  ja4=$(grep -A1 "relay-c2s-$f.bin" "$WORK/ja4.txt" | grep "JA4:" | sed 's/.*JA4: //')
  echo "mux=$f JA4=$ja4"
  case "$ja4" in
    t13d0f10h2_8daaf6152771_36142f6fd6ef_0e284abb3885|t13d0f11h2_8daaf6152771_2d0528ac8a1e_0e284abb3885)
      echo "mux=$f: JA4 matches baseline (zero difference)" ;;
    *) echo "mux=$f: JA4 DIFFERS from baseline — investigate" ;;
  esac
done
echo "ja4-mux done (workdir kept at $WORK)"
