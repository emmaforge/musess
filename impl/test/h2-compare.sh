#!/usr/bin/env bash
# musess mux-landing: H2 record-shape comparison (landing item (c)).
#
# Question: does a mux session's frame/record shape look like a real
# browser's HTTP/2, or does it stand out? Two independent views:
#   (1) TLS records (passive, record-tap.py — never decrypts): the
#       exact shape a network observer sees. H2 leg = curl --http2
#       (nghttp2, a real H2 implementation) against the Go net/http
#       H2 server (dest2); mux leg = one musess mux session carrying
#       the same workload; stock leg = plain musess (control).
#   (2) H2 frames (helper h2tap — terminates TLS twice, so frame
#       sizes only, never timing): the exact H2 frame sizes the
#       same curl client produces, to compare against mux's own
#       frame sizes (32 KiB data frames + 9-byte header, from the
#       server's "mux session closed" debug line).
# Ports are offset +100, same scheme as bench-mux.sh. Run AFTER the
# bench (sequential — the box is shared and timing is load-sensitive).
set -u
cd "$(dirname "$0")"
TESTDIR=$(pwd)
IMPLDIR=$(dirname "$TESTDIR")
TMPROOT="$IMPLDIR/.tmp"
mkdir -p "$TMPROOT"
WORK=$(mktemp -d "$TMPROOT/h2-XXXXXX")
echo "workdir: $WORK"

export GOTOOLCHAIN=local TMPDIR="$TMPROOT"
GO="$HOME/workspace/go-1.24.7/bin/go"
[ -x "$GO" ] || GO="$(command -v go || true)"
BIN="$TMPROOT/sing-box-musess"
[ -x "$BIN" ] || { echo "FATAL: binary missing at $BIN"; exit 2; }
(cd helper && "$GO" build -o "$WORK/helper" .) || { echo "FATAL: helper build failed"; exit 2; }
HELPER="$WORK/helper"

DEST_PORT=18543
DEST2_SMALL=18544
DEST2_BIG=18545
MUSESS_PORT=14543
BULK_PORT=19101
SOCKS_MUX=11180
SOCKS_STOCK=11181
H2TAP_SMALL=15560
H2TAP_BIG=15563
RECTAP_H2=15561
RECTAP_H2BIG=15564
RECTAP_MUX=15562
RECTAP_STOCK=15565
ALL_PORTS="$DEST_PORT $DEST2_SMALL $DEST2_BIG $MUSESS_PORT $BULK_PORT $SOCKS_MUX $SOCKS_STOCK $H2TAP_SMALL $H2TAP_BIG $RECTAP_H2 $RECTAP_H2BIG $RECTAP_MUX $RECTAP_STOCK"

echo "--- preflight ---"
ss -ltnp 2>/dev/null | grep -E ":(1854[3-5]|14543|19101|1118[01]|1556[0-5])\b" || echo "no offset ports in use"
# Scoped to this line only (see bench-mux.sh: the VM is shared with
# other musess lines; a bare "sing-box-musess" pkill killed the
# multipath line's processes twice). Kill only the PIDs ss reports
# as owning our ports, and only when their /proc cmdline contains
# this line's workdir.
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
for p in $ALL_PORTS; do
  if ss -ltn 2>/dev/null | grep -q ":$p\b"; then echo "FATAL: port $p still occupied"; ss -ltnp 2>/dev/null | grep ":$p\b"; exit 2; fi
done
echo "preflight: all offset ports free"

WM="$WORK/musess"; mkdir -p "$WM"
cd "$WM"
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 2 -nodes \
  -subj "/CN=musess-h2-ca" >/dev/null 2>&1
for name in dest server-local; do
  openssl req -newkey rsa:2048 -keyout "$name-key.pem" -out "$name.csr" -nodes \
    -subj "/CN=dest.test" >/dev/null 2>&1
  printf "subjectAltName=DNS:dest.test,IP:127.0.0.1\n" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "$name.pem" -days 2 -extfile "$name.ext" >/dev/null 2>&1
done
printf 'MUSESS-H2-DEST' > body.txt
head -c 1048576 /dev/urandom > body1m.bin
KEYS=$("$HELPER" keygen)
SERVER_PRIVATE=$(printf '%s\n' "$KEYS" | sed -n 's/^private=//p')
SERVER_PUBLIC=$(printf '%s\n' "$KEYS" | sed -n 's/^public=//p')

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
json.dump(cfg, open(dst, "w"), indent=2)
EOF
mkclient() { # $1=tag $2=socks $3=mux $4=server_port
  python3 - "$TESTDIR/client.json" "$WM/client-$1.json" "$2" "$3" "$4" "$SERVER_PUBLIC" <<'EOF'
import json, sys
src, dst, socks, mux, sport, pub = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), sys.argv[6]
text = open(src).read().replace("__SERVER_PORT__", str(sport))
cfg = json.loads(text)
cfg["inbounds"][0]["listen_port"] = socks
for ob in cfg["outbounds"]:
    if ob["type"] == "musess":
        ob["server_port"] = sport
        ob["public_key"] = pub
        if mux == "true":
            ob["mux"] = True
json.dump(cfg, open(dst, "w"), indent=2)
EOF
}
mkclient mux $SOCKS_MUX true $RECTAP_MUX
mkclient stock $SOCKS_STOCK false $RECTAP_STOCK
for cfg in "$WM/server.json" "$WM/client-mux.json" "$WM/client-stock.json"; do
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
CURL="env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY curl -s --max-time 30 --cacert $WM/ca.pem"

"$HELPER" dest -addr 127.0.0.1:$DEST_PORT -cert "$WM/dest.pem" -key "$WM/dest-key.pem" \
  -body "$WM/body.txt" -sidlog "$WM/dest-sids.log" > "$WORK/dest.log" 2>&1 &
PIDS+=($!)
"$HELPER" dest2 -addr 127.0.0.1:$DEST2_SMALL -cert "$WM/dest.pem" -key "$WM/dest-key.pem" \
  -body "$WM/body.txt" > "$WORK/dest2-small.log" 2>&1 &
PIDS+=($!)
"$HELPER" dest2 -addr 127.0.0.1:$DEST2_BIG -cert "$WM/dest.pem" -key "$WM/dest-key.pem" \
  -body "$WM/body1m.bin" > "$WORK/dest2-big.log" 2>&1 &
PIDS+=($!)
"$HELPER" bulkserver -port $BULK_PORT > "$WORK/bulkserver.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WM/server.json" > "$WORK/musess-server.log" 2>&1 &
PIDS+=($!)
wait_port $DEST_PORT && wait_port $DEST2_SMALL && wait_port $DEST2_BIG && wait_port $BULK_PORT && wait_port $MUSESS_PORT \
  || { tail -n 20 "$WORK"/*.log; exit 2; }
echo "servers up"

# --- (2) H2 frames via h2tap (frame sizes only) ------------------------------
"$HELPER" h2tap -listen 127.0.0.1:$H2TAP_SMALL -target 127.0.0.1:$DEST2_SMALL \
  -cert "$WM/dest.pem" -key "$WM/dest-key.pem" -log "$WORK/h2frames-small.jsonl" > "$WORK/h2tap-small.log" 2>&1 &
PIDS+=($!)
"$HELPER" h2tap -listen 127.0.0.1:$H2TAP_BIG -target 127.0.0.1:$DEST2_BIG \
  -cert "$WM/dest.pem" -key "$WM/dest-key.pem" -log "$WORK/h2frames-big.jsonl" > "$WORK/h2tap-big.log" 2>&1 &
PIDS+=($!)
wait_port $H2TAP_SMALL && wait_port $H2TAP_BIG || { tail -n 20 "$WORK"/h2tap-*.log; exit 2; }
URLS_SMALL=""
for i in $(seq 1 10); do URLS_SMALL="$URLS_SMALL https://dest.test:$H2TAP_SMALL/?n=$i"; done
# Same 10 fetches, but through the record tap (its own port — the
# (1a) leg previously reused $URLS_SMALL, i.e. the h2tap port, so
# the small H2 record tap logged nothing).
URLS_SMALL_REC=""
for i in $(seq 1 10); do URLS_SMALL_REC="$URLS_SMALL_REC https://dest.test:$RECTAP_H2/?n=$i"; done
$CURL --http2 --parallel --parallel-max 10 --resolve dest.test:$H2TAP_SMALL:127.0.0.1 \
  -o /dev/null -w 'h2small %{http_version} %{size_download} %{time_total}\n' $URLS_SMALL | tee "$WORK/h2small-curl.txt"
grep -q "h2small 2 " "$WORK/h2small-curl.txt" && echo "H2 confirmed for small parallel fetch (http_version 2)" || echo "WARN: small fetch did not negotiate h2"
$CURL --http2 --resolve dest.test:$H2TAP_BIG:127.0.0.1 \
  -o "$WORK/h2big.bin" -w 'h2big %{http_version} %{size_download} %{time_total}\n' https://dest.test:$H2TAP_BIG/ | tee "$WORK/h2big-curl.txt"
cmp -s "$WORK/h2big.bin" "$WM/body1m.bin" && echo "h2 1MiB fetch byte-identical" || echo "WARN: h2 1MiB fetch mismatch"
sleep 0.5

# --- (1a) H2 TLS records via record-tap ---------------------------------------
python3 "$TESTDIR/record-tap.py" $RECTAP_H2 $DEST2_SMALL "$WORK/records-h2-small.jsonl" > "$WORK/rectap-h2.log" 2>&1 &
PIDS+=($!)
python3 "$TESTDIR/record-tap.py" $RECTAP_H2BIG $DEST2_BIG "$WORK/records-h2-big.jsonl" > "$WORK/rectap-h2big.log" 2>&1 &
PIDS+=($!)
wait_port $RECTAP_H2 && wait_port $RECTAP_H2BIG || exit 2
$CURL --http2 --parallel --parallel-max 10 --resolve dest.test:$RECTAP_H2:127.0.0.1 \
  -o /dev/null -w 'h2rec-small %{http_version} %{size_download} %{time_total}\n' $URLS_SMALL_REC | tee "$WORK/h2rec-small-curl.txt"
$CURL --http2 --resolve dest.test:$RECTAP_H2BIG:127.0.0.1 \
  -o "$WORK/h2rec-big.bin" -w 'h2rec-big %{http_version} %{size_download} %{time_total}\n' https://dest.test:$RECTAP_H2BIG/ | tee "$WORK/h2rec-big-curl.txt"
cmp -s "$WORK/h2rec-big.bin" "$WM/body1m.bin" && echo "h2-rec 1MiB fetch byte-identical" || echo "WARN: h2-rec 1MiB fetch mismatch"
sleep 0.5

# --- (1b) mux TLS records via record-tap --------------------------------------
python3 "$TESTDIR/record-tap.py" $RECTAP_MUX $MUSESS_PORT "$WORK/records-mux.jsonl" > "$WORK/rectap-mux.log" 2>&1 &
PIDS+=($!)
python3 "$TESTDIR/record-tap.py" $RECTAP_STOCK $MUSESS_PORT "$WORK/records-stock.jsonl" > "$WORK/rectap-stock.log" 2>&1 &
PIDS+=($!)
wait_port $RECTAP_MUX && wait_port $RECTAP_STOCK || exit 2
"$BIN" run -c "$WM/client-mux.json" > "$WORK/client-mux.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WM/client-stock.json" > "$WORK/client-stock.log" 2>&1 &
PIDS+=($!)
wait_port $SOCKS_MUX && wait_port $SOCKS_STOCK || { tail -n 20 "$WORK"/client-*.log; exit 2; }
# mux leg: 10 sequential small fetches (one session, 10 streams) + 1 MiB bulk.
for i in $(seq 1 10); do
  $CURL --socks5 127.0.0.1:$SOCKS_MUX --resolve dest.test:$DEST_PORT:127.0.0.1 \
    -o /tmp/h2-mux-body.txt https://dest.test:$DEST_PORT/?n=$i || echo "mux fetch $i FAILED"
done
[ "$(cat /tmp/h2-mux-body.txt)" = "MUSESS-H2-DEST" ] && echo "mux small fetches OK" || echo "WARN: mux small fetch body mismatch"
"$HELPER" bulkclient -bytes 1048576 -socks 127.0.0.1:$SOCKS_MUX -addr "127.0.0.1:$BULK_PORT" | tee "$WORK/mux-bulk1m.txt"
# stock leg (control): same 10 fetches, one connection each.
for i in $(seq 1 10); do
  $CURL --socks5 127.0.0.1:$SOCKS_STOCK --resolve dest.test:$DEST_PORT:127.0.0.1 \
    -o /tmp/h2-stock-body.txt https://dest.test:$DEST_PORT/?n=$i || echo "stock fetch $i FAILED"
done
[ "$(cat /tmp/h2-stock-body.txt)" = "MUSESS-H2-DEST" ] && echo "stock small fetches OK" || echo "WARN: stock small fetch body mismatch"
"$HELPER" bulkclient -bytes 1048576 -socks 127.0.0.1:$SOCKS_STOCK -addr "127.0.0.1:$BULK_PORT" | tee "$WORK/stock-bulk1m.txt"
sleep 1
# End the mux session so the server logs its frame histogram.
pkill -f "run -c $WM/client-mux.json" 2>/dev/null || true
sleep 1
echo "--- mux session frame stats (server log) ---"
grep -h "mux session closed" "$WORK/musess-server.log" | tail -3 || echo "(no mux session close line — session may still be open)"

echo "--- analysis ---"
python3 "$TESTDIR/h2-analyze.py" \
  "h2-frames-small=$WORK/h2frames-small.jsonl" \
  "h2-frames-big=$WORK/h2frames-big.jsonl" \
  "h2-records-small=$WORK/records-h2-small.jsonl" \
  "h2-records-big=$WORK/records-h2-big.jsonl" \
  "mux-records=$WORK/records-mux.jsonl" \
  "stock-records=$WORK/records-stock.jsonl" | tee "$WORK/h2-analysis.txt"

echo "h2 compare done (workdir kept at $WORK)"
