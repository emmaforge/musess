#!/usr/bin/env bash
# musess TTFB control table (small HTTPS fetch through the tunnel).
#
# Legs (all on 127.0.0.1), each a small fetch of the dest stand-in body
# (a few dozen bytes) so time_starttransfer is dominated by connection
# setup, not bulk transfer:
#   direct     - curl straight to the dest stand-in
#   ss2022     - curl -> client sing-box SOCKS :11082 -> ss2022 -> server
#   musess-on  - curl -> client sing-box SOCKS :11080 -> musess (early_request
#                unset = default ON) -> server
#   musess-off - curl -> client sing-box SOCKS :11083 -> musess with
#                "early_request": false -> server
#
# Impairment: the same user-space delay shim as bench-e2e.sh (delay model,
# NOT packet loss, NOT netem), placed between proxy client and proxy
# server for the proxied legs. Settings: none | delay25 | delay100.
# Each leg: 1 warmup + 3 measured fetches, median reported.
#
# Harness lessons (from DESHELL-REPORT.md): do NOT export no_proxy='*'
# (it makes curl bypass --socks5-hostname); use --noproxy '*' only on
# the direct leg. curl --resolve pins dest.test to 127.0.0.1 so no leg
# depends on sing-box DNS.
set -u
cd "$(dirname "$0")"
TESTDIR=$(pwd)
IMPLDIR=$(dirname "$TESTDIR")
TMPROOT="$IMPLDIR/.tmp"
mkdir -p "$TMPROOT"
WORK=$(mktemp -d "$TMPROOT/ttfb-XXXXXX")
echo "workdir: $WORK"
echo "impairment: user-space shim, delay model (NOT packet loss)"

export GOTOOLCHAIN=local TMPDIR="$TMPROOT"
GO="$HOME/workspace/go-1.24.7/bin/go"
[ -x "$GO" ] || GO="$(command -v go || true)"
[ -n "$GO" ] || { echo "FATAL: no go toolchain"; exit 2; }

BIN="$TMPROOT/sing-box-musess"
[ -x "$BIN" ] || { echo "FATAL: sing-box binary not found at $BIN"; exit 2; }
echo "binary: $($BIN version | head -1)"

(cd helper && "$GO" build -o "$WORK/helper" .) || { echo "FATAL: helper build failed"; exit 2; }
HELPER="$WORK/helper"

SS_SERVER_PORT=14446
SHIM_MUSESS_PORT=15451
SHIM_SS_PORT=15452

# --- certs + configs (run-e2e.sh pattern) -----------------------------------
WM="$WORK/musess"; mkdir -p "$WM"
cd "$WM"
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 2 -nodes \
  -subj "/CN=musess-ttfb-ca" >/dev/null 2>&1
for name in dest server-local; do
  openssl req -newkey rsa:2048 -keyout "$name-key.pem" -out "$name.csr" -nodes \
    -subj "/CN=dest.test" >/dev/null 2>&1
  printf "subjectAltName=DNS:dest.test,IP:127.0.0.1\n" > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "$name.pem" -days 2 -extfile "$name.ext" >/dev/null 2>&1
done
TOKEN="MUSESS-TTFB-OK-$(date +%s)"
printf '%s' "$TOKEN" > body.txt
KEYS=$("$HELPER" keygen)
SERVER_PRIVATE=$(printf '%s\n' "$KEYS" | sed -n 's/^private=//p')
SERVER_PUBLIC=$(printf '%s\n' "$KEYS" | sed -n 's/^public=//p')
sed -e "s|__WORKDIR__|$WM|g" -e "s|__SERVER_PRIVATE_KEY__|$SERVER_PRIVATE|g" \
  "$TESTDIR/server.json" > "$WM/server.json"
sed -e "s|__SERVER_PORT__|14443|g" -e "s|__SERVER_PUBLIC_KEY__|$SERVER_PUBLIC|g" \
  "$TESTDIR/client.json" > "$WM/client-on-direct.json"
sed -e "s|__SERVER_PORT__|$SHIM_MUSESS_PORT|g" -e "s|__SERVER_PUBLIC_KEY__|$SERVER_PUBLIC|g" \
  "$TESTDIR/client.json" > "$WM/client-on-shim.json"
# early_request explicitly OFF: add the option to the musess outbound and
# move the SOCKS port to 11083.
python3 - "$WM/client-on-direct.json" "$WM/client-off-direct.json" <<'EOF'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
cfg = json.load(open(src))
cfg["inbounds"][0]["listen_port"] = 11083
for ob in cfg["outbounds"]:
    if ob["type"] == "musess":
        ob["early_request"] = False
json.dump(cfg, open(dst, "w"), indent=2)
EOF
python3 - "$WM/client-on-shim.json" "$WM/client-off-shim.json" <<'EOF'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
cfg = json.load(open(src))
cfg["inbounds"][0]["listen_port"] = 11083
for ob in cfg["outbounds"]:
    if ob["type"] == "musess":
        ob["early_request"] = False
json.dump(cfg, open(dst, "w"), indent=2)
EOF

WS="$WORK/ss2022"; mkdir -p "$WS"
cp "$TESTDIR/ss2022-server.json" "$WS/server.json"
sed -e "s|__SERVER_PORT__|$SS_SERVER_PORT|g" "$TESTDIR/ss2022-client.json" > "$WS/client-direct.json"
sed -e "s|__SERVER_PORT__|$SHIM_SS_PORT|g" "$TESTDIR/ss2022-client.json" > "$WS/client-shim.json"

for cfg in "$WM/server.json" "$WM/client-on-direct.json" "$WM/client-on-shim.json" \
           "$WM/client-off-direct.json" "$WM/client-off-shim.json" \
           "$WS/server.json" "$WS/client-direct.json" "$WS/client-shim.json"; do
  "$BIN" check -c "$cfg" >/dev/null || { echo "FATAL: config check failed: $cfg"; exit 2; }
done
echo "all configs: OK"

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

"$HELPER" dest -addr 127.0.0.1:18443 -cert "$WM/dest.pem" -key "$WM/dest-key.pem" \
  -body "$WM/body.txt" -sidlog "$WM/dest-sids.log" > "$WORK/dest.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WM/server.json" > "$WORK/musess-server.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WS/server.json" > "$WORK/ss-server.log" 2>&1 &
PIDS+=($!)
wait_port 18443 && wait_port 14443 && wait_port $SS_SERVER_PORT \
  || { tail -n 20 "$WORK"/*.log; exit 2; }
echo "servers up"

median() { printf '%s\n' "$@" | sort -n | awk '{ a[NR]=$1 } END { print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2) }'; }

fetch_ttfb() { # $1 = curl extra args...; prints time_starttransfer (seconds); exit != 0 on curl error
  rm -f /tmp/ttfb-body.txt
  curl -s --max-time 15 --cacert "$WM/ca.pem" --resolve dest.test:18443:127.0.0.1 \
    -o /tmp/ttfb-body.txt -w '%{time_starttransfer}' "$@" https://dest.test:18443/
}

run_leg() { # $1=leg $2=desc $3..=curl args
  local leg=$1 desc=$2; shift 2
  # warmup (unchecked)
  fetch_ttfb "$@" >/dev/null 2>&1
  local samples=()
  for _ in 1 2 3; do
    local t
    t=$(fetch_ttfb "$@"); local rc=$?
    if [ "$rc" -ne 0 ] || [ ! -f /tmp/ttfb-body.txt ]; then
      echo "leg=$leg shim=$desc FAILED curl error rc=$rc"; return
    fi
    local body
    body=$(cat /tmp/ttfb-body.txt)
    if [ "$body" != "$TOKEN" ]; then
      echo "leg=$leg shim=$desc FAILED wrong body: $body"; return
    fi
    samples+=("$t")
  done
  local med
  med=$(median "${samples[@]}")
  echo "leg=$leg shim=$desc ttfb_samples=${samples[*]} ttfb_median=$med"
}

for setting in none delay25 delay100; do
  case $setting in
    none)     DESC="none";     SHIM_ARGS=() ;;
    delay25)  DESC="delay25ms"; SHIM_ARGS=(-delay-ms 25) ;;
    delay100) DESC="delay100ms"; SHIM_ARGS=(-delay-ms 100) ;;
  esac

  if [ "$setting" = none ]; then
    "$BIN" run -c "$WM/client-on-direct.json" > "$WORK/musess-on-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-off-direct.json" > "$WORK/musess-off-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WS/client-direct.json" > "$WORK/ss-client-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    wait_port 11080 && wait_port 11083 && wait_port 11082 || { tail -n 20 "$WORK"/*-$setting.log; exit 2; }
    run_leg direct "$DESC" --noproxy '*'
    run_leg ss2022 "$DESC" --socks5 127.0.0.1:11082
    run_leg musess-on "$DESC" --socks5 127.0.0.1:11080
    run_leg musess-off "$DESC" --socks5 127.0.0.1:11083
  else
    "$HELPER" shim -listen 127.0.0.1:$SHIM_MUSESS_PORT -target 127.0.0.1:14443 \
      "${SHIM_ARGS[@]}" > "$WORK/shim-musess-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$HELPER" shim -listen 127.0.0.1:$SHIM_SS_PORT -target 127.0.0.1:$SS_SERVER_PORT \
      "${SHIM_ARGS[@]}" > "$WORK/shim-ss-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-on-shim.json" > "$WORK/musess-on-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WM/client-off-shim.json" > "$WORK/musess-off-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    "$BIN" run -c "$WS/client-shim.json" > "$WORK/ss-client-$setting.log" 2>&1 &
    SETTING_PIDS+=($!)
    wait_port $SHIM_MUSESS_PORT && wait_port $SHIM_SS_PORT \
      && wait_port 11080 && wait_port 11083 && wait_port 11082 || { tail -n 20 "$WORK"/*-$setting.log; exit 2; }
    run_leg direct "$DESC" --noproxy '*'
    run_leg ss2022 "$DESC" --socks5 127.0.0.1:11082
    run_leg musess-on "$DESC" --socks5 127.0.0.1:11080
    run_leg musess-off "$DESC" --socks5 127.0.0.1:11083
  fi
  stop_setting
done

echo "ttfb done (workdir kept at $WORK for logs)"
