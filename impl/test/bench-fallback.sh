#!/usr/bin/env bash
# Fallback-mechanism benchmark for musess milestone 1.
#
# Compares, against the SAME destination stand-in (dest2: net/http,
# TLS 1.3 + H2, like a real site):
#   direct   - curl straight to the destination
#   musess   - curl to the musess server with NO auth (byte-forward splice)
#   reality  - curl to a stock sing-box VLESS+REALITY inbound whose
#              handshake server is the same destination (the tree's
#              reality-style mechanism, unauthenticated probe)
#
# For each leg: response-body sanity, presented certificate
# fingerprint, negotiated TLS parameters (openssl s_client), and
# curl timings over repeated fetches (median of %{time_appconnect},
# %{time_starttransfer}, %{time_total}).
set -u
cd "$(dirname "$0")"
TESTDIR=$(pwd)
IMPLDIR=$(dirname "$TESTDIR")
TMPROOT="$IMPLDIR/.tmp"
mkdir -p "$TMPROOT"
WORK=$(mktemp -d "$TMPROOT/bench-XXXXXX")
echo "workdir: $WORK"

export GOTOOLCHAIN=local TMPDIR="$TMPROOT"
export no_proxy='*' NO_PROXY='*'
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY || true
GO=""
for cand in /home/hatch/workspace/.go-tmp/go/bin/go "$(command -v go || true)"; do
  if [ -n "$cand" ] && [ -x "$cand" ]; then GO="$cand"; break; fi
done
BIN="$TMPROOT/sing-box-musess"
[ -x "$BIN" ] || { echo "FATAL: build sing-box-musess first (see impl/README.md)"; exit 2; }
(cd helper && "$GO" build -o "$WORK/helper" .) || { echo "FATAL: helper build failed"; exit 2; }

cd "$WORK"
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 2 -nodes \
  -subj "/CN=musess-bench-ca" >/dev/null 2>&1
openssl req -newkey rsa:2048 -keyout dest-key.pem -out dest.csr -nodes \
  -subj "/CN=dest.test" >/dev/null 2>&1
printf "subjectAltName=DNS:dest.test,IP:127.0.0.1\n" > dest.ext
openssl x509 -req -in dest.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out dest.pem -days 2 -extfile dest.ext >/dev/null 2>&1
# server-local cert for the musess leg (distinct key, same name)
openssl req -newkey rsa:2048 -keyout server-local-key.pem -out server-local.csr -nodes \
  -subj "/CN=dest.test" >/dev/null 2>&1
openssl x509 -req -in server-local.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-local.pem -days 2 -extfile dest.ext >/dev/null 2>&1

TOKEN="MUSESS-BENCH-OK"
printf '%s' "$TOKEN" > body.txt

KEYS=$("$WORK/helper" keygen)
SERVER_PRIVATE=$(printf '%s\n' "$KEYS" | sed -n 's/^private=//p')
sed -e "s|__WORKDIR__|$WORK|g" -e "s|__SERVER_PRIVATE_KEY__|$SERVER_PRIVATE|g" \
  "$TESTDIR/server.json" > "$WORK/musess-server.json"

REALITY_KEYS=$("$BIN" generate reality-keypair)
REALITY_PRIVATE=$(printf '%s\n' "$REALITY_KEYS" | sed -n 's/^PrivateKey: //p')
cat > "$WORK/reality-server.json" <<EOF
{
  "log": {"level": "info"},
  "inbounds": [
    {
      "type": "vless",
      "tag": "reality-in",
      "listen": "127.0.0.1",
      "listen_port": 14444,
      "users": [{"uuid": "22222222-3333-4444-5555-666666666666"}],
      "tls": {
        "enabled": true,
        "server_name": "dest.test",
        "reality": {
          "enabled": true,
          "handshake": {"server": "127.0.0.1", "server_port": 18443},
          "private_key": "$REALITY_PRIVATE",
          "short_id": ["0123456789abcdef"]
        }
      }
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF

PIDS=()
cleanup() { for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done; }
trap cleanup EXIT

"$WORK/helper" dest2 -addr 127.0.0.1:18443 -cert "$WORK/dest.pem" -key "$WORK/dest-key.pem" \
  -body "$WORK/body.txt" > "$WORK/dest2.log" 2>&1 &
PIDS+=($!)
"$BIN" run -c "$WORK/musess-server.json" > "$WORK/musess.log" 2>&1 &
PIDS+=($!)
SSL_CERT_FILE="$WORK/ca.pem" "$BIN" run -c "$WORK/reality-server.json" > "$WORK/reality.log" 2>&1 &
PIDS+=($!)

wait_port() {
  for _ in $(seq 1 75); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
    sleep 0.2
  done
  echo "FATAL: port $1 never came up"; return 1
}
wait_port 18443 && wait_port 14443 && wait_port 14444 || { tail -n 20 "$WORK"/*.log; exit 2; }
echo "all bench services up"

DEST_FP=$(openssl x509 -in dest.pem -noout -fingerprint -sha256)

leg() { # $1=name $2=port
  local name=$1 port=$2
  local body fp proto
  body=$(curl -s --max-time 10 --cacert "$WORK/ca.pem" --resolve "dest.test:$port:127.0.0.1" "https://dest.test:$port/")
  fp=$(echo | openssl s_client -connect "127.0.0.1:$port" -servername dest.test -showcerts 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null)
  proto=$(echo | openssl s_client -connect "127.0.0.1:$port" -servername dest.test -alpn h2,http/1.1 2>/dev/null | grep -a "Protocol *:\|Cipher *:\|ALPN protocol" | sed 's/^ *//' | tr '\n' ' ')
  echo "[$name] body_ok=$([ "$body" = "$TOKEN" ] && echo yes || echo NO) cert_is_dest=$([ "$fp" = "$DEST_FP" ] && echo yes || echo NO)"
  echo "[$name] s_client: $proto"
  # warmup
  for _ in 1 2 3; do curl -s -o /dev/null --max-time 10 --cacert "$WORK/ca.pem" --resolve "dest.test:$port:127.0.0.1" "https://dest.test:$port/"; done
  : > "$WORK/times-$name.txt"
  for _ in $(seq 1 25); do
    curl -s -o /dev/null --max-time 10 --cacert "$WORK/ca.pem" --resolve "dest.test:$port:127.0.0.1" \
      -w "%{time_appconnect} %{time_starttransfer} %{time_total}\n" "https://dest.test:$port/" >> "$WORK/times-$name.txt"
  done
  awk '{a[NR]=$1; s[NR]=$2; t[NR]=$3} END {
    for (i=1;i<=NR;i++) for (j=i+1;j<=NR;j++) { if (a[j]<a[i]) {x=a[i];a[i]=a[j];a[j]=x} if (s[j]<s[i]) {x=s[i];s[i]=s[j];s[j]=x} if (t[j]<t[i]) {x=t[i];t[i]=t[j];t[j]=x} }
    m = int(NR/2)+1
    printf "[%s] median appconnect=%.4fs starttransfer=%.4fs total=%.4fs (n=%d)\n", "'"$name"'", a[m], s[m], t[m], NR
  }' "$WORK/times-$name.txt"
}

leg direct 18443
leg musess 14443
leg reality 14444
echo "bench done"
