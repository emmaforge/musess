#!/usr/bin/env bash
# musess 一键安装脚本
#
# 在服务器上以 root 运行：
#   bash <(curl -sL https://raw.githubusercontent.com/emmaforge/musess/main/install.sh)
# 自定义（端口 / 借站 / 用户名 / 已有凭证）：
#   curl -sL https://raw.githubusercontent.com/emmaforge/musess/main/install.sh \
#     | sudo bash -s -- --port 8443 --dest www.yahoo.co.jp --user emma
# 或用环境变量：MUSESS_PORT / MUSESS_DEST / MUSESS_USER / MUSESS_UUID /
#   MUSESS_SECRET / MUSESS_PRIVATE_KEY（base64 的 X25519 私钥）/ MUSESS_REF（提交）。
#
# 未提供的 UUID / secret / 私钥会在本机生成；私钥只写进 /etc/musess/server.json，
# 不会上传到任何地方。装完脚本会打印公钥、客户端配置和节点链接，请妥善保存。
#
# 默认值与代码一致：脱壳、多路复用默认关（预热池是客户端默认开，无需服务端配置）。
# 如需开启脱壳/多路复用，改 /etc/musess/server.json 的 inbound，加上
# "deshell": true / "mux": true 后 systemctl restart musess。
set -euo pipefail

PORT="${MUSESS_PORT:-443}"
DEST="${MUSESS_DEST:-www.yahoo.co.jp}"
USER_NAME="${MUSESS_USER:-emma}"
USER_UUID="${MUSESS_UUID:-}"
USER_SECRET="${MUSESS_SECRET:-}"
PRIVATE_KEY="${MUSESS_PRIVATE_KEY:-}"
REPO_REF="${MUSESS_REF:-d5452b51991867899595313095aa6c3d241d8bea}"

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --dest) DEST="$2"; shift 2 ;;
    --user) USER_NAME="$2"; shift 2 ;;
    --uuid) USER_UUID="$2"; shift 2 ;;
    --secret) USER_SECRET="$2"; shift 2 ;;
    --private-key) PRIVATE_KEY="$2"; shift 2 ;;
    --ref) REPO_REF="$2"; shift 2 ;;
    -h|--help) echo "用法：bash install.sh [--port 端口] [--dest 借站域名] [--user 用户名] [--uuid UUID] [--secret 密钥] [--private-key 私钥] [--ref 提交]"; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "请以 root 运行" >&2; exit 1; }
for cmd in curl openssl git; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "缺少 $cmd，尝试安装…"
    if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get install -y -qq "$cmd"
    elif command -v yum >/dev/null 2>&1; then yum install -y -q "$cmd"
    else echo "请先手动安装 $cmd" >&2; exit 1; fi
  }
done

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) GO_ARCH=amd64 ;;
  aarch64) GO_ARCH=arm64 ;;
  *) echo "不支持的架构: $ARCH" >&2; exit 1 ;;
esac

# 1. Go 1.24.7
if ! command -v go >/dev/null 2>&1; then
  echo "==> 安装 Go 1.24.7"
  curl -sL "https://go.dev/dl/go1.24.7.linux-${GO_ARCH}.tar.gz" -o /tmp/go1.24.7.tgz
  tar -C /usr/local -xzf /tmp/go1.24.7.tgz
fi
export PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local

# 2. 凭证：缺失的在本机生成
[ -n "$USER_UUID" ] || USER_UUID="$(cat /proc/sys/kernel/random/uuid)"
[ -n "$USER_SECRET" ] || USER_SECRET="$(openssl rand -base64 32 | tr -d '\n')"
cat > /tmp/musess-keygen.go <<'GOEOF'
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	var k *ecdh.PrivateKey
	if p := os.Getenv("MUSESS_PRIV_B64"); p != "" {
		b, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			panic(err)
		}
		k, err = ecdh.X25519().NewPrivateKey(b)
		if err != nil {
			panic(err)
		}
	} else {
		var err error
		k, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
	}
	fmt.Println(base64.StdEncoding.EncodeToString(k.Bytes()))
	fmt.Println(base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()))
}
GOEOF
mapfile -t _KEYS < <(MUSESS_PRIV_B64="$PRIVATE_KEY" go run /tmp/musess-keygen.go)
PRIVATE_KEY="${_KEYS[0]}"
PUBLIC_KEY="${_KEYS[1]}"

# 3. 拉代码并编译（仓库已公开，无需鉴权）
echo "==> 拉取 musess@$REPO_REF"
[ -d /opt/musess/.git ] || git clone https://github.com/emmaforge/musess.git /opt/musess
cd /opt/musess && git fetch -q && git checkout -q "$REPO_REF"
echo "==> 编译 sing-box-musess"
cd /opt/musess/impl/sing-box
go build -trimpath \
  -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=1.14.0-alpha.2-musess-m1' $(cat release/LDFLAGS) -s -w -buildid=" \
  -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" \
  -o /usr/local/bin/sing-box-musess ./cmd/sing-box

# 4. 服务端配置 + 借站域名的本地证书
mkdir -p /etc/musess
cat > /etc/musess/server.json <<EOF
{
  "log": {"level": "info", "timestamp": true},
  "inbounds": [{
    "type": "musess", "tag": "musess-in",
    "listen": "0.0.0.0", "listen_port": $PORT,
    "dest": "$DEST", "dest_port": 443,
    "private_key": "$PRIVATE_KEY",
    "certificate_path": "/etc/musess/server-local.pem",
    "key_path": "/etc/musess/server-local-key.pem",
    "users": [{"name": "$USER_NAME", "uuid": "$USER_UUID", "secret": "$USER_SECRET"}]
  }],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF
openssl req -x509 -newkey rsa:2048 \
  -keyout /etc/musess/server-local-key.pem \
  -out /etc/musess/server-local.pem \
  -days 3650 -nodes \
  -subj "/CN=$DEST" -addext "subjectAltName=DNS:$DEST" 2>/dev/null

# 5. systemd 服务并启动
cat > /etc/systemd/system/musess.service <<EOF
[Unit]
Description=musess server
After=network.target
[Service]
ExecStart=/usr/local/bin/sing-box-musess run -c /etc/musess/server.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now musess >/dev/null

# 6. 打印结果：公网 IP、客户端配置、节点链接
PUBLIC_IP="$(curl -s --max-time 5 https://ifconfig.me || true)"
[ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(hostname -I | awk '{print $1}')"
[ -n "$PUBLIC_IP" ] || PUBLIC_IP="<你的服务器 IP>"
cat > /etc/musess/client.json <<EOF
{
  "log": {"level": "info", "timestamp": true},
  "inbounds": [{
    "type": "socks", "tag": "socks-in",
    "listen": "127.0.0.1", "listen_port": 1080
  }],
  "outbounds": [
    {
      "type": "musess", "tag": "musess-out",
      "server": "$PUBLIC_IP", "server_port": $PORT,
      "server_name": "$DEST",
      "public_key": "$PUBLIC_KEY",
      "uuid": "$USER_UUID",
      "secret": "$USER_SECRET"
    },
    {"type": "direct", "tag": "direct"}
  ],
  "route": {"final": "musess-out"}
}
EOF

echo
echo "================ musess 已启动 ================"
systemctl is-active --quiet musess && echo "服务状态：active" || { echo "服务启动失败，查看：journalctl -u musess -n 50"; exit 1; }
echo "服务器：$PUBLIC_IP:$PORT（借站 $DEST）"
echo "用户：$USER_NAME"
echo "UUID：$USER_UUID"
echo "Secret：$USER_SECRET"
echo "公钥：$PUBLIC_KEY"
echo "私钥（已写入 /etc/musess/server.json）：$PRIVATE_KEY"
echo
echo "客户端配置已保存到 /etc/musess/client.json，内容如下："
cat /etc/musess/client.json
if command -v python3 >/dev/null 2>&1; then
  echo
  echo "节点链接："
  python3 - "$USER_UUID" "$PUBLIC_IP" "$PORT" "$USER_SECRET" "$PUBLIC_KEY" "$DEST" <<'PYEOF'
import sys, urllib.parse
uuid, server, port, secret, pub, dest = sys.argv[1:7]
q = urllib.parse.quote
link = (f"musess://{uuid}@{server}:{port}"
        f"?secret={q(secret)}&public_key={q(pub)}"
        f"&server_name={q(dest)}&warm_pool=2#musess")
print(link)
PYEOF
fi
echo "================================================"
echo "电脑客户端：用本仓库编译的 sing-box + 上面的 client.json，"
echo "socks 入口 127.0.0.1:1080。"
