#!/bin/sh
# musess 一键安装脚本 - POSIX sh，交互选择，装完生成节点链接
# 用法：curl -fsSL -o install.sh https://raw.githubusercontent.com/emmaforge/musess/main/install.sh && sh install.sh
# 装好后输入 ms 打开面板（查看链接/重启/状态/卸载）
# 本脚本直接下载 GitHub Release 里的预编译二进制，不再现场编译 Go（不需要 Go、不需要 git clone）。
BIN=/usr/local/bin/sing-box-musess; DIR=/etc/musess; CFG=$DIR/server.json; INFO=$DIR/info.env
REL_TAG=v0.1.1

say(){ printf '%s\n' "$*"; }
ask(){ printf '%s' "$1"; IFS= read -r REPLY; }
die(){ say "错误: $*"; exit 1; }
[ "$(id -u)" = 0 ] || die "请用 root 运行"

uuid(){ cat /proc/sys/kernel/random/uuid; }
randpw(){ head -c 32 /dev/urandom | base64 | tr -d '\n'; }
qenc(){ printf '%s' "$1" | sed -e 's/+/%2B/g' -e 's/\//%2F/g' -e 's/=/%3D/g'; }

has_sd(){ [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }
has_rc(){ command -v rc-update >/dev/null 2>&1; }

# 预编译安装只需要约 150MB（60MB 二进制 + 配置/证书），不再需要 4GB 编译空间。
disk_check(){
  free_kb=$(df -k / | awk 'NR==2 {print $4}')
  [ -n "$free_kb" ] && [ "$free_kb" -gt 262144 ] && return 0
  die "磁盘剩余空间不足：预编译安装只需约 256MB 空闲，当前约 $((free_kb / 1024))MB。先清理或扩容磁盘后再装。"
}

deps(){
  for c in curl openssl; do command -v "$c" >/dev/null 2>&1 || need=1; done
  [ -z "${need:-}" ] && return 0
  [ -f /etc/os-release ] && . /etc/os-release; os=${ID:-unknown}
  case "$os" in
    alpine) apk add --no-cache curl openssl ca-certificates >/dev/null 2>&1 ;;
    debian|ubuntu) apt-get update -qq && apt-get install -y -qq curl openssl ca-certificates >/dev/null 2>&1 ;;
    centos|rhel|rocky|almalinux|fedora|ol) (command -v dnf >/dev/null && dnf install -y -q curl openssl ca-certificates || yum install -y -q curl openssl ca-certificates) >/dev/null 2>&1 ;;
    arch|manjaro) pacman -Sy --noconfirm curl openssl ca-certificates >/dev/null 2>&1 ;;
    *) say "未识别系统 $os，假设依赖已齐全" ;;
  esac
}

# X25519 密钥对用 openssl 生成（私钥 32 字节在 PKCS#8 DER 末尾，公钥 32 字节在
# SubjectPublicKeyInfo DER 末尾；已在沙箱用 Go ecdh 交叉验证：从私钥重算的公钥一致）。
# 私钥只写进服务端配置，不会上传到任何地方。
keygen(){
  openssl genpkey -algorithm X25519 -out /tmp/musess-key.pem 2>/dev/null || die "密钥生成失败"
  PRIV=$(openssl pkey -in /tmp/musess-key.pem -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n')
  PUB=$(openssl pkey -in /tmp/musess-key.pem -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr -d '\n')
  rm -f /tmp/musess-key.pem
  [ "${#PRIV}" = 44 ] && [ "${#PUB}" = 44 ] || die "密钥生成失败"
}

install_bin(){
  case "$(uname -m)" in x86_64|amd64) a=amd64;; aarch64|arm64) a=arm64;; *) die "不支持架构 $(uname -m)";; esac
  file="sing-box-musess-linux-$a"
  url="https://github.com/emmaforge/musess/releases/download/$REL_TAG/$file"
  say "下载预编译二进制 $file（约 60MB，无需编译）..."
  tmpd=$(mktemp -d) || die "建临时目录失败"
  curl -fsSL -o "$tmpd/$file" "$url" || { rm -rf "$tmpd"; die "下载失败：请检查网络，或到 https://github.com/emmaforge/musess/releases 手动下载"; }
  curl -fsSL -o "$tmpd/$file.sha256" "$url.sha256" || { rm -rf "$tmpd"; die "校验和下载失败"; }
  (cd "$tmpd" && sha256sum -c "$file.sha256" >/dev/null 2>&1) || { rm -rf "$tmpd"; die "校验和不匹配：下载的文件可能损坏，请重装"; }
  mv "$tmpd/$file" "$BIN"; chmod +x "$BIN"; rm -rf "$tmpd"
  "$BIN" version >/dev/null 2>&1 || die "二进制无法运行（架构可能不匹配）"
}

svc_install(){
  mkdir -p "$DIR"
  if has_sd; then
    cat > /etc/systemd/system/musess.service <<'EOF'
[Unit]
Description=musess server
After=network.target
[Service]
ExecStart=/usr/local/bin/sing-box-musess run -c /etc/musess/server.json
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable musess >/dev/null 2>&1; systemctl restart musess
  elif has_rc; then
    cat > /etc/init.d/musess <<'EOF'
#!/sbin/openrc-run
name="musess"
command="/usr/local/bin/sing-box-musess"
command_args="run -c /etc/musess/server.json"
command_background="yes"
pidfile="/run/${RC_SVCNAME}.pid"
depend(){ need net; }
EOF
    chmod +x /etc/init.d/musess; rc-update add musess default >/dev/null 2>&1; rc-service musess restart >/dev/null 2>&1 || rc-service musess start
  else
    pkill -f "$BIN run" 2>/dev/null; nohup "$BIN" run -c "$CFG" >/dev/null 2>&1 &
    say "无 systemd/OpenRC，已后台启动（无自启）"
  fi
}
svc_stop(){
  if has_sd; then systemctl stop musess 2>/dev/null; systemctl disable musess 2>/dev/null; rm -f /etc/systemd/system/musess.service; systemctl daemon-reload
  elif has_rc; then rc-service musess stop 2>/dev/null; rc-update del musess default 2>/dev/null; rm -f /etc/init.d/musess
  else pkill -f "$BIN run" 2>/dev/null; fi
}
svc_restart(){ if has_sd; then systemctl restart musess; elif has_rc; then rc-service musess restart; else pkill -f "$BIN run" 2>/dev/null; nohup "$BIN" run -c "$CFG" >/dev/null 2>&1 & fi; }
svc_status(){ if has_sd; then systemctl is-active musess; elif has_rc; then rc-service musess status; else pgrep -f "$BIN run" >/dev/null && say running || say stopped; fi; }

# ---------- 安装向导：借站 -> 端口 -> 方案 -> 用户名，逐级选 ----------
wizard(){
  say "=== 1/3 选择借站目标 ==="
  say "1) www.yahoo.co.jp（推荐，日本第一门户）  2) ja.wikipedia.org  3) www.mixi.jp  4) 自定义"
  ask "输入编号 [1]: "; c=${REPLY:-1}
  case "$c" in
    1) DEST=www.yahoo.co.jp;;
    2) DEST=ja.wikipedia.org;;
    3) DEST=www.mixi.jp;;
    4) ask "输入借站域名: "; DEST=$REPLY; [ -n "$DEST" ] || die "域名为空";;
    *) die "无效选择";;
  esac

  ask "端口 [443]: "; PORT=${REPLY:-443}
  case "$PORT" in ''|*[!0-9]*) die "端口无效";; esac

  say "=== 2/3 选择性能方案 ==="
  say "1) 推荐均衡（预热池开，脱壳/多路复用关）"
  say "2) 大文件优先（多路复用开，大文件绕开 mux）"
  say "3) 晚高峰抗丢包（多路复用开，丢包时自动绕开 mux）"
  ask "输入编号 [1]: "; c=${REPLY:-1}
  case "$c" in
    1) PRESET=1;;
    2) PRESET=2;;
    3) PRESET=3;;
    *) die "无效选择";;
  esac

  ask "用户名 [emma]: "; USER=${REPLY:-emma}

  IP=$(curl -fsSL -4 --max-time 5 https://api.ipify.org 2>/dev/null || curl -fsSL -4 --max-time 5 https://ip.sb 2>/dev/null)
  ask "服务器地址 [${IP:-手动输入}]: "; ADDR=${REPLY:-$IP}; [ -n "$ADDR" ] || die "地址为空"

  say "借站=$DEST 端口=$PORT 方案=$PRESET 用户=$USER 地址=$ADDR"
  deps; install_bin; keygen
  ID=$(uuid); PW=$(randpw)

  case "$PRESET" in
    2) MUXF=',"mux":true'; COPT=',"mux":true,"mux_bypass":[":443"]'; EXTRA='&mux=1&mux_bypass=%3A443';;
    3) MUXF=',"mux":true'; COPT=',"mux":true,"mux_adaptive_bypass":true'; EXTRA='&mux=1&mux_adaptive_bypass=1';;
    *) MUXF=''; COPT=''; EXTRA='';;
  esac

  mkdir -p "$DIR"
  cat > "$CFG" <<EOF
{"log":{"level":"info"},"inbounds":[{"type":"musess","tag":"musess-in","listen":"::","listen_port":$PORT,"dest":"$DEST","dest_port":443,"private_key":"$PRIV","certificate_path":"$DIR/server-local.pem","key_path":"$DIR/server-local-key.pem","users":[{"name":"$USER","uuid":"$ID","secret":"$PW"}]$MUXF}],"outbounds":[{"type":"direct","tag":"direct"}]}
EOF
  openssl req -x509 -newkey rsa:2048 -keyout "$DIR/server-local-key.pem" -out "$DIR/server-local.pem" -days 3650 -nodes -subj "/CN=$DEST" -addext "subjectAltName=DNS:$DEST" >/dev/null 2>&1 || die "证书生成失败"
  chmod 600 "$DIR/server-local-key.pem"
  "$BIN" check -c "$CFG" >/dev/null || die "服务端配置校验失败"

  cat > "$DIR/client.json" <<EOF
{"log":{"level":"info"},"inbounds":[{"type":"socks","tag":"socks-in","listen":"127.0.0.1","listen_port":1080}],"outbounds":[{"type":"musess","tag":"musess-out","server":"$ADDR","server_port":$PORT,"server_name":"$DEST","public_key":"$PUB","uuid":"$ID","secret":"$PW"$COPT},{"type":"direct","tag":"direct"}],"route":{"final":"musess-out"}}
EOF
  "$BIN" check -c "$DIR/client.json" >/dev/null || die "客户端配置校验失败"

  cat > "$INFO" <<EOF
DEST='$DEST'
PORT='$PORT'
PRESET='$PRESET'
USER='$USER'
ADDR='$ADDR'
ID='$ID'
PW='$PW'
PRIV='$PRIV'
PUB='$PUB'
EXTRA='$EXTRA'
EOF
  chmod 600 "$INFO"
  cp -f "$0" /usr/local/bin/ms 2>/dev/null && chmod +x /usr/local/bin/ms
  svc_install; sleep 1; gen_link
  say "自启: $(has_sd && say systemd已启用 || (has_rc && say OpenRC已启用 || say 无)) | 状态: $(svc_status 2>/dev/null | head -1)"
  say "以后输入 ms 打开面板"
}

gen_link(){
  [ -f "$INFO" ] || die "未安装"
  . "$INFO"
  LINK="musess://$ID@$ADDR:$PORT?secret=$(qenc "$PW")&public_key=$(qenc "$PUB")&server_name=$DEST&warm_pool=2$EXTRA#musess"
  printf '%s' "$LINK" > "$DIR/link.txt"
  say ""; say "=== 节点链接 ==="; say "$LINK"
  say ""; say "用户: $USER  UUID: $ID"; say "Secret: $PW"; say "公钥: $PUB"; say "私钥(已写入 $CFG): $PRIV"
  say "客户端配置: $DIR/client.json"
}

panel(){
  say "=== musess 面板 ==="; say "1) 安装/重装节点  2) 查看链接  3) 重启  4) 状态  5) 卸载  0) 退出"
  ask "输入编号: "; case "${REPLY:-0}" in
    1) wizard;; 2) cat "$DIR/link.txt" 2>/dev/null || gen_link;;
    3) svc_restart; say 已重启;; 4) svc_status;; 5) svc_stop; rm -rf "$DIR" "$BIN" /usr/local/bin/ms /opt/musess; say 已卸载;; *) exit 0;; esac
}

disk_check
case "$1" in
  link) gen_link;; restart) svc_restart;; status) svc_status;;
  stop) svc_stop;; uninstall) svc_stop; rm -rf "$DIR" "$BIN" /usr/local/bin/ms /opt/musess; say 已卸载;;
  "") [ -f "$CFG" ] && panel || wizard ;;
  *) wizard ;;
esac
