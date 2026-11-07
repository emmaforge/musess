# musess

一个围绕 sing-box 实现的新代理协议（设计与开发中）。

## 状态

- 设计评审稿已完成：见 [DESIGN.md](DESIGN.md)（调研落笔清单见
  [DESIGN-suggestions.md](DESIGN-suggestions.md)）。
- 第一程开发中：在 sing-box 中实现 TCP/TLS 路（借站 dest 回落、
  绑握手转录的认证标签、时间窗防重放），先把协议本体跑通；
  Xboard-Node / 面板集成后置。
- 已公开：2026-11-07 起仓库公开，支持一键安装（`install.sh`）；仍不投稿上游。

## 一键安装

在服务器上以 root 运行一行命令（Linux x86_64 / arm64，需 curl、openssl、git，443 端口空闲）：

```bash
bash <(curl -sL https://raw.githubusercontent.com/emmaforge/musess/main/install.sh)
```

脚本会：安装 Go 1.24.7 → 拉取代码（钉在测过的提交）→ 编译 sing-box → 写
`/etc/musess/server.json` → 给借站域名签本地证书 → 起 systemd 服务并启动。
装完打印用户 UUID / secret、公钥 / 私钥、客户端配置和节点链接，请妥善保存。

自定义端口、借站、用户名或自带凭证：

```bash
curl -sL https://raw.githubusercontent.com/emmaforge/musess/main/install.sh \
  | sudo bash -s -- --port 8443 --dest www.yahoo.co.jp --user emma
# 或用环境变量：MUSESS_PORT / MUSESS_DEST / MUSESS_USER / MUSESS_UUID /
#   MUSESS_SECRET / MUSESS_PRIVATE_KEY（base64 的 X25519 私钥）/ MUSESS_REF
```

没提供的 UUID / secret / 私钥会在本机生成，不会上传到任何地方。
默认值与代码一致：脱壳、多路复用默认关（预热池是客户端默认开，无需服务端配置）。

装好后，电脑客户端用本仓库编译的 sing-box + 脚本打印的 `client.json`
（本机 socks 入口 `127.0.0.1:1080`）。原版 sing-box 与常见客户端暂不支持 musess。

## 已定决策

- 路线：围绕 sing-box 写，先协议本体，后 Xboard-Node 集成；
  新核心只在设计文档第 7.4 节的三条决策门满足时才重新评估。
- 部署基线：借用外部目标站（dest），未认证流量回落到真实目标站。
- 优先级：**速率 > 伪装 > 延迟**。
- 双路：QUIC 主路 + TCP 回落（分阶段实现）；认证数据禁用 0-RTT；
  FEC 进 v1，仅应用层、自适应、按流差异化（第二程）。

## 目标（一句话版）

强伪装、低延迟、丢包不卡、跑满带宽 —— 四者不可同时顶满，
取舍口径与量化目标（均为待验证目标）见 DESIGN.md 第 1 章。
