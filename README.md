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

在服务器上以 root 运行（Linux x86_64 / arm64，需 256MB 空闲磁盘，443 端口空闲）：

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/emmaforge/musess/main/install.sh && sh install.sh
```

逐级选择：借站目标 → 端口 → 性能方案 → 用户名，装完直接输出节点链接。
装好后输入 `ms` 打开面板（查看链接/重启/状态/卸载）。

子命令：`ms link|status|restart|stop|uninstall`

脚本会：下载 GitHub Release v0.1.0 里的预编译二进制（按架构自动选，
附 sha256 校验）→ 写服务端配置 → 给借站域名签本地证书 → 起服务。
不编译、不装 Go。UUID、secret、X25519 密钥对自动生成（openssl），
只写进本机配置，不会上传到任何地方。

性能方案：1）推荐均衡（预热池开，脱壳/多路复用关） 2）大文件优先（多路复用开，
大文件绕开 mux） 3）晚高峰抗丢包（多路复用开，丢包时自动绕开 mux）。

磁盘空间不够会在一开始就报错；如果之前装失败了，先 `ms uninstall` 再重装，
或到 [Releases](https://github.com/emmaforge/musess/releases) 手动下载二进制。

装好后，电脑客户端用本仓库编译的 sing-box + `/etc/musess/client.json`
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
