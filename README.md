# Hy2Link

基于 Hysteria2 魔改 QUIC 的虚拟组网工具，为游戏对战和抗审查场景打造。

## 特性

- **六条独立 QUIC 连接** — 认证、bulk、匹配、游戏 TCP、对战 UDP、控制面各走各的拥塞控制
- **Salamander 混淆** — 每个 UDP 包 XOR BLAKE2b-256(PSK‖salt)，防 DPI 深度包检测
- **ALPN 伪装** — 使用 `h3` / `h3-data` / `h3-ctrl`，在网络中看起来像标准 HTTP/3
- **QUIC-DC 拥塞控制** — 为对战 UDP datagram 定制，minCwnd=4、lossReduction=0.85
- **端口分流** — 按端口范围拆分游戏 TCP、匹配 UDP、对战 UDP 到独立通道
- **服务端 TUN** — 游戏服务器直接监听虚拟 IP，无需运行客户端
- **配置导入导出** — `.hy2` 文件双击导入，Windows 文件关联
- **Web 管理面板** — 实时图表、多用户、配额、地理围栏、证书管理
- **多语言** — 简体中文 / 繁體中文 / English / 日本語

## 架构

所有连接共享同一个 UDP socket 和 Salamander 混淆层，通过 ALPN 在服务端分流：

| # | 连接 | ALPN | 拥塞控制 | 承载 |
|---|------|------|----------|------|
| 1 | hysteria 认证 | `h3` | BBR ultra | 认证 + DHCP |
| 2 | dataConn | `h3-data` | Cubic | bulk TCP + 其他 UDP |
| 3 | matchConn | `h3-data` | Cubic | 匹配 UDP |
| 4 | gameTCPConn | `h3-data` | BBR standard | 游戏 TCP |
| 5 | gameConn | `h3-data` | QUIC-DC | 对战 UDP datagram |
| 6 | ctrlConn | `h3-ctrl` | Cubic | ICMP + 心跳 |

## 目录结构
.
├── hy-core/ Hysteria2 core（含本地修改）
├── hy-extras/ Hysteria2 extras（obfs 等）
├── quic-go/ quic-go（本地锁定版本）
├── vpn-server/ 服务端（Go + 内嵌 Web 面板）
└── vpn-tool/ 客户端（Wails + Vue 3）

text

## 快速开始

### 环境要求

- Go 1.25+
- 客户端额外需要：Wails CLI、Node.js 18+
- 服务端 TUN 功能需要管理员/root 权限

### 编译服务端

```bash
cd vpn-server
go build -o hy2link-server.exe .
./hy2link-server.exe
首次启动自动创建：

config/server.json — 服务端配置

certs/selfsigned.crt / certs/selfsigned.key — 自签证书

管理面板：http://localhost:8444

编译客户端
bash
cd vpn-tool
wails build
产物在 build/bin/ 下。

配置说明
服务端
关键配置项（server.json）：

字段	说明
port	QUIC 监听端口
obfsEnabled / obfsPassword	Salamander 混淆开关和预共享密钥
tcpSplitEnabled / tcpSplitPorts	TCP 端口拆分
udpReliablePorts	匹配 UDP 端口范围
udpUnreliablePorts	对战 UDP 端口范围
serverTunEnabled	服务端 TUN 开关
客户端
支持 .hy2 配置文件双击导入：

json
{
  "v": 1,
  "type": "hy2link",
  "name": "香港节点",
  "server": "hk.example.com",
  "port": 8443,
  "password": "your-auth-password",
  "obfsEnabled": true,
  "obfsPassword": "your-obfs-password",
  "skipCertVerify": false
}
抗封锁设计
三层混淆叠加，对抗不同维度的深度包检测：

1.数据包混淆 — Salamander，无 PSK 无法还原任何 QUIC 特征

2.TLS 握手伪装 — ALPN 使用标准 HTTP/3 名字

3.流量模式打散 — 按应用类型拆分到多条 QUIC 连接

依赖说明
本项目包含以下本地依赖（通过 replace 指令引用）：

依赖	来源	说明
hy-core/	apernet/hysteria	MIT，有本地修改
hy-extras/	同上	                MIT，保留上游
quic-go/	apernet/quic-go	    MIT，版本锁定
许可证
本项目采用 MIT 许可证，详见 LICENSE。

第三方依赖保留各自原许可证：

Hysteria2 — MIT License

quic-go — MIT License

致谢
Hysteria2 — 核心协议栈

quic-go — QUIC 实现

Wails — 桌面客户端框架

Vue 3 — 前端框架