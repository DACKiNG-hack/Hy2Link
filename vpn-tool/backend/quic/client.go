package quic

// backend/quic/client.go

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	qcong "vpn-tool/backend/quic/congestion"
	bbr "vpn-tool/backend/quic/congestion/bbr"
	"vpn-tool/backend/tun"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/apernet/quic-go"
	"github.com/google/uuid"
)

const maxFrameSize = 65535
const tunMTU = 1400

// ⭐ ALPN 改名（hysteria 认证的 "h3" 由 hysteria core 内部处理）
const (
	alpnData = "h3-data"
	alpnCtrl = "h3-ctrl"
)

const ClientVersion = "1.2.0"
const hardcodedBBRProfile = "ultra"
const hardcodedLatencyMode = "low"

const gameDgMagic = "HYUDP"
const maxGameDatagramSize = 1200

var defaultUDPMatchRanges = []portRange{
	{42300, 42800},
}

var defaultUDPUnreliableRanges = []portRange{
	{50000, 50550},
}

type portRange struct {
	lo, hi uint16
}

func (r portRange) contains(p uint16) bool { return p >= r.lo && p <= r.hi }
func (r portRange) String() string {
	if r.lo == r.hi {
		return fmt.Sprintf("%d", r.lo)
	}
	return fmt.Sprintf("%d-%d", r.lo, r.hi)
}

func parsePortRangeStr(s string) (portRange, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return portRange{}, false
	}
	if i := strings.Index(s, "-"); i >= 0 {
		lo, err1 := strconv.Atoi(strings.TrimSpace(s[:i]))
		hi, err2 := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
			return portRange{}, false
		}
		return portRange{uint16(lo), uint16(hi)}, true
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 1 || p > 65535 {
		return portRange{}, false
	}
	return portRange{uint16(p), uint16(p)}, true
}

func parsePortRanges(sep string, items []string) []portRange {
	out := make([]portRange, 0, len(items))
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if r, ok := parsePortRangeStr(it); ok {
			out = append(out, r)
		}
	}
	return out
}

func extractTCPDstPort(data []byte) (uint16, bool) {
	if len(data) < 20 {
		return 0, false
	}
	if (data[0]>>4)&0xF != 4 {
		return 0, false
	}
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl+4 {
		return 0, false
	}
	return binary.BigEndian.Uint16(data[ihl+2 : ihl+4]), true
}

func parseUDPDstPort(data []byte) (uint16, bool) {
	if len(data) < 20 {
		return 0, false
	}
	if (data[0]>>4)&0xF != 4 {
		return 0, false
	}
	if data[9] != ipProtoUDP {
		return 0, false
	}
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl+4 {
		return 0, false
	}
	return binary.BigEndian.Uint16(data[ihl+2 : ihl+4]), true
}

func parseUDPSrcPort(data []byte) (uint16, bool) {
	if len(data) < 20 {
		return 0, false
	}
	if (data[0]>>4)&0xF != 4 {
		return 0, false
	}
	if data[9] != ipProtoUDP {
		return 0, false
	}
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl+4 {
		return 0, false
	}
	return binary.BigEndian.Uint16(data[ihl : ihl+2]), true
}

func keysOf(m map[uint16]bool) []uint16 {
	out := make([]uint16, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

const (
	hbTypePing byte = 0x01
	hbTypePong byte = 0x02
)

const (
	ipProtoICMP = 1
	ipProtoTCP  = 6
	ipProtoUDP  = 17
)

const (
	offlineThreshold   = 30 * time.Second
	reconnectThreshold = 15 * time.Second
)

const (
	StateHealthy      = "healthy"
	StateDegraded     = "degraded"
	StateReconnecting = "reconnecting"
	StateOffline      = "offline"
)

type latencyPreset struct {
	streamWindow int
	connWindow   int
	keepAlive    time.Duration
	heartbeat    time.Duration
	udpBufSize   int
}

var latencyPresets = map[string]latencyPreset{
	"low": {
		streamWindow: 16 * 1024 * 1024,
		connWindow:   32 * 1024 * 1024,
		keepAlive:    20 * time.Second,
		heartbeat:    5 * time.Second,
		udpBufSize:   8 * 1024 * 1024,
	},
}

func isKickedError(err error) (bool, string) {
	if err == nil {
		return false, ""
	}
	s := err.Error()
	if strings.Contains(s, "kicked by admin") {
		return true, "服务端将你踢出连线"
	}
	if strings.Contains(s, "replaced by new connection") {
		return true, "你已在其他设备登录，本连接被替换"
	}
	return false, ""
}

func isDebugMode() bool {
	return strings.ToLower(os.Getenv("HY_DEBUG")) == "true"
}

// probeTraceEnabled 直连**探针收发**的可观测开关（2026-09-27 真机 bug 的排查口）。
//
// ⚠️ 为什么单独给一个开关（而不复用 isDebugMode）：`HY_DEBUG=true` 会打开大量日志，
// 排查「试用期采不到样本」时噪声太大；本开关只开**探针级**那几行。
//
// 用法（真机：把环境变量设在客户端进程上即可，**不用改代码**）：
//
//	Windows PowerShell:  $env:HY2_PROBE_TRACE='true'; .\vpn-tool.exe ...
//	Linux/macOS:         HY2_PROBE_TRACE=true ./vpn-tool ...
//
// ⚠️ 它会每 `probeInterval`（5s）每条路径打一行 —— **只在排查时开**。
func probeTraceEnabled() bool {
	return strings.ToLower(os.Getenv("HY2_PROBE_TRACE")) == "true" || isDebugMode()
}

func isQUICDCDebug() bool {
	return strings.ToLower(os.Getenv("HY_QUICDCDEBUG")) == "true" ||
		strings.ToLower(os.Getenv("HY_QUICDC_DEBUG")) == "true"
}

// ========== 指纹存储 ==========

// fingerprintPath 返回某个服务器的指纹文件路径。
//
// ⭐ 安全审计 S33（High）：原实现是
//
//	safe := strings.ReplaceAll(serverIP, ":", "_")
//	safe = strings.ReplaceAll(safe, "/", "_")   // 反斜杠与 ".." 都没有过滤
//	return filepath.Join(dir, "fp_"+safe+".txt")
//
// 而 filepath.Join 会做**纯词法**的 ".." 归约，前缀 "fp_" 会被紧跟的
// 第一个 ".." 抵消掉，实测（Go 1.26 / Windows）：
//
//	"..\..\..\..\..\..\..\Users\Public\secret"  ->  C:\Users\Public\secret.txt
//
// serverIP 直接来自 .hy2 文件里的 server 字段（原来完全不校验），
// 因此导入一个恶意 .hy2 就能对任意 *.txt 做
// 「存在性探测（HasPinnedFingerprint）」「删除（清除指纹）」
// 「内容读取（GetPinnedFingerprint，已绑定到 webview JS）」。
//
// 现在改为对 serverIP 取 SHA-256 当文件名，与路径语义彻底解耦。
func fingerprintPath(serverIP string) string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	dir = filepath.Join(dir, "hy2link")
	_ = os.MkdirAll(dir, 0700)

	sum := sha256.Sum256([]byte(serverIP))
	return filepath.Join(dir, "fp_"+hex.EncodeToString(sum[:])+".txt")
}

func loadPinnedFingerprint(serverIP string) string {
	data, err := os.ReadFile(fingerprintPath(serverIP))
	if err != nil {
		return ""
	}
	fp := strings.ToLower(strings.TrimSpace(string(data)))
	// ⭐ 安全审计 S38：只接受合法的 SHA-256 十六进制串。
	//    指纹文件是非原子写入且错误被忽略过，截断/半写的文件会让
	//    后续的 known[:16] 切片越界 panic —— 而那里没有任何 recover。
	//    这里直接把不合格的内容当作「没有指纹」，同时下方也不再切片。
	if len(fp) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return ""
	}
	return fp
}

// savePinnedFingerprint 原子写入指纹文件。
// ⭐ 安全审计 S36/S38：原实现直接用 os.WriteFile，非原子且错误被忽略。
func savePinnedFingerprint(serverIP, fp string) error {
	path := fingerprintPath(serverIP)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(fp), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func clearPinnedFingerprint(serverIP string) error {
	path := fingerprintPath(serverIP)
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// 顺带清理可能残留的临时文件
	_ = os.Remove(path + ".tmp")
	return nil
}

func dumpTCPPacket(pkt []byte, direction string) {
	if !isDebugMode() {
		return
	}
	if len(pkt) < 40 {
		return
	}
	if (pkt[0]>>4)&0xF != 4 {
		return
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return
	}
	srcIP := net.IP(pkt[12:16]).String()
	dstIP := net.IP(pkt[16:20]).String()
	tcp := pkt[ihl:]
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	dataOffset := int(tcp[12]>>4) * 4
	if dataOffset < 20 {
		dataOffset = 20
	}
	payloadLen := len(tcp) - dataOffset
	if payloadLen < 0 {
		payloadLen = 0
	}
	flags := tcp[13]
	var flagStr string
	if flags&0x02 != 0 {
		flagStr += "S"
	}
	if flags&0x10 != 0 {
		flagStr += "A"
	}
	if flags&0x01 != 0 {
		flagStr += "F"
	}
	if flags&0x04 != 0 {
		flagStr += "R"
	}
	if flags&0x08 != 0 {
		flagStr += "P"
	}
	log.Printf("[TCP-%s] %s:%d → %s:%d len=%d flags=%s",
		direction, srcIP, srcPort, dstIP, dstPort, payloadLen, flagStr)
}

// ⭐ udpConnFactory：hysteria 认证连接创建 UDP socket 时，在这里套 Salamander
type udpConnFactory struct {
	bufSize int
	obfsPSK []byte // nil 表示不混淆
}

func (f *udpConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	if f.bufSize > 0 {
		_ = conn.SetReadBuffer(f.bufSize)
		_ = conn.SetWriteBuffer(f.bufSize)
	}
	if f.obfsPSK != nil {
		return obfs.WrapPacketConnSalamander(conn, f.obfsPSK)
	}
	return conn, nil
}

type HealthTracker struct {
	mu              sync.RWMutex
	lastRecvTime    time.Time
	lastPongTime    time.Time
	consecutiveFail int
	state           string
	lastStateChange time.Time
}

func NewHealthTracker() *HealthTracker {
	now := time.Now()
	return &HealthTracker{
		lastRecvTime:    now,
		lastPongTime:    now,
		state:           StateHealthy,
		lastStateChange: now,
	}
}

func (h *HealthTracker) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.lastRecvTime = now
	h.lastPongTime = now
	h.consecutiveFail = 0
	h.state = StateHealthy
	h.lastStateChange = now
}

func (h *HealthTracker) OnAnyDataReceived() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastRecvTime = time.Now()
	h.consecutiveFail = 0
	h.recomputeState()
}

func (h *HealthTracker) OnPongReceived() {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.lastRecvTime = now
	h.lastPongTime = now
	h.consecutiveFail = 0
	h.recomputeState()
}

func (h *HealthTracker) OnHeartbeatFailure() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.consecutiveFail++
	h.recomputeState()
}

func (h *HealthTracker) recomputeState() {
	sinceLastRecv := time.Since(h.lastRecvTime)
	newState := StateHealthy
	switch {
	case sinceLastRecv > offlineThreshold:
		newState = StateOffline
	case sinceLastRecv > reconnectThreshold:
		newState = StateReconnecting
	case sinceLastRecv > 30*time.Second:
		newState = StateDegraded
	default:
		newState = StateHealthy
	}
	if newState != h.state {
		h.state = newState
		h.lastStateChange = time.Now()
		log.Printf("📊 [健康状态] %s（上次数据 %v 前）",
			newState, sinceLastRecv.Truncate(time.Second))
	}
}

func (h *HealthTracker) State() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recomputeState()
	return h.state
}

func (h *HealthTracker) Snapshot() map[string]interface{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recomputeState()
	return map[string]interface{}{
		"state":           h.state,
		"lastRecvAgo":     time.Since(h.lastRecvTime).Seconds(),
		"lastPongAgo":     time.Since(h.lastPongTime).Seconds(),
		"consecutiveFail": h.consecutiveFail,
	}
}

type Hysteria2Client struct {
	hysteriaClient client.Client
	ctx            context.Context
	cancel         context.CancelFunc

	dataConn   *quic.Conn
	dataCtx    context.Context
	dataCancel context.CancelFunc

	matchConn   *quic.Conn
	matchCtx    context.Context
	matchCancel context.CancelFunc

	gameTCPConn   *quic.Conn
	gameTCPCtx    context.Context
	gameTCPCancel context.CancelFunc

	gameConn   *quic.Conn
	gameCtx    context.Context
	gameCancel context.CancelFunc

	ctrlConn   *quic.Conn
	ctrlCtx    context.Context
	ctrlCancel context.CancelFunc

	// ⭐ P2SP 阶段 1：隧道内信令流（h3-ctrl 上的第 4 条 stream）
	//
	// 通道形态是「**常驻读协程** + 写请求等响应」，不是「发一问读一答」：
	// 打洞要求双方同时发包，服务端必须能把「A 想连你」主动推给 B，
	// 而 B 不读流就永远收不到（详见 signal.go 顶部）。
	signalMu        sync.Mutex         // 保护下面 5 个字段
	signalStream    *quic.Stream       // 当前信令流（nil = 没有）
	signalGen       chan struct{}      // 当前流的代际：流结束时 close，唤醒所有等待者
	signalPending   chan signalMessage // 当前等待应答的槽位（nil = 无人等待）
	signalDeadUntil time.Time          // 流被对端断开后的重开冷却截止
	signalPush      func(SignalPush)   // 服务端主动下行的处理钩子（1b）
	signalOpenMu    sync.Mutex         // 串行化「打开流」，避免并发开出两条
	signalReqMu     sync.Mutex         // 串行化「请求—响应」往返（协议无请求 ID）
	signalWriteMu   sync.Mutex         // 串行化写入（预留多写者，见 signal.go）
	signalReaders   int32              // 活跃读协程数（atomic，诊断/测试用）

	// ⭐ D1-a：「服务端不支持 peers」的**单次探测缓存**（atomic）。
	//
	// 语义（方案 §7）：新客户端 + **旧服务端** ⇒ 回 `unknown message type`；
	// 把该结论缓存起来，**本次连接内只探测一次**（否则每次预打洞都去打一个不支持的服务端）。
	// ⚠️ **超时不缓存**（超时可能是「服务端忙/网络慢」被误判成「不支持」⇒ 永久放弃）；
	// 且 `resetSignalStream`（重连/换流）时清零，下次重连可再试。
	peersUnsupported atomic.Bool

	// ⭐ P2SP 阶段 1b：打洞会话管理器 + 直连自签证书
	//
	// punchMu 只保护「指针/证书」这几个字段本身；打洞会话内部的并发
	// 由 punchManager 自己的锁与「状态迁移单 goroutine」保证（见 punch.go 头注释）。
	punchMu    sync.Mutex
	punchMgr   *punchManager
	directCert *tls.Certificate
	directFP   string
	// pendingP2PStatus 在管理器启动之前设置的处理器（Connect 时补挂）
	pendingP2PStatus func(P2PStatus)

	// ⭐ P2SP 阶段 1b-2A：直连路径管理（触发/路由/切换/回切）
	//   同样受 punchMu 保护（生命周期与 punchMgr 一致：P2P 生效时建，Close 时停）
	pathMgr *pathManager

	// lastRelayRTT 中继 RTT（ns，由心跳 RTT 更新），供「直连 vs 中继」对比显示
	lastRelayRTT atomic.Int64

	// natRefreshMu 串行化「NAT 重探测 + 重新登记」（1b-2A：地址变化后重试用）
	natRefreshMu sync.Mutex

	serverIP   string
	port       int
	portVPN    int
	username   string
	password   string
	tunDevice  *tun.TUNDevice
	assignedIP string
	subnetMask string
	useDHCP    bool
	staticIP   string
	staticMask string
	mu         sync.Mutex
	connected  bool

	// ⭐ 1b-4 第 2 步-A：对端质量表（内存 + 进程内 TTL，不落盘）。
	//
	// ⚠️ 生命周期契约：**唯一 new 点是 NewHysteria2Client**（见该函数），
	// 跨重连存活 ⇒ 「重连不清空」。Connect/cleanupPartial/stopPunchManager **一律不得重置**
	// （Connect 里已有 health.Reset()，**不要**照抄给这个字段加 Reset）。
	quality *peerTable

	skipCertVerify bool
	serverCertMode string
	serverHostname string

	// ⭐ Salamander 混淆设置
	obfsEnabled  bool
	obfsPassword string

	// ⭐ 5 条自定义 QUIC 连接共享的已混淆 UDP socket / Transport
	sharedUDPConn   *net.UDPConn
	sharedTransport *quic.Transport

	serverSplitEnabled bool
	serverSplitPorts   map[uint16]bool

	udpMatchRanges      []portRange
	udpUnreliableRanges []portRange

	dataCtrlStream *quic.Stream
	tcpStream      *quic.Stream
	tcpWriteMu     sync.Mutex
	udpStream      *quic.Stream
	udpWriteMu     sync.Mutex

	matchStream  *quic.Stream
	matchWriteMu sync.Mutex

	gameTCPStream  *quic.Stream
	gameTCPWriteMu sync.Mutex

	gameDatagramReady atomic.Bool

	gameCC *qcong.QUICDCController

	ctrlCtrlStream *quic.Stream
	icmpStream     *quic.Stream
	icmpWriteMu    sync.Mutex
	hbStream       *quic.Stream
	hbWriteMu      sync.Mutex

	health    *HealthTracker
	closeOnce sync.Once

	tunWriteChan chan []byte

	tcpSendChan     chan []byte
	matchSendChan   chan []byte
	gameTCPSendChan chan []byte
	gameUDPSendChan chan []byte
	udpSendChan     chan []byte
	icmpSendChan    chan []byte

	kickedMu     sync.Mutex
	kicked       bool
	kickedReason string

	// ⭐ 延迟测量
	pingMu         sync.Mutex
	lastPingSentAt time.Time
	lastRTT        time.Duration
	lastRTTAt      time.Time

	// ⭐ 新增（P2SP 阶段 0）
	//
	// p2pLocalEnabled  本机开关（来自 ClientConfig.P2PEnabled，默认 false）
	// p2pServerEnabled 服务端开关（DHCP 应答第 11 段，旧服务端恒为 false）
	// 两者都为真时才认为 P2P 真正启用 —— 服务端与客户端各自都保留否决权。
	p2pLocalEnabled  bool
	p2pServerEnabled bool

	natOnce   sync.Once
	natMu     sync.RWMutex
	natResult NATProbeResult
	// builtinSTUNPorts 服务端内置 STUN 端点端口（DHCP 第 12 段；为空表示服务端没开）
	builtinSTUNPorts []int
	natReady         bool
}

func NewHysteria2Client(serverIP string, port, portVPN int, username, password string,
	useDHCP bool, staticIP, staticMask string, skipCertVerify bool) *Hysteria2Client {

	ctx, cancel := context.WithCancel(context.Background())
	dataCtx, dataCancel := context.WithCancel(context.Background())
	matchCtx, matchCancel := context.WithCancel(context.Background())
	gameTCPCtx, gameTCPCancel := context.WithCancel(context.Background())
	gameCtx, gameCancel := context.WithCancel(context.Background())
	ctrlCtx, ctrlCancel := context.WithCancel(context.Background())

	if portVPN == 0 {
		portVPN = 8444
	}

	// ⭐ 1b-4 第 2 步-A：`quality: newPeerTable()` 是**对端质量表的唯一 new 点**。
	//    ⚠️ 绝不要在 startPunchManager / Connect / cleanupPartial 里重建 ——
	//    「重连不清空」这条拍板约束的唯一保证点就是这一行（见实施计划 §9.2.1）。
	return &Hysteria2Client{
		ctx:             ctx,
		cancel:          cancel,
		dataCtx:         dataCtx,
		dataCancel:      dataCancel,
		matchCtx:        matchCtx,
		matchCancel:     matchCancel,
		gameTCPCtx:      gameTCPCtx,
		gameTCPCancel:   gameTCPCancel,
		gameCtx:         gameCtx,
		gameCancel:      gameCancel,
		ctrlCtx:         ctrlCtx,
		ctrlCancel:      ctrlCancel,
		serverIP:        serverIP,
		port:            port,
		portVPN:         portVPN,
		username:        username,
		password:        password,
		useDHCP:         useDHCP,
		staticIP:        staticIP,
		staticMask:      staticMask,
		skipCertVerify:  skipCertVerify,
		health:          NewHealthTracker(),
		quality:         newPeerTable(),
		tunWriteChan:    make(chan []byte, 512),
		tcpSendChan:     make(chan []byte, 512),
		matchSendChan:   make(chan []byte, 512),
		gameTCPSendChan: make(chan []byte, 512),
		gameUDPSendChan: make(chan []byte, 512),
		udpSendChan:     make(chan []byte, 512),
		icmpSendChan:    make(chan []byte, 256),
	}
}

// ⭐ SetObfs 设置 Salamander 混淆（必须在 Connect 之前调用）
func (c *Hysteria2Client) SetObfs(enabled bool, password string) {
	c.obfsEnabled = enabled
	c.obfsPassword = password
}

// ⭐ IsObfsEnabled 供 UI 查询
func (c *Hysteria2Client) IsObfsEnabled() bool {
	return c.obfsEnabled
}

// ========== P2SP 阶段 0：P2P 开关与 NAT 探测 ==========

// SetP2P 设置本机 P2P 开关（来自 ClientConfig.P2PEnabled）。
//
// 连接前调用时只记值；连接后调用会**立即生效**（关掉时清空路由并关闭直连路径），
// 因为内部走 ApplyP2PLocal（详见那里对开/关两种切换的语义说明）。
func (c *Hysteria2Client) SetP2P(enabled bool) {
	c.ApplyP2PLocal(enabled)
}

// P2PLocalEnabled 本机开关
func (c *Hysteria2Client) P2PLocalEnabled() bool { return c.p2pLocalEnabled }

// P2PServerEnabled 服务端下发的开关（DHCP 应答第 11 段；旧服务端恒为 false）
func (c *Hysteria2Client) P2PServerEnabled() bool { return c.p2pServerEnabled }

// P2PEffective 是否真正启用 P2P。
//
// ⭐ 1b-2A（UI 块）：**服务端开关 && 本机开关**，两者都开才生效。
//   - 服务端开关（DHCP 应答第 11 段）是权威：它关着，客户端连 NAT 探测都不做；
//   - 本机开关（客户端「高级选项 → 禁用 P2P」）是**本机否决**：
//     它关着时，即使服务端允许，本机也不打洞、不建直连（流量全走中继）。
//
// 运行期切换由 ApplyP2PLocal 处理（关掉时会立刻清空路由表并关闭已有直连路径）。
func (c *Hysteria2Client) P2PEffective() bool {
	return c.p2pServerEnabled && c.p2pLocalEnabled
}

// ApplyP2PLocal 设置本机 P2P 开关并**立即生效**（运行期切换用；连接前调用也安全）。
//
// 语义（与验收要求逐条对应）：
//   - 开→关：清空路由表 + 关闭已有直连路径（流量立刻回中继）；
//   - 关→开：**不主动触发**任何打洞，等流量驱动（下一个发给对端 VIP 的包）。
func (c *Hysteria2Client) ApplyP2PLocal(enabled bool) {
	c.punchMu.Lock()
	changed := c.p2pLocalEnabled != enabled
	c.p2pLocalEnabled = enabled
	pm := c.pathMgr
	c.punchMu.Unlock()

	log.Printf("📡 [HARP] 本机 P2P 开关: %v（参与判定）", enabled)
	if !changed {
		return
	}
	if !enabled && pm != nil {
		// 关掉：立刻摘掉所有路由并关闭路径（中继从未被拆掉，所以这是零等待切换）
		pm.ClearAll("本机已禁用 P2P")
		log.Printf("📴 [HARP] 本机已禁用 P2P：已清空路由表并关闭全部直连路径（流量回中继）")
		return
	}
	if enabled {
		log.Printf("🔗 [HARP] 本机已启用 P2P：等待流量驱动触发（不会主动对所有对端打洞）")
	}
}

// controlledP2PEnabled 打洞是否被允许（= 服务端开关 && 本机开关）
func (c *Hysteria2Client) controlledP2PEnabled() bool {
	return c.P2PEffective()
}

// SetP2PStatusHandler 注册直连状态回调（app 层把它转成 Wails 事件 "p2p:status"）。
//
// ⚠️ 回调可能从**多个 goroutine**触发（会话 goroutine / 事件 goroutine），实现方需自行保证并发安全；
// 回调里不要做耗时操作（会拖慢状态机）。
func (c *Hysteria2Client) SetP2PStatusHandler(fn func(P2PStatus)) {
	c.punchMu.Lock()
	mgr := c.punchMgr
	c.punchMu.Unlock()
	if mgr == nil {
		// 还没启动（未连接）：先记录下来，startPunchManager 时会补上
		c.pendingP2PStatus = fn
		return
	}
	mgr.setStatusHandler(fn)
}

// startPunchManager 建立并启动打洞管理器（Connect 时调用，幂等）
func (c *Hysteria2Client) startPunchManager() {
	c.punchMu.Lock()
	defer c.punchMu.Unlock()
	if c.punchMgr != nil {
		return
	}
	mgr := newPunchManager(c)
	if c.pendingP2PStatus != nil {
		mgr.setStatusHandler(c.pendingP2PStatus)
	}
	c.punchMgr = mgr
	mgr.start()

	// ⭐ 1b-2A：直连路径管理器（触发 → 路由 → 切换 → 回切）。
	//    与打洞管理器同生命周期；它自己不发包，只在「有流量要发给某个对端 VIP」时
	//    触发一次打洞，成功后把该对端加入路由表（写协程按表分流）。
	pm := newPathManager(c)
	c.pathMgr = pm
	pm.start()
	mgr.setPathManager(pm)
	// ⭐ 1b-4 第 2 步-A：把**同一张**质量表注入两个短生命周期管理器（只读引用，绝不重建）。
	//    punchManager 写（会话结束）、pathManager 读（试用期长短 + 软跳过）。
	//
	// ⚠️ 这里**不能**调 `c.qualityTable()`：本函数已持有 `c.punchMu`，而那个方法也要取
	//    `c.punchMu` ⇒ 自死锁（非重入互斥锁；1b-2A 在 `pathMgr` 上踩过同款，构建期测试直接超时）。
	//    生产路径上该字段已由 `NewHysteria2Client` 建好；这里只对「测试手工构造的 client」兜底。
	tbl := c.quality
	if tbl == nil {
		tbl = newPeerTable()
		c.quality = tbl
	}
	mgr.setQualityTable(tbl)
	pm.setQualityTable(tbl)
	log.Printf("📡 [打洞] 打洞管理器已启动（P2P 生效=%v，直连路径管理已启用）", c.P2PEffective())
}

// stopPunchManager 关闭打洞管理器与直连路径管理器（Close / cleanupPartial 调用，幂等）
func (c *Hysteria2Client) stopPunchManager() {
	c.punchMu.Lock()
	mgr := c.punchMgr
	pm := c.pathMgr
	c.punchMgr = nil
	c.pathMgr = nil
	c.punchMu.Unlock()
	// ⚠️ 顺序：先停路径管理（清空路由表 → 写协程立刻回中继），再停打洞会话
	if pm != nil {
		pm.close()
		log.Printf("📴 [HARP] 直连路径管理已停止（所有路径已关闭）")
	}
	if mgr != nil {
		mgr.close()
		log.Printf("📴 [打洞] 打洞管理器已停止")
	}
}

// pathManagerOrNil 取当前路径管理器（未连接/P2P 关闭时为 nil）
func (c *Hysteria2Client) pathManagerOrNil() *pathManager {
	c.punchMu.Lock()
	defer c.punchMu.Unlock()
	return c.pathMgr
}

// qualityTable 取对端质量表（**永不为 nil**：在 NewHysteria2Client 里 new）。
//
// ⚠️ 锁契约（review 追问 1 的全仓审计结论）：
//   - 本方法是**唯一取 `c.punchMu`** 的取表入口；因此**调用方绝不能在持有 `punchMu` 的
//     函数里调它** —— 那就是非重入锁自死锁（`startPunchManager` 踩过，见那里的注释）；
//   - 反过来，`punchManager.qualityTable()` 与 `pathManager.qualityTable()` 都只是
//     `atomic.Pointer.Load()`（**不取任何锁**）⇒ 它们可以在持锁上下文里安全调用。
//     全仓审计（2026-09）：持 `punchMu` 而调取表入口的调用点 = **0 处**。
//
// ⚠️ 惰性兜底（`if c.quality == nil`）的定位：**只为覆盖「测试里手工 `&Hysteria2Client{}`」**。
// 该分支在调用方的 `punchMu` 临界区内执行，所以两次 `new` 不会同时发生（指针写入受锁保护），
// 但「A 建的表被 B 的 new 覆盖」在理论上可能（两者各自持有不同实例）。
// 生产路径上 `c.quality` 由构造函数建好 ⇒ 该分支**永不触发**；
// ⚠️ 因此也**明令禁止**任何代码把它置回 nil（那会让上述理论风险变成真风险）。
func (c *Hysteria2Client) qualityTable() *peerTable {
	c.punchMu.Lock()
	defer c.punchMu.Unlock()
	if c.quality == nil {
		c.quality = newPeerTable()
	}
	return c.quality
}

// PunchTo 向指定对端 VIP 发起一次直连尝试（**异步**，结果通过状态回调/事件给出）。
//
// 返回 attemptId 用于日志关联；立即错误只覆盖「前置条件不满足」这一类。
func (c *Hysteria2Client) PunchTo(peerVIP string) (string, error) {
	c.punchMu.Lock()
	mgr := c.punchMgr
	c.punchMu.Unlock()
	if mgr == nil {
		// 区分三种「没有管理器」：本机否决 / 服务端没开 / 还没连上。
		// 手工验证与用户排障时这三句话的差别很重要（要改的地方完全不同）。
		return "", c.p2pUnavailableErr()
	}
	return mgr.PunchTo(peerVIP)
}

// PunchSessionState 查询某次尝试的当前状态（诊断/UI 用；找不到返回 "", false）
func (c *Hysteria2Client) PunchSessionState(attemptID string) (string, bool) {
	c.punchMu.Lock()
	mgr := c.punchMgr
	c.punchMu.Unlock()
	if mgr == nil {
		return "", false
	}
	mgr.mu.Lock()
	s := mgr.sessions[attemptID]
	mgr.mu.Unlock()
	if s == nil {
		return "", false
	}
	st, _ := s.state.Load().(string)
	return st, true
}

// DirectFingerprint 本机直连证书指纹（诊断用；不存在时返回 ""）
func (c *Hysteria2Client) DirectFingerprint() string {
	c.punchMu.Lock()
	defer c.punchMu.Unlock()
	return c.directFP
}

// NATResult 返回 NAT 探测结果；Ready 为 false 表示尚未探测完成。
func (c *Hysteria2Client) NATResult() (res NATProbeResult, ready bool) {
	c.natMu.RLock()
	defer c.natMu.RUnlock()
	return c.natResult, c.natReady
}

// NATType 返回 NAT 类型标签；未探测完成时返回 unknown。
func (c *Hysteria2Client) NATType() NATType {
	res, ready := c.NATResult()
	if !ready {
		return NATUnknown
	}
	return res.Type
}

// noteNATReprobed 本机 NAT 重探测**成功**（拿到了新的公网地址）时调用（pathHost 接口方法）。
//
// ⭐ 1b-4 第一步 第 2 条重置：本机公网地址变了 ⇒ 之前所有对端的失败原因
// （punch-timeout / nat-symmetric / peer-no-punch-addr）都可能不再成立，
// 所以清掉**全部**对端的失败记录，让它们下一轮从第 0 档重试。
//
// ⚠️ 锁契约：只取 pathMgr 的 punchMu（短暂）与 pathManager 自己的 m.mu（在 resetAllBackoff 内）；
//
//	不做 I/O、不回调，调用点在调度器 goroutine 上（打洞尝试内部），不会拖慢热路径。
func (c *Hysteria2Client) notifyNATReprobed() {
	pm := c.pathManagerOrNil()
	if pm == nil {
		return
	}
	pm.ResetBackoffAll("本机 NAT 重探测成功，公网地址已更新")
}

// noteAssignedIP 记录隧道地址；**地址变化**时清掉全部对端失败记录。
//
// ⭐ 1b-4 第一步 第 3 条重置（VIP 变更）：VIP 是直连的路由键与仲裁依据，
// 换了 VIP ⇒ 旧的路由/仲裁/失败记录全部作废（重连时通常同时发生）。
//
// ⚠️ 锁契约：只取 punchMu（取 pathMgr 引用）+ pathManager 的 m.mu；无 I/O。
func (c *Hysteria2Client) noteAssignedIP(ip string) {
	if ip == "" || ip == c.assignedIP {
		return
	}
	c.assignedIP = ip
	pm := c.pathManagerOrNil()
	if pm == nil {
		return
	}
	pm.ResetBackoffAll("本机隧道地址(VIP)变更：" + ip)
}

// NATPublicAddr 返回探测到的公网地址 "ip:port"；未探测完成时为空。
func (c *Hysteria2Client) NATPublicAddr() string {
	res, ready := c.NATResult()
	if !ready {
		return ""
	}
	return res.PublicAddr
}

// startNATDetection 异步探测 NAT 类型。
//
// ⭐ 约束（任务书 0.1）：
//   - 只用临时 UDP socket，绝不复用 sharedUDPConn；
//   - 不阻塞连接流程（放到 goroutine 里，失败只记日志）；
//   - P2P 未启用时**完全跳过**（不发任何 STUN 包），
//     这样「关掉 P2P 时行为与以前一模一样」。
func (c *Hysteria2Client) startNATDetection() {
	if !c.P2PEffective() {
		log.Printf("🌐 [NAT] P2P 未启用（服务端开关=%v，本机开关=%v），跳过 NAT 探测",
			c.p2pServerEnabled, c.p2pLocalEnabled)
		return
	}

	c.natOnce.Do(func() {
		go func() {
			log.Println("🌐 [NAT] 开始探测 NAT 类型（临时 UDP socket，独立于隧道）...")

			// 复用 dataCtx：Close()/cleanupPartial() 取消它，探测随之退出，
			// 临时 socket 由 detectNAT 内部的 defer 关闭。
			//
			// ⭐ P2SP 阶段 1b-1 补丁：STUN 列表 = **服务端内置端点优先** + 公共 STUN 备选。
			res := detectNAT(c.dataCtx, c.stunServerList())

			c.natMu.Lock()
			c.natResult = res
			c.natReady = true
			c.natMu.Unlock()

			// ⭐ 验收要求：连接时打印这一行
			log.Printf("🌐 [NAT] 类型: %s", res.Type)
			if res.PublicAddr != "" {
				log.Printf("🌐 [NAT] 公网地址: %s（映射端口=%v，STUN 响应=%d 台，映射与目的地址无关=%v）",
					res.PublicAddr, res.ObservedPorts, res.RespondedServers, res.MappingIndependent)
			}
			if res.Err != nil {
				log.Printf("🌐 [NAT] 探测未完整成功（已优雅降级，不影响连接）: %v", res.Err)
			}

			// ⭐ P2SP 阶段 1：拿到公网地址后把自己登记到服务端，
			//    这样对端就能通过信令查到我的地址（失败只记日志）
			c.registerSignalSelf()
		}()
	})
}

func (c *Hysteria2Client) markKicked(reason string) {
	c.kickedMu.Lock()
	if c.kicked {
		c.kickedMu.Unlock()
		return
	}
	c.kicked = true
	c.kickedReason = reason
	c.kickedMu.Unlock()

	log.Printf("🚫 [客户端] %s", reason)
	go func() {
		_ = c.Close()
	}()
}

func (c *Hysteria2Client) IsKicked() (bool, string) {
	c.kickedMu.Lock()
	defer c.kickedMu.Unlock()
	return c.kicked, c.kickedReason
}

func (c *Hysteria2Client) isUDPMatchPort(port uint16) bool {
	for _, r := range c.udpMatchRanges {
		if r.contains(port) {
			return true
		}
	}
	return false
}

func (c *Hysteria2Client) isUDPUnreliablePort(port uint16) bool {
	for _, r := range c.udpUnreliableRanges {
		if r.contains(port) {
			return true
		}
	}
	return false
}

// ========== 证书验证 ==========

// verifyPin 通过 TOFU 指纹固定校验服务端证书。
//
// ⭐ 安全审计 S3 / S36 / S38：
//   - 「解析失败就放行」改为返回错误；
//   - 指纹保存失败必须视为**致命**错误（原实现只打一行日志，
//     写不进去时每次连接都会退化成「首次连接」→ 指纹保护永久失效，失败开放）；
//   - 打印与比较完整指纹，不再做 `known[:16]` / `got[:16]` 切片
//     （指纹文件被截断时那会 panic，而 TLS 回调里没有 recover）。
func (c *Hysteria2Client) verifyPin() func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if c.skipCertVerify {
			return nil
		}
		if len(rawCerts) == 0 {
			return fmt.Errorf("服务端未提供证书")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("解析服务端证书失败: %w", err)
		}
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return fmt.Errorf("证书已过期（%v ~ %v）", cert.NotBefore, cert.NotAfter)
		}

		fp := sha256.Sum256(rawCerts[0])
		got := hex.EncodeToString(fp[:])

		known := loadPinnedFingerprint(c.serverIP)
		if known == "" {
			// 首次连接：TOFU 固定。
			// TODO(S36 剩余部分)：目前是「静默固定 + 醒目日志」，
			//  理想的 TOFU 应当弹出指纹让用户确认后再固定；
			//  这需要 UI 侧配合（弹出 + 阻塞等待用户选择），留待下一步。
			if err := savePinnedFingerprint(c.serverIP, got); err != nil {
				return fmt.Errorf("保存服务端指纹失败，拒绝以不安全状态继续连接: %w", err)
			}
			log.Printf("📌 [客户端] 首次连接 %s，已记录服务端证书指纹:", c.serverIP)
			log.Printf("           SHA-256 = %s", got)
			log.Printf("           如与管理员公布的不一致，请立即断开并清除该指纹。")
			return nil
		}
		if !strings.EqualFold(known, got) {
			return fmt.Errorf("⚠️ 服务端证书指纹不匹配\n"+
				"  已知: %s\n"+
				"  收到: %s\n"+
				"可能被中间人攻击，或服务端重新生成过证书。\n"+
				"如确认安全，请在客户端清除已保存的指纹后重试。",
				known, got)
		}
		return nil
	}
}

// verifyPinOrCA 用于**认证（引导）连接**的证书校验。
//
// ⭐ 安全审计 S3（Critical）：原实现是
//
//	cert, err := x509.ParseCertificate(rawCerts[0])
//	if err != nil { return nil }                                    // 解析失败 → 放行
//	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) { return nil }  // 非自签 → 放行
//	return c.verifyPin()(rawCerts, nil)
//
// 配合调用处的 `InsecureSkipVerify: true`，它等于「**任何非自签证书都无条件接受**」：
// 既不验证签发链，也不验证域名与有效期。攻击者只要持有一张任意 CA 签发的证书
// （例如自己域名的 Let's Encrypt 证书）就能中间人这条连接，
// 而 hysteria 的认证串 `user:pass:vn=x.y.z` 是明文送进去的 → 口令泄露。
//
// 引导连接的固有难点是：此刻还不知道服务端的 ACME 域名
// （serverHostname 要等 DHCP 应答才拿到），无法做主机名校验。
// 因此正确做法是：**引导连接一律使用 TOFU 指纹固定**（自签与 ACME 一视同仁）；
// 后续的数据面连接再按 DHCP 下发的 certMode/hostname 走严格 CA 校验
// —— `buildTLSConfig` 已经是这么做的，那里不需要改动。
func (c *Hysteria2Client) verifyPinOrCA() func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if c.skipCertVerify {
			return nil
		}
		// 统一走指纹固定：绝不因为「证书不是自签」就放行。
		return c.verifyPin()(rawCerts, nil)
	}
}

func (c *Hysteria2Client) buildTLSConfig(nextProtos []string) *tls.Config {
	cfg := &tls.Config{
		NextProtos: nextProtos,
	}

	if c.skipCertVerify {
		cfg.InsecureSkipVerify = true
		return cfg
	}

	if c.serverCertMode == "acme" {
		cfg.ServerName = c.serverHostname
		return cfg
	}

	cfg.InsecureSkipVerify = true
	cfg.ServerName = c.serverHostname
	cfg.VerifyPeerCertificate = c.verifyPin()
	return cfg
}

// ========== 指纹管理（供 UI 调用） ==========

func (c *Hysteria2Client) ClearPinnedFingerprint() error {
	return clearPinnedFingerprint(c.serverIP)
}

func (c *Hysteria2Client) PinnedFingerprint() string {
	return loadPinnedFingerprint(c.serverIP)
}

func ClearPinnedFingerprintByIP(serverIP string) error {
	if serverIP == "" {
		return fmt.Errorf("服务器地址为空")
	}
	return clearPinnedFingerprint(serverIP)
}

func HasPinnedFingerprint(serverIP string) bool {
	if serverIP == "" {
		return false
	}
	return loadPinnedFingerprint(serverIP) != ""
}

func GetPinnedFingerprintByIP(serverIP string) string {
	return loadPinnedFingerprint(serverIP)
}

// validateTunnelIPv4 校验服务端（或本地配置）下发的虚拟 IP 与掩码。
//
// ⭐ 安全审计 S34：这两个值会被直接用于
//  1. 配置本机 TUN 适配器地址；
//  2. 通过 `route add <net> mask <mask> <vip> if <idx>` 添加路由。
//
// 而 net.ParseIP 过于宽松：它接受 0.0.0.0、IPv6 字面量，
// 以及 255.0.255.0 这类非连续掩码。其中 mask=0.0.0.0 会让
// calculateNetwork 得到 0.0.0.0、maskToPrefix 得到 "0"，
// 于是客户端**自己**装上一整条默认路由指向隧道 —— 整机流量改道。
func validateTunnelIPv4(ip, mask string) error {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil || ipAddr.To4() == nil {
		return fmt.Errorf("无效的 IPv4 地址: %q", ip)
	}
	ip4 := ipAddr.To4()
	// 未指定 / 组播 / 广播地址都不该被当成隧道本机地址：
	// 0.0.0.0 会让 `netsh ... static 0.0.0.0 <mask>` 与本机网络配置打架。
	if ip4.IsUnspecified() {
		return fmt.Errorf("服务端下发了未指定地址: %s", ip)
	}
	if ip4.IsMulticast() {
		return fmt.Errorf("服务端下发了组播地址: %s", ip)
	}
	if ip4.Equal(net.IPv4bcast) {
		return fmt.Errorf("服务端下发了广播地址: %s", ip)
	}

	maskAddr := net.ParseIP(mask)
	if maskAddr == nil || maskAddr.To4() == nil {
		return fmt.Errorf("无效的 IPv4 掩码: %q", mask)
	}
	ones, bits := net.IPMask(maskAddr.To4()).Size()
	// Size() 对非连续掩码返回 (0, 0)
	if bits != 32 || ones < 8 || ones > 30 {
		return fmt.Errorf("不合理的掩码: %s（/%d，仅接受 /8–/30 的连续掩码）", mask, ones)
	}
	return nil
}

// ========== Connect ==========

// ⭐ 使用命名返回值 + defer 兜底，任何中途失败都会自动清理残留资源
func (c *Hysteria2Client) Connect() (retIP string, retErr error) {
	success := false
	defer func() {
		if !success {
			c.cleanupPartial()
		}
	}()

	ipAddr, err := net.ResolveIPAddr("ip4", c.serverIP)
	if err != nil {
		return "", fmt.Errorf("解析服务器地址失败（仅支持 IPv4）: %v", err)
	}
	serverIPv4 := ipAddr.IP.String()

	if serverIPv4 != c.serverIP {
		log.Printf("🌐 [客户端] 服务器地址 %s 解析为 IPv4: %s", c.serverIP, serverIPv4)
	}

	preset := latencyPresets[hardcodedLatencyMode]

	// ⭐ 认证连接混淆 PSK
	var authPSK []byte
	if c.obfsEnabled {
		if len(c.obfsPassword) < 4 {
			return "", fmt.Errorf("Salamander 混淆密码至少 4 字节")
		}
		authPSK = []byte(c.obfsPassword)
		log.Printf("🔒 [客户端] 认证连接将启用 Salamander 混淆")
	} else {
		log.Printf("⚠️ [客户端] Salamander 混淆未启用")
	}

	tlsCfg := client.TLSConfig{
		ServerName:            serverIPv4,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: c.verifyPinOrCA(),
	}
	quicCfg := client.QUICConfig{
		InitialStreamReceiveWindow:     uint64(preset.streamWindow),
		MaxStreamReceiveWindow:         uint64(preset.streamWindow),
		InitialConnectionReceiveWindow: uint64(preset.connWindow),
		MaxConnectionReceiveWindow:     uint64(preset.connWindow),
		MaxIdleTimeout:                 120 * time.Second,
		KeepAlivePeriod:                preset.keepAlive,
	}

	// ⭐ 服务端已停用全局密码（单用户模式）：必须使用「用户名:密码」认证。
	//    用户名还必须是服务端「用户管理」里存在的账户。
	if strings.TrimSpace(c.username) == "" {
		return "", fmt.Errorf("请填写用户名：服务端已停用全局密码，" +
			"客户端必须以「用户名 + 密码」认证（用户名见服务端的用户管理）")
	}
	authStr := c.username + ":" + c.password
	authStr = authStr + ":vn=" + ClientVersion

	hyCfg := &client.Config{
		ConnFactory: &udpConnFactory{
			bufSize: preset.udpBufSize,
			obfsPSK: authPSK,
		},
		ServerAddr: &net.UDPAddr{
			IP:   ipAddr.IP,
			Port: c.port,
		},
		Auth:            authStr,
		TLSConfig:       tlsCfg,
		QUICConfig:      quicCfg,
		BandwidthConfig: client.BandwidthConfig{},
		CongestionConfig: client.CongestionConfig{
			Type:       "bbr",
			BBRProfile: hardcodedBBRProfile,
		},
	}

	log.Printf("📈 [客户端] 延迟模式=%s(固定) BBR=%s(固定) 跳过证书验证=%v",
		hardcodedLatencyMode, hardcodedBBRProfile, c.skipCertVerify)

	cli, _, err := client.NewClient(hyCfg)
	if err != nil {
		return "", fmt.Errorf("hysteria 控制面连接失败: %v", err)
	}
	c.hysteriaClient = cli
	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()
	log.Printf("✅ hysteria 控制面已连接 %s:%d", serverIPv4, c.port)

	deviceID := uuid.New().String()
	var ip, mask string
	if c.useDHCP {
		dhcpConn, err := cli.TCP("10.0.0.1:9999")
		if err != nil {
			return "", fmt.Errorf("建立 DHCP 连接失败: %v", err)
		}
		defer dhcpConn.Close()

		_, err = dhcpConn.Write([]byte(deviceID + "\nREQUEST_IP"))
		if err != nil {
			return "", fmt.Errorf("发送 DHCP 请求失败: %v", err)
		}

		buf := make([]byte, 512)
		dhcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := dhcpConn.Read(buf)
		if err != nil {
			return "", fmt.Errorf("读取 DHCP 响应失败: %v", err)
		}
		response := strings.TrimSpace(string(buf[:n]))
		parts := strings.Split(response, ",")
		if len(parts) < 2 {
			return "", fmt.Errorf("无效 DHCP 响应: %s", response)
		}
		ip = strings.TrimSpace(parts[0])
		mask = strings.TrimSpace(parts[1])

		// ⭐ 安全审计 S34：原来只用 net.ParseIP 校验，它会放过
		// 0.0.0.0、IPv6 字面量，以及 255.0.255.0 这类非连续掩码。
		// 其中 mask=0.0.0.0 会让本机装上一条 0.0.0.0/0 默认路由指向隧道，
		// 整机流量改道（而服务端是能被中间人控制的输入端）。
		// 这里要求：合法 IPv4 + 掩码必须是合理范围内的连续前缀。
		if err := validateTunnelIPv4(ip, mask); err != nil {
			return "", err
		}

		c.serverSplitEnabled = false
		c.serverSplitPorts = make(map[uint16]bool)
		if len(parts) >= 3 && strings.TrimSpace(parts[2]) == "on" {
			c.serverSplitEnabled = true
			if len(parts) >= 4 {
				for _, ps := range strings.Split(parts[3], "|") {
					ps = strings.TrimSpace(ps)
					if n, err := strconv.Atoi(ps); err == nil && n > 0 && n <= 65535 {
						c.serverSplitPorts[uint16(n)] = true
					}
				}
			}
			if len(c.serverSplitPorts) == 0 {
				c.serverSplitPorts[22345] = true
				c.serverSplitPorts[443] = true
			}
		}

		c.udpMatchRanges = nil
		if len(parts) >= 6 && strings.TrimSpace(parts[4]) == "on" {
			c.udpMatchRanges = parsePortRanges("|", strings.Split(parts[5], "|"))
			if len(c.udpMatchRanges) == 0 {
				c.udpMatchRanges = append([]portRange(nil), defaultUDPMatchRanges...)
			}
		}

		c.udpUnreliableRanges = nil
		if len(parts) >= 8 && strings.TrimSpace(parts[6]) == "on" {
			c.udpUnreliableRanges = parsePortRanges("|", strings.Split(parts[7], "|"))
			if len(c.udpUnreliableRanges) == 0 {
				c.udpUnreliableRanges = append([]portRange(nil), defaultUDPUnreliableRanges...)
			}
		}

		c.serverCertMode = "selfsigned"
		c.serverHostname = serverIPv4
		if len(parts) >= 9 {
			mode := strings.TrimSpace(parts[8])
			if mode != "" {
				c.serverCertMode = mode
			}
		}
		if len(parts) >= 10 {
			hn := strings.TrimSpace(parts[9])
			if hn != "" {
				c.serverHostname = hn
			}
		}

		// ⭐ P2SP 阶段 0：第 11 段 = 服务端 P2P 开关（"on"/"off"）。
		//    旧服务端只发 10 段 → parseP2PFlag 安全返回 false，
		//    客户端行为与引入该功能之前完全一致（不会做 NAT 探测）。
		c.p2pServerEnabled = parseP2PFlag(parts)
		// ⭐ 1b-2A（UI 块）：本机开关**参与判定**（P2PEffective = 服务端 && 本机）
		log.Printf("📡 [HARP] 服务端 P2P 开关: %v（本机开关: %v，参与判定）",
			c.p2pServerEnabled, c.p2pLocalEnabled)

		// ⭐ P2SP 阶段 1b-1 补丁：第 12 段 = 服务端内置 STUN 端点端口（"3478|3479" / "off"）。
		//    国内公共 STUN 经常不可达，内置端点排到 STUN 列表首位可保证有观测点。
		c.builtinSTUNPorts = parseBuiltinSTUNPorts(parts)
		if len(c.builtinSTUNPorts) > 0 {
			log.Printf("📡 [HARP] 服务端内置 STUN 端点: %v（将作为 STUN 列表首位）", c.builtinSTUNPorts)
		}

		if c.serverCertMode == "acme" {
			if c.skipCertVerify {
				log.Printf("⚠️ [客户端] 服务端使用 ACME 证书，但『跳过证书验证』已开启，安全性降低")
			} else {
				log.Printf("🔐 [客户端] 服务端使用 ACME 证书，走系统 CA 验证 ServerName=%s", c.serverHostname)
			}
		} else {
			if c.skipCertVerify {
				log.Printf("⚠️ [客户端] 自签证书 + 跳过证书验证（无任何验证）")
			} else {
				log.Printf("🔐 [客户端] 自签证书 + Pin 指纹（TOFU）ServerName=%s", c.serverHostname)
			}
		}

		log.Printf("📡 DHCP 分配 IP: %s, 掩码: %s, TCP拆分: %v, 端口: %v, UDP匹配: %v, UDP不可靠: %v, 证书=%s",
			ip, mask, c.serverSplitEnabled, keysOf(c.serverSplitPorts),
			c.udpMatchRanges, c.udpUnreliableRanges, c.serverCertMode)
	} else {
		ip = c.staticIP
		mask = c.staticMask
		// ⭐ 安全审计 S34：静态 IP 同样必须严格校验
		if err := validateTunnelIPv4(ip, mask); err != nil {
			return "", err
		}
		c.serverSplitEnabled = false
		c.serverSplitPorts = make(map[uint16]bool)
		c.udpMatchRanges = nil
		c.udpUnreliableRanges = nil
		c.serverCertMode = "selfsigned"
		c.serverHostname = serverIPv4
	}

	// ⭐ 1b-4 第一步 第 3 条重置（VIP 变更）：**必须在 startPunchManager 之前**调用 ——
	//    它要拿的是「重启之前那个 pathManager」来清退避；而且这里也可能只是
	//    「同一次连接里的 DHCP 续约拿到同一个 IP」⇒ noteAssignedIP 内部按值比较后 no-op。
	c.noteAssignedIP(ip)
	c.subnetMask = mask

	tunDev, err := tun.CreateTUN("hy2-tun0", ip, mask, tunMTU)
	if err != nil {
		return "", fmt.Errorf("创建 TUN 失败: %v", err)
	}
	c.tunDevice = tunDev
	log.Printf("🔧 TUN 设备创建成功 (MTU=%d)", tunMTU)

	// ⭐ 创建 5 条自定义 QUIC 连接共享的已混淆 UDP socket / Transport
	if c.obfsEnabled {
		sharedUDPConn, err := net.ListenUDP("udp4", nil)
		if err != nil {
			return "", fmt.Errorf("创建数据面共享 UDP socket 失败: %v", err)
		}
		if preset.udpBufSize > 0 {
			_ = sharedUDPConn.SetReadBuffer(preset.udpBufSize)
			_ = sharedUDPConn.SetWriteBuffer(preset.udpBufSize)
		}
		wrapped, err := obfs.WrapPacketConnSalamander(sharedUDPConn, []byte(c.obfsPassword))
		if err != nil {
			sharedUDPConn.Close()
			return "", fmt.Errorf("创建数据面 Salamander 混淆器失败: %v", err)
		}
		c.sharedUDPConn = sharedUDPConn
		c.sharedTransport = &quic.Transport{Conn: wrapped}
		log.Printf("🔒 [客户端] 数据面已启用 Salamander 混淆（共享 UDP socket）")
	}

	dataConn, dataCtrlStream, tcpStream, udpStream, err := c.connectDataConn(serverIPv4, ip, preset)
	if err != nil {
		return "", fmt.Errorf("数据面连接失败: %v", err)
	}
	c.dataConn = dataConn
	c.dataCtrlStream = dataCtrlStream
	c.tcpStream = tcpStream
	c.udpStream = udpStream
	log.Printf("🚀 [客户端] 数据面(bulk)已建立")

	if len(c.udpMatchRanges) > 0 {
		matchConn, matchStream, err := c.connectMatchConn(serverIPv4, ip, preset)
		if err != nil {
			log.Printf("⚠️ [客户端] 匹配面连接失败: %v", err)
			c.udpMatchRanges = nil
		} else {
			c.matchConn = matchConn
			c.matchStream = matchStream
			log.Printf("🎯 [客户端] 匹配面已建立（Cubic）")
		}
	}

	if c.serverSplitEnabled {
		gameTCPConn, gameTCPStream, err := c.connectGameTCPConn(serverIPv4, ip, preset)
		if err != nil {
			log.Printf("⚠️ [客户端] 游戏 TCP 面连接失败: %v", err)
			c.serverSplitEnabled = false
		} else {
			c.gameTCPConn = gameTCPConn
			c.gameTCPStream = gameTCPStream
			log.Printf("🎮 [客户端] 游戏 TCP 面已建立（BBR / standard）")
		}
	}

	if len(c.udpUnreliableRanges) > 0 {
		gameConn, err := c.connectGameDatagramConn(serverIPv4, ip, preset)
		if err != nil {
			log.Printf("⚠️ [客户端] 游戏 UDP datagram 面连接失败: %v", err)
			c.udpUnreliableRanges = nil
		} else {
			c.gameConn = gameConn
			if c.gameDatagramReady.Load() {
				log.Printf("🎮 [客户端] 游戏 UDP datagram 面已建立（QUIC-DC）")
			} else {
				log.Printf("🎮 [客户端] 游戏 UDP datagram 面已建立但握手失败")
			}
		}
	}

	ctrlConn, ctrlCtrlStream, icmpStream, hbStream, err := c.connectCtrlConn(serverIPv4, ip, preset)
	if err != nil {
		return "", fmt.Errorf("控制面连接失败: %v", err)
	}
	c.ctrlConn = ctrlConn
	c.ctrlCtrlStream = ctrlCtrlStream
	c.icmpStream = icmpStream
	c.hbStream = hbStream
	log.Printf("🚀 [客户端] VPN 控制面已建立")

	c.health.Reset()

	// ⭐ P2SP 阶段 0：NAT 类型探测（异步；P2P 未启用时直接跳过）
	c.startNATDetection()

	// ⭐ P2SP 阶段 1b：打洞管理器（推送处理 + 直连会话）。
	// 只在 P2P 生效时启动：关闭时连队列和 goroutine 都不建。
	if c.P2PEffective() {
		c.startPunchManager()
	}

	// ⭐ P2SP 阶段 1：隧道内信令流（h3-ctrl 的第 4 条 stream）**不在这里开**。
	//
	// 两个原因（都是实打实的语义，不是风格问题）：
	//  ① 信令流要求「登记自己」时就带上公网地址，而此刻 NAT 探测刚开始；
	//  ② QUIC 里客户端开的流在**写入第一个字节之前对服务端不可见** ——
	//     开完流不写，服务端会一直卡在 AcceptStream 上直到超时放弃，
	//     之后就永远无法向这个客户端主动推送（打洞就废了）。
	// 所以改由 NAT 探测完成后的 registerSignalSelf() 惰性建立，
	// 开流后立刻写一帧 register（既登记、又让服务端看见这条流）。

	go c.TunWriteLoop()
	go c.tcpReceiveLoop(tcpStream)
	go c.udpReceiveLoop(udpStream)
	go c.icmpReceiveLoop(icmpStream)
	go c.heartbeatReceiveLoop(hbStream)

	go c.forwardData()
	go c.TCPWriteLoop()
	go c.UDPWriteLoop()
	go c.ICMPWriteLoop()

	if c.matchStream != nil {
		go c.matchReceiveLoop(c.matchStream)
		go c.MatchWriteLoop()
	}
	if c.gameTCPStream != nil {
		go c.gameTCPReceiveLoop(c.gameTCPStream)
		go c.GameTCPWriteLoop()
	}
	if c.gameDatagramReady.Load() {
		go c.gameDatagramReceiveLoop()
		go c.GameDatagramWriteLoop()
		if c.gameCC != nil {
			go c.gameConnStatsLoop()
		}
	}

	go c.heartbeatLoop(hbStream, preset.heartbeat)

	// ⭐ D1-a：**握手成功后**清掉「服务端不支持 peers」的缓存（review 追问 2 的定稿选择）。
	//
	// 语义：该缓存的**作用域 = 一次连接**，不是客户端。同一个 `Hysteria2Client`
	// 实例可以对**不同服务端**发起连接（用户切节点）；若把「旧服务端不支持」的结论
	// 带过去 ⇒ 新服务端明明支持也永远不再试 ⇒ 功能永久失效（功能性 bug）。
	//
	// ⚠️ 为什么放在**握手成功后**而不是函数开头（定稿理由）：
	//   - 放在开头 ⇒ 每次**失败的**重试也会清缓存 ⇒ 对「同一个不支持的服务端」反复
	//     试错时，每次都白打一次 peers 往返（缓存等于失效）；
	//   - 放在成功处 ⇒ 「失败重试」仍复用缓存（服务端没变，结论仍有效），
	//     只有**真的换了一个连上的服务端**才清零 —— 既正确又省一次请求。
	//   - 连接**失败**路径仍由 `cleanupPartial()` → `closeSignalStream()` 清零（双保险）。
	c.peersUnsupported.Store(false)

	// ⭐ 标记成功，禁用 defer 中的清理
	success = true
	return ip, nil
}

// ⭐ cleanupPartial 清理 Connect 中途失败时残留的资源
// 幂等：可以安全地重复调用
func (c *Hysteria2Client) cleanupPartial() {
	log.Printf("🧹 [客户端] 连接未完成，清理残留资源...")

	// ⭐ P2SP 阶段 1：关闭隧道内信令流
	c.closeSignalStream()

	// ⭐ P2SP 阶段 1b：停止打洞管理器（取消所有会话、释放 punch socket）
	c.stopPunchManager()

	// 数据面连接
	if c.dataConn != nil {
		_ = c.dataConn.CloseWithError(0, "")
		c.dataConn = nil
	}
	if c.matchConn != nil {
		_ = c.matchConn.CloseWithError(0, "")
		c.matchConn = nil
	}
	if c.gameTCPConn != nil {
		_ = c.gameTCPConn.CloseWithError(0, "")
		c.gameTCPConn = nil
	}
	if c.gameConn != nil {
		_ = c.gameConn.CloseWithError(0, "")
		c.gameConn = nil
	}
	if c.ctrlConn != nil {
		_ = c.ctrlConn.CloseWithError(0, "")
		c.ctrlConn = nil
	}

	// 共享 Transport / UDP socket
	if c.sharedTransport != nil {
		_ = c.sharedTransport.Close()
		c.sharedTransport = nil
	}
	if c.sharedUDPConn != nil {
		_ = c.sharedUDPConn.Close()
		c.sharedUDPConn = nil
	}

	// TUN
	if c.tunDevice != nil {
		_ = c.tunDevice.Close()
		c.tunDevice = nil
		log.Printf("🧹 [客户端] 已释放 TUN 设备")
	}

	// hysteria 控制面
	if c.hysteriaClient != nil {
		_ = c.hysteriaClient.Close()
		c.hysteriaClient = nil
	}

	// 取消所有 context（幂等，可重复调用）
	c.cancel()
	c.dataCancel()
	c.matchCancel()
	c.gameTCPCancel()
	c.gameCancel()
	c.ctrlCancel()

	c.mu.Lock()
	c.connected = false
	c.mu.Unlock()
}

// ⭐ 统一 QUIC 拨号：有 sharedTransport 就复用它（已混淆），否则回退 quic.DialAddr
func (c *Hysteria2Client) dialQUIC(
	ctx context.Context,
	serverIPv4 string,
	tlsConfig *tls.Config,
	quicConfig *quic.Config,
) (*quic.Conn, error) {
	if c.sharedTransport != nil {
		udpAddr := &net.UDPAddr{
			IP:   net.ParseIP(serverIPv4),
			Port: c.port,
		}
		return c.sharedTransport.Dial(ctx, udpAddr, tlsConfig, quicConfig)
	}
	addr := net.JoinHostPort(serverIPv4, fmt.Sprintf("%d", c.port))
	return quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
}

func (c *Hysteria2Client) connectDataConn(serverIPv4, vip string, preset latencyPreset) (
	*quic.Conn, *quic.Stream, *quic.Stream, *quic.Stream, error) {

	tlsConfig := c.buildTLSConfig([]string{alpnData})
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 120 * time.Second,
		KeepAlivePeriod:                preset.keepAlive,
		MaxIncomingStreams:             100,
		InitialStreamReceiveWindow:     uint64(preset.streamWindow),
		MaxStreamReceiveWindow:         uint64(preset.streamWindow),
		InitialConnectionReceiveWindow: uint64(preset.connWindow),
		MaxConnectionReceiveWindow:     uint64(preset.connWindow),
		InitialPacketSize:              1400,
		HandshakeIdleTimeout:           5 * time.Second,
	}

	log.Printf("⏳ [客户端] 连接数据面(bulk) %s:%d ...", serverIPv4, c.port)
	conn, err := c.dialQUIC(c.dataCtx, serverIPv4, tlsConfig, quicConfig)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("数据面 Dial 失败: %v", err)
	}
	log.Printf("✅ [客户端] 数据面(bulk) QUIC 已建立")

	ctrlStream, err := conn.OpenStreamSync(c.dataCtx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("打开数据面控制流失败: %v", err)
	}
	mode := "single"
	if c.username != "" {
		mode = "multi"
	}
	regStr := "data\n" + mode + "\n" + c.username + "\n" + vip
	if _, err := ctrlStream.Write([]byte(regStr)); err != nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("发送数据面注册帧失败: %v", err)
	}
	_ = ctrlStream.Close()

	tcpStream, err := conn.OpenStreamSync(c.dataCtx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("打开 TCP 流失败: %v", err)
	}
	if err := writeFrameToStream(tcpStream, []byte{}); err != nil {
		tcpStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("TCP 流握手失败: %v", err)
	}

	udpStream, err := conn.OpenStreamSync(c.dataCtx)
	if err != nil {
		tcpStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("打开 UDP 流失败: %v", err)
	}
	if err := writeFrameToStream(udpStream, []byte{}); err != nil {
		udpStream.Close()
		tcpStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("UDP 流握手失败: %v", err)
	}

	return conn, ctrlStream, tcpStream, udpStream, nil
}

func (c *Hysteria2Client) connectMatchConn(serverIPv4, vip string, preset latencyPreset) (
	*quic.Conn, *quic.Stream, error) {

	tlsConfig := c.buildTLSConfig([]string{alpnData})
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 120 * time.Second,
		KeepAlivePeriod:                preset.keepAlive,
		MaxIncomingStreams:             100,
		InitialStreamReceiveWindow:     uint64(preset.streamWindow),
		MaxStreamReceiveWindow:         uint64(preset.streamWindow),
		InitialConnectionReceiveWindow: uint64(preset.connWindow),
		MaxConnectionReceiveWindow:     uint64(preset.connWindow),
		InitialPacketSize:              1400,
		HandshakeIdleTimeout:           5 * time.Second,
	}

	log.Printf("⏳ [客户端] 连接匹配面 %s:%d ...", serverIPv4, c.port)
	conn, err := c.dialQUIC(c.matchCtx, serverIPv4, tlsConfig, quicConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("匹配面 Dial 失败: %v", err)
	}
	log.Printf("✅ [客户端] 匹配面 QUIC 已建立（CC=Cubic）")

	ctrlStream, err := conn.OpenStreamSync(c.matchCtx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, fmt.Errorf("打开注册流失败: %v", err)
	}
	mode := "single"
	if c.username != "" {
		mode = "multi"
	}
	regStr := "data-match\n" + mode + "\n" + c.username + "\n" + vip
	if _, err := ctrlStream.Write([]byte(regStr)); err != nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, fmt.Errorf("发送注册帧失败: %v", err)
	}
	_ = ctrlStream.Close()

	matchStream, err := conn.OpenStreamSync(c.matchCtx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, fmt.Errorf("打开匹配流失败: %v", err)
	}
	if err := writeFrameToStream(matchStream, []byte{}); err != nil {
		matchStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, fmt.Errorf("匹配流握手失败: %v", err)
	}

	return conn, matchStream, nil
}

func (c *Hysteria2Client) connectGameTCPConn(serverIPv4, vip string, preset latencyPreset) (
	*quic.Conn, *quic.Stream, error) {

	tlsConfig := c.buildTLSConfig([]string{alpnData})
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 120 * time.Second,
		KeepAlivePeriod:                preset.keepAlive,
		MaxIncomingStreams:             100,
		InitialStreamReceiveWindow:     uint64(preset.streamWindow),
		MaxStreamReceiveWindow:         uint64(preset.streamWindow),
		InitialConnectionReceiveWindow: uint64(preset.connWindow),
		MaxConnectionReceiveWindow:     uint64(preset.connWindow),
		InitialPacketSize:              1400,
		HandshakeIdleTimeout:           5 * time.Second,
	}

	log.Printf("⏳ [客户端] 连接游戏 TCP 面 %s:%d ...", serverIPv4, c.port)
	conn, err := c.dialQUIC(c.gameTCPCtx, serverIPv4, tlsConfig, quicConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("游戏 TCP Dial 失败: %v", err)
	}

	bbrSender := bbr.NewBbrSender(
		bbr.DefaultClock{},
		conn.InitialPacketSize(),
		bbr.ProfileStandard,
	)
	conn.SetCongestionControl(bbrSender)

	log.Printf("✅ [客户端] 游戏 TCP 面 QUIC 已建立（CC=BBR / profile=standard）")

	ctrlStream, err := conn.OpenStreamSync(c.gameTCPCtx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, fmt.Errorf("打开注册流失败: %v", err)
	}
	mode := "single"
	if c.username != "" {
		mode = "multi"
	}
	regStr := "data-game-tcp\n" + mode + "\n" + c.username + "\n" + vip
	if _, err := ctrlStream.Write([]byte(regStr)); err != nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, fmt.Errorf("发送注册帧失败: %v", err)
	}
	_ = ctrlStream.Close()

	gameStream, err := conn.OpenStreamSync(c.gameTCPCtx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, fmt.Errorf("打开 Game TCP 流失败: %v", err)
	}
	if err := writeFrameToStream(gameStream, []byte{}); err != nil {
		gameStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, fmt.Errorf("Game TCP 流握手失败: %v", err)
	}

	return conn, gameStream, nil
}

// ⭐ 游戏 UDP datagram 连接（握手改用 stream 协商，抗丢包）
func (c *Hysteria2Client) connectGameDatagramConn(serverIPv4, vip string, preset latencyPreset) (
	*quic.Conn, error) {

	tlsConfig := c.buildTLSConfig([]string{alpnData})
	quicConfig := &quic.Config{
		MaxIdleTimeout:                 120 * time.Second,
		KeepAlivePeriod:                preset.keepAlive,
		MaxIncomingStreams:             100,
		InitialStreamReceiveWindow:     uint64(preset.streamWindow),
		MaxStreamReceiveWindow:         uint64(preset.streamWindow),
		InitialConnectionReceiveWindow: uint64(preset.connWindow),
		MaxConnectionReceiveWindow:     uint64(preset.connWindow),
		InitialPacketSize:              1400,
		HandshakeIdleTimeout:           5 * time.Second,
		EnableDatagrams:                true,
	}

	log.Printf("⏳ [客户端] 连接游戏 UDP datagram 面 %s:%d ...", serverIPv4, c.port)
	conn, err := c.dialQUIC(c.gameCtx, serverIPv4, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("游戏 UDP Dial 失败: %v", err)
	}
	log.Printf("✅ [客户端] 游戏 UDP datagram 面 QUIC 已建立")

	qdc := qcong.NewQUICDCController()
	qdc.SetMaxDatagramSize(conn.InitialPacketSize())
	conn.SetCongestionControl(qdc)
	c.gameCC = qdc
	log.Printf("🎯 [QUIC-DC] 已注入 gameConn（初始 cwnd=%d）", qdc.GetCongestionWindow())

	// 注册流
	ctrlStream, err := conn.OpenStreamSync(c.gameCtx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, fmt.Errorf("打开注册流失败: %v", err)
	}
	mode := "single"
	if c.username != "" {
		mode = "multi"
	}
	regStr := "data-game\n" + mode + "\n" + c.username + "\n" + vip
	if _, err := ctrlStream.Write([]byte(regStr)); err != nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "")
		return nil, fmt.Errorf("发送注册帧失败: %v", err)
	}
	_ = ctrlStream.Close()

	// ⭐ 用 stream 做 datagram 协商（stream 有 ACK + 重传，丢包不会导致握手失败）
	var datagramReady bool
	dgStream, err := conn.OpenStreamSync(c.gameCtx)
	if err != nil {
		log.Printf("⚠️ [客户端] 打开 datagram 协商流失败: %v", err)
	} else {
		if _, werr := dgStream.Write([]byte("datagram-negotiate\n")); werr != nil {
			log.Printf("⚠️ [客户端] 发送协商请求失败: %v", werr)
		} else {
			_ = dgStream.SetReadDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, 64)
			// ⭐ 服务端 Write 后立即 Close，FIN 会紧跟 DATA 到达，
			//    所以 Read 可能返回 (n, io.EOF)，此时数据仍然是有效的。
			//    只要 n > 0 且内容正确就算握手成功，不要用 rerr == nil 判断。
			n, _ := dgStream.Read(buf)
			if n > 0 && strings.TrimSpace(string(buf[:n])) == "datagram-ok" {
				datagramReady = true
				log.Printf("✅ [客户端] Datagram 握手成功（stream 协商）")
			} else {
				log.Printf("⚠️ [客户端] Datagram 协商失败: 未收到有效响应（n=%d）", n)
			}
		}
		_ = dgStream.Close()
	}

	c.gameDatagramReady.Store(datagramReady)
	log.Printf("✅ [客户端] 游戏 UDP datagram 面: (Datagram=%v)", datagramReady)

	return conn, nil
}

func (c *Hysteria2Client) connectCtrlConn(serverIPv4, vip string, preset latencyPreset) (
	*quic.Conn, *quic.Stream, *quic.Stream, *quic.Stream, error) {

	tlsConfig := c.buildTLSConfig([]string{alpnCtrl})
	ctrlStreamWindow := 262144

	quicConfig := &quic.Config{
		MaxIdleTimeout:             120 * time.Second,
		KeepAlivePeriod:            preset.keepAlive,
		MaxIncomingStreams:         10,
		InitialStreamReceiveWindow: uint64(ctrlStreamWindow),
		MaxStreamReceiveWindow:     uint64(ctrlStreamWindow),
		InitialPacketSize:          1400,
		HandshakeIdleTimeout:       5 * time.Second,
	}

	log.Printf("⏳ [客户端] 连接控制面 %s:%d ...", serverIPv4, c.port)
	conn, err := c.dialQUIC(c.ctrlCtx, serverIPv4, tlsConfig, quicConfig)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("控制面 Dial 失败: %v", err)
	}
	log.Printf("✅ [客户端] 控制面 QUIC 已建立")

	ctrlStream, err := conn.OpenStreamSync(c.ctrlCtx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("打开控制面控制流失败: %v", err)
	}
	mode := "single"
	if c.username != "" {
		mode = "multi"
	}
	regStr := "ctrl\n" + mode + "\n" + c.username + "\n" + vip
	if _, err := ctrlStream.Write([]byte(regStr)); err != nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("发送控制面注册帧失败: %v", err)
	}
	_ = ctrlStream.Close()

	icmpStream, err := conn.OpenStreamSync(c.ctrlCtx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("打开 ICMP 流失败: %v", err)
	}
	if err := writeFrameToStream(icmpStream, []byte{}); err != nil {
		icmpStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("ICMP 流握手失败: %v", err)
	}

	hbStream, err := conn.OpenStreamSync(c.ctrlCtx)
	if err != nil {
		icmpStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("打开心跳流失败: %v", err)
	}
	placeholder := make([]byte, 5)
	binary.BigEndian.PutUint32(placeholder[:4], 1)
	placeholder[4] = hbTypePing
	if _, err := hbStream.Write(placeholder); err != nil {
		hbStream.Close()
		icmpStream.Close()
		conn.CloseWithError(0, "")
		return nil, nil, nil, nil, fmt.Errorf("心跳流握手失败: %v", err)
	}

	return conn, ctrlStream, icmpStream, hbStream, nil
}

func (c *Hysteria2Client) deliverToTun(pkt []byte) {
	if c.tunDevice == nil {
		return
	}
	if len(pkt) >= 20 && (pkt[0]>>4)&0xF == 4 && pkt[9] == ipProtoTCP {
		dumpTCPPacket(pkt, "DOWN")
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case c.tunWriteChan <- cp:
	default:
		if isDebugMode() {
			log.Printf("⚠️ TUN 写队列已满，丢弃包 (len=%d)", len(pkt))
		}
	}
}

func (c *Hysteria2Client) TunWriteLoop() {
	if c.tunDevice == nil {
		return
	}
	log.Printf("🔄 [客户端] TUN 写循环已启动")
	for {
		select {
		case <-c.dataCtx.Done():
			return
		case pkt := <-c.tunWriteChan:
			if err := c.tunDevice.Write(pkt); err != nil {
				log.Printf("❌ [客户端] 写入 TUN 失败: %v", err)
			}
		}
	}
}

func (c *Hysteria2Client) forwardData() {
	if c.tunDevice == nil {
		return
	}

	log.Println("🚀 [客户端] TUN 读循环启动")

	for {
		select {
		case <-c.dataCtx.Done():
			return
		default:
		}

		data, err := c.tunDevice.Read()
		if err != nil {
			log.Printf("❌ [客户端] 读取 TUN 失败: %v", err)
			return
		}
		if len(data) < 20 {
			continue
		}
		if (data[0]>>4)&0xF != 4 {
			continue
		}

		proto := data[9]

		// ⭐ 1b-2A 热路径钩子：把目的地址交给路径管理器（只做原子读 + map 查 + 非阻塞入队）。
		//    「有流量要发给某个对端 VIP」就是打洞的触发条件（流量驱动，设计 §1.1）。
		c.observeDst(data)

		cp := make([]byte, len(data))
		copy(cp, data)

		switch proto {
		case ipProtoICMP:
			select {
			case c.icmpSendChan <- cp:
			default:
			}
		case ipProtoTCP:
			dumpTCPPacket(data, "UP")
			isGame := false
			if c.serverSplitEnabled && c.gameTCPStream != nil {
				if dstPort, ok := extractTCPDstPort(data); ok && c.serverSplitPorts[dstPort] {
					isGame = true
				}
			}
			if isGame {
				select {
				case c.gameTCPSendChan <- cp:
				default:
				}
			} else {
				select {
				case c.tcpSendChan <- cp:
				default:
				}
			}
		case ipProtoUDP:
			if c.gameDatagramReady.Load() {
				if dstPort, ok := parseUDPDstPort(data); ok && c.isUDPUnreliablePort(dstPort) {
					select {
					case c.gameUDPSendChan <- cp:
					default:
					}
					continue
				}
			}
			if c.matchStream != nil {
				if dstPort, ok := parseUDPDstPort(data); ok && c.isUDPMatchPort(dstPort) {
					select {
					case c.matchSendChan <- cp:
					default:
					}
					continue
				}
			}
			select {
			case c.udpSendChan <- cp:
			default:
			}
		default:
			select {
			case c.tcpSendChan <- cp:
			default:
			}
		}
	}
}

func (c *Hysteria2Client) TCPWriteLoop() {
	log.Println("🚀 [客户端] TCP(bulk) 写协程启动")
	for {
		select {
		case <-c.dataCtx.Done():
			return
		case pkt := <-c.tcpSendChan:
			if err := c.sendTCPFrame(pkt); err != nil {
				if kicked, reason := isKickedError(err); kicked {
					c.markKicked(reason)
					return
				}
				log.Printf("❌ [客户端] TCP(bulk) 发送失败: %v", err)
			}
		}
	}
}

func (c *Hysteria2Client) MatchWriteLoop() {
	log.Println("🚀 [客户端] Match 写协程启动")
	for {
		select {
		case <-c.matchCtx.Done():
			return
		case pkt := <-c.matchSendChan:
			if err := c.sendMatchFrame(pkt); err != nil {
				if kicked, reason := isKickedError(err); kicked {
					c.markKicked(reason)
					return
				}
				log.Printf("❌ [客户端] Match 发送失败: %v", err)
			}
		}
	}
}

func (c *Hysteria2Client) GameTCPWriteLoop() {
	log.Println("🚀 [客户端] Game TCP 写协程启动")
	for {
		select {
		case <-c.gameTCPCtx.Done():
			return
		case pkt := <-c.gameTCPSendChan:
			if err := c.sendGameTCPFrame(pkt); err != nil {
				if kicked, reason := isKickedError(err); kicked {
					c.markKicked(reason)
					return
				}
				log.Printf("❌ [客户端] Game TCP 发送失败: %v", err)
			}
		}
	}
}

func (c *Hysteria2Client) GameDatagramWriteLoop() {
	log.Println("🚀 [客户端] Game Datagram 写协程启动")
	for {
		select {
		case <-c.gameCtx.Done():
			return
		case pkt := <-c.gameUDPSendChan:
			// ⭐ 1b-2A：不可靠 UDP 平面命中直连时走直连 datagram
			//   （语义必须与中继一致：丢了就丢了、不重排、超限丢弃）
			if dp := c.directDatagramPath(pkt); dp != nil {
				dp.writeDatagram(pkt)
				continue
			}
			if c.gameConn == nil {
				continue
			}
			if len(pkt) > maxGameDatagramSize {
				if isDebugMode() {
					log.Printf("⚠️ [客户端] Datagram 包过大 %d，丢弃", len(pkt))
				}
				continue
			}
			if isDebugMode() {
				if port, ok := parseUDPDstPort(pkt); ok {
					log.Printf("📤 [GameDatagram-UP] dstPort=%d len=%d", port, len(pkt))
				}
			}
			if err := c.gameConn.SendDatagram(pkt); err != nil {
				if isDebugMode() {
					log.Printf("⚠️ [客户端] Datagram 发送失败: %v", err)
				}
			}
		}
	}
}

func (c *Hysteria2Client) UDPWriteLoop() {
	log.Println("🚀 [客户端] UDP 写协程启动")
	for {
		select {
		case <-c.dataCtx.Done():
			return
		case pkt := <-c.udpSendChan:
			if isDebugMode() {
				if port, ok := parseUDPDstPort(pkt); ok {
					log.Printf("📤 [DataUDP-UP] dstPort=%d len=%d", port, len(pkt))
				}
			}
			if err := c.sendUDPFrame(pkt); err != nil {
				if kicked, reason := isKickedError(err); kicked {
					c.markKicked(reason)
					return
				}
				log.Printf("❌ [客户端] UDP 发送失败: %v", err)
			}
		}
	}
}

func (c *Hysteria2Client) ICMPWriteLoop() {
	log.Println("🚀 [客户端] ICMP 写协程启动")
	for {
		select {
		case <-c.ctrlCtx.Done():
			return
		case pkt := <-c.icmpSendChan:
			if err := c.sendICMPFrame(pkt); err != nil {
				if kicked, reason := isKickedError(err); kicked {
					c.markKicked(reason)
					return
				}
				log.Printf("❌ [客户端] ICMP 发送失败: %v", err)
			}
		}
	}
}

// ⭐ 1b-2A：5 个流平面的发送函数都先问一次「这个目的地址有直连吗」（§2.2）：
//   - 有 → 投进**该平面对应流**的有界队列（非阻塞，满了丢这条流的包）；
//   - 无 → 走中继（与 1b-1 逐字一致）。
//
// 直连的真实写发生在路径自己的写协程里，所以这里的阻塞风险为零（R1b 的隔离点）；
// 平面→流的分组见 path.go 的 planeStream（关键小包与批量流量分属两条流即 Q1）。
func (c *Hysteria2Client) sendTCPFrame(data []byte) error {
	if ch := c.directSink(data, planeTCP); ch != nil {
		enqueueDirect(ch, planeTCP, data)
		return nil
	}
	c.tcpWriteMu.Lock()
	defer c.tcpWriteMu.Unlock()
	return writeFrameToStream(c.tcpStream, data)
}

func (c *Hysteria2Client) sendMatchFrame(data []byte) error {
	if ch := c.directSink(data, planeMatch); ch != nil {
		enqueueDirect(ch, planeMatch, data)
		return nil
	}
	if c.matchStream == nil {
		return fmt.Errorf("matchStream 未建立")
	}
	c.matchWriteMu.Lock()
	defer c.matchWriteMu.Unlock()
	return writeFrameToStream(c.matchStream, data)
}

func (c *Hysteria2Client) sendGameTCPFrame(data []byte) error {
	if ch := c.directSink(data, planeGameTCP); ch != nil {
		enqueueDirect(ch, planeGameTCP, data)
		return nil
	}
	if c.gameTCPStream == nil {
		return fmt.Errorf("gameTCPStream 未建立")
	}
	c.gameTCPWriteMu.Lock()
	defer c.gameTCPWriteMu.Unlock()
	return writeFrameToStream(c.gameTCPStream, data)
}

func (c *Hysteria2Client) sendUDPFrame(data []byte) error {
	if ch := c.directSink(data, planeUDP); ch != nil {
		enqueueDirect(ch, planeUDP, data)
		return nil
	}
	c.udpWriteMu.Lock()
	defer c.udpWriteMu.Unlock()
	return writeFrameToStream(c.udpStream, data)
}

func (c *Hysteria2Client) sendICMPFrame(data []byte) error {
	if ch := c.directSink(data, planeICMP); ch != nil {
		enqueueDirect(ch, planeICMP, data)
		return nil
	}
	c.icmpWriteMu.Lock()
	defer c.icmpWriteMu.Unlock()
	return writeFrameToStream(c.icmpStream, data)
}

func (c *Hysteria2Client) tcpReceiveLoop(stream *quic.Stream) {
	buf := make([]byte, maxFrameSize)
	for {
		select {
		case <-c.dataCtx.Done():
			return
		default:
		}
		pkt, err := readFrame(stream, buf)
		if err != nil {
			if kicked, reason := isKickedError(err); kicked {
				c.markKicked(reason)
				return
			}
			return
		}
		if len(pkt) == 0 {
			continue
		}
		c.health.OnAnyDataReceived()
		c.deliverToTun(pkt)
	}
}

func (c *Hysteria2Client) matchReceiveLoop(stream *quic.Stream) {
	buf := make([]byte, maxFrameSize)
	for {
		select {
		case <-c.matchCtx.Done():
			return
		default:
		}
		pkt, err := readFrame(stream, buf)
		if err != nil {
			if kicked, reason := isKickedError(err); kicked {
				c.markKicked(reason)
				return
			}
			return
		}
		if len(pkt) == 0 {
			continue
		}
		c.health.OnAnyDataReceived()
		c.deliverToTun(pkt)
	}
}

func (c *Hysteria2Client) gameTCPReceiveLoop(stream *quic.Stream) {
	buf := make([]byte, maxFrameSize)
	for {
		select {
		case <-c.gameTCPCtx.Done():
			return
		default:
		}
		pkt, err := readFrame(stream, buf)
		if err != nil {
			if kicked, reason := isKickedError(err); kicked {
				c.markKicked(reason)
				return
			}
			return
		}
		if len(pkt) == 0 {
			continue
		}
		c.health.OnAnyDataReceived()
		c.deliverToTun(pkt)
	}
}

func (c *Hysteria2Client) gameDatagramReceiveLoop() {
	for {
		select {
		case <-c.gameCtx.Done():
			return
		default:
		}
		pkt, err := c.gameConn.ReceiveDatagram(c.gameCtx)
		if err != nil {
			if c.gameCtx.Err() != nil {
				return
			}
			return
		}
		if len(pkt) == 0 {
			continue
		}
		if isDebugMode() {
			if port, ok := parseUDPSrcPort(pkt); ok {
				log.Printf("📥 [GameDatagram-DOWN] srcPort=%d len=%d", port, len(pkt))
			}
		}
		c.health.OnAnyDataReceived()
		c.deliverToTun(pkt)
	}
}

func (c *Hysteria2Client) udpReceiveLoop(stream *quic.Stream) {
	buf := make([]byte, maxFrameSize)
	for {
		select {
		case <-c.dataCtx.Done():
			return
		default:
		}
		pkt, err := readFrame(stream, buf)
		if err != nil {
			if kicked, reason := isKickedError(err); kicked {
				c.markKicked(reason)
				return
			}
			return
		}
		if len(pkt) == 0 {
			continue
		}
		c.health.OnAnyDataReceived()
		c.deliverToTun(pkt)
	}
}

func (c *Hysteria2Client) icmpReceiveLoop(stream *quic.Stream) {
	buf := make([]byte, maxFrameSize)
	for {
		select {
		case <-c.ctrlCtx.Done():
			return
		default:
		}
		pkt, err := readFrame(stream, buf)
		if err != nil {
			if kicked, reason := isKickedError(err); kicked {
				c.markKicked(reason)
				return
			}
			return
		}
		if len(pkt) == 0 {
			continue
		}
		c.health.OnAnyDataReceived()
		c.deliverToTun(pkt)
	}
}

func (c *Hysteria2Client) heartbeatLoop(stream *quic.Stream, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctrlCtx.Done():
			return
		case <-ticker.C:
			// ⭐ 把最近一次 RTT 编码到 ping payload 上报给服务端
			lat := c.GetLatency()
			if lat < 0 {
				lat = 0
			}
			payload := make([]byte, 4)
			binary.BigEndian.PutUint32(payload, uint32(lat))

			if err := c.sendHeartbeatFrame(hbTypePing, payload); err != nil {
				if kicked, reason := isKickedError(err); kicked {
					c.markKicked(reason)
					return
				}
				c.health.OnHeartbeatFailure()
			}
		}
	}
}

func (c *Hysteria2Client) sendHeartbeatFrame(frameType byte, payload []byte) error {
	c.hbWriteMu.Lock()
	defer c.hbWriteMu.Unlock()

	// ⭐ 记录 ping 发送时刻（用于 RTT 测量）
	if frameType == hbTypePing {
		c.pingMu.Lock()
		c.lastPingSentAt = time.Now()
		c.pingMu.Unlock()
	}

	data := make([]byte, 1+len(payload))
	data[0] = frameType
	copy(data[1:], payload)

	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)

	_, err := c.hbStream.Write(buf)
	return err
}

func (c *Hysteria2Client) heartbeatReceiveLoop(stream *quic.Stream) {
	buf := make([]byte, maxFrameSize)
	for {
		select {
		case <-c.ctrlCtx.Done():
			return
		default:
		}
		pkt, err := readFrame(stream, buf)
		if err != nil {
			if kicked, reason := isKickedError(err); kicked {
				c.markKicked(reason)
				return
			}
			return
		}
		if len(pkt) < 1 {
			continue
		}
		if pkt[0] == hbTypePong {
			// ⭐ 计算 RTT
			c.pingMu.Lock()
			if !c.lastPingSentAt.IsZero() {
				rtt := time.Since(c.lastPingSentAt)
				// 过滤异常值
				if rtt > 0 && rtt < 30*time.Second {
					c.lastRTT = rtt
					c.lastRTTAt = time.Now()
				}
			}
			c.pingMu.Unlock()

			c.health.OnPongReceived()
		}
	}
}

func (c *Hysteria2Client) gameConnStatsLoop() {
	if c.gameCC == nil {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.gameCtx.Done():
			return
		case <-ticker.C:
			if !isQUICDCDebug() {
				continue
			}
			acks, resets, cwnd, ssthresh, owqd, minRTT := c.gameCC.Stats()
			log.Printf("📊 [QUIC-DC] acks=%d resets=%d cwnd=%d ssthresh=%d owqd=%v minRTT=%v",
				acks, resets, cwnd, ssthresh, owqd, minRTT)
		}
	}
}

// ⭐ 1b-2A：这两个分帧函数改成作用于**窄接口**直接流（`directStream`），
// 于是中继的 *quic.Stream 与直连的流共用同一套分帧，不重复实现（见 path.go）。
func writeFrameToStream(stream directStream, data []byte) error {
	if len(data) > maxFrameSize {
		return fmt.Errorf("帧过大: %d", len(data))
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err := stream.Write(buf)
	return err
}

func readFrame(stream directStream, buf []byte) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 {
		return buf[:0], nil
	}
	if length > maxFrameSize {
		return nil, fmt.Errorf("无效帧长度: %d", length)
	}
	if int(length) > len(buf) {
		return nil, fmt.Errorf("缓冲区不足: 需要 %d, 实际 %d", length, len(buf))
	}
	if _, err := io.ReadFull(stream, buf[:length]); err != nil {
		return nil, err
	}
	return buf[:length], nil
}

func (c *Hysteria2Client) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()

		log.Println("🛑 [客户端] 正在关闭连接...")

		c.cancel()
		c.dataCancel()
		c.matchCancel()
		c.gameTCPCancel()
		c.gameCancel()
		c.ctrlCancel()

		// ⭐ P2SP 阶段 1：关闭隧道内信令流
		c.closeSignalStream()

		// ⭐ P2SP 阶段 1b：停止打洞管理器（必须在关连接之前，让它先释放 punch socket）
		c.stopPunchManager()

		if c.dataConn != nil {
			c.dataConn.CloseWithError(0, "")
		}
		if c.matchConn != nil {
			c.matchConn.CloseWithError(0, "")
		}
		if c.gameTCPConn != nil {
			c.gameTCPConn.CloseWithError(0, "")
		}
		if c.gameConn != nil {
			c.gameConn.CloseWithError(0, "")
		}
		if c.ctrlConn != nil {
			c.ctrlConn.CloseWithError(0, "")
		}
		// ⭐ 关闭数据面共享 Transport / UDPConn
		if c.sharedTransport != nil {
			_ = c.sharedTransport.Close()
		}
		if c.sharedUDPConn != nil {
			_ = c.sharedUDPConn.Close()
		}
		if c.tunDevice != nil {
			c.tunDevice.Close()
		}
		if c.hysteriaClient != nil {
			err = c.hysteriaClient.Close()
		}

		log.Println("✅ [客户端] 连接已关闭")
	})
	return err
}

func (c *Hysteria2Client) GetStats() (rttMs int, lossRate float64) {
	return 0, 0
}

// ⭐ GetLatency 返回最近一次心跳 RTT 的毫秒数；无数据或过期返回 -1
func (c *Hysteria2Client) GetLatency() int {
	c.pingMu.Lock()
	defer c.pingMu.Unlock()
	if c.lastRTTAt.IsZero() {
		return -1
	}
	if time.Since(c.lastRTTAt) > 30*time.Second {
		return -1
	}
	ms := int(c.lastRTT.Milliseconds())
	if ms < 1 {
		ms = 1 // RTT 已测量但不足 1ms，向上取整，避免显示 0
	}
	return ms
}

func (c *Hysteria2Client) GetHealthState() string {
	if c.health == nil {
		return StateOffline
	}
	return c.health.State()
}

func (c *Hysteria2Client) GetHealthSnapshot() map[string]interface{} {
	kicked, reason := c.IsKicked()
	latency := c.GetLatency()

	if c.health == nil {
		return map[string]interface{}{
			"state":           StateOffline,
			"lastRecvAgo":     0.0,
			"lastPongAgo":     0.0,
			"consecutiveFail": 0,
			"kicked":          kicked,
			"kickedReason":    reason,
			"latency":         latency,
		}
	}
	snapshot := c.health.Snapshot()
	snapshot["kicked"] = kicked
	snapshot["kickedReason"] = reason
	snapshot["latency"] = latency
	return snapshot
}
