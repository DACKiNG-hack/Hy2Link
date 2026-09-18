package quic

// backend/quic/client.go

import (
	"bytes"
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
const tunMTU = 1380

// ⭐ ALPN 改名（hysteria 认证的 "h3" 由 hysteria core 内部处理）
const (
	alpnData = "h3-data"
	alpnCtrl = "h3-ctrl"
)

const ClientVersion = "1.0.0"
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

func isQUICDCDebug() bool {
	return strings.ToLower(os.Getenv("HY_QUICDCDEBUG")) == "true" ||
		strings.ToLower(os.Getenv("HY_QUICDC_DEBUG")) == "true"
}

// ========== 指纹存储 ==========

func fingerprintPath(serverIP string) string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	dir = filepath.Join(dir, "hy2link")
	_ = os.MkdirAll(dir, 0700)
	safe := strings.ReplaceAll(serverIP, ":", "_")
	safe = strings.ReplaceAll(safe, "/", "_")
	return filepath.Join(dir, "fp_"+safe+".txt")
}

func loadPinnedFingerprint(serverIP string) string {
	data, err := os.ReadFile(fingerprintPath(serverIP))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func savePinnedFingerprint(serverIP, fp string) error {
	return os.WriteFile(fingerprintPath(serverIP), []byte(fp), 0600)
}

func clearPinnedFingerprint(serverIP string) error {
	err := os.Remove(fingerprintPath(serverIP))
	if os.IsNotExist(err) {
		return nil
	}
	return err
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
			return fmt.Errorf("解析证书失败: %w", err)
		}
		now := time.Now()
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return fmt.Errorf("证书已过期（%v ~ %v）", cert.NotBefore, cert.NotAfter)
		}

		fp := sha256.Sum256(rawCerts[0])
		got := hex.EncodeToString(fp[:])

		known := loadPinnedFingerprint(c.serverIP)
		if known == "" {
			if err := savePinnedFingerprint(c.serverIP, got); err != nil {
				log.Printf("⚠️ [客户端] 保存指纹失败: %v", err)
			}
			log.Printf("📌 [客户端] 首次连接，已记录服务端指纹: %s", got[:16])
			return nil
		}
		if known != got {
			return fmt.Errorf("⚠️ 服务端证书指纹不匹配\n"+
				"  已知: %s\n"+
				"  收到: %s\n"+
				"可能被中间人攻击，或服务端重新生成过证书。\n"+
				"如确认安全，请在客户端清除已保存的指纹后重试。",
				known[:16], got[:16])
		}
		return nil
	}
}

func (c *Hysteria2Client) verifyPinOrCA() func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if c.skipCertVerify {
			return nil
		}
		if len(rawCerts) == 0 {
			return fmt.Errorf("服务端未提供证书")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return nil
		}
		if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			return nil
		}
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

// ========== Connect ==========

func (c *Hysteria2Client) Connect() (string, error) {
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

	authStr := c.password
	if c.username != "" {
		authStr = c.username + ":" + c.password
	}
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
		if net.ParseIP(ip) == nil || net.ParseIP(mask) == nil {
			return "", fmt.Errorf("收到无效 IP 或掩码")
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
		if net.ParseIP(ip) == nil || net.ParseIP(mask) == nil {
			return "", fmt.Errorf("静态 IP 或掩码无效")
		}
		c.serverSplitEnabled = false
		c.serverSplitPorts = make(map[uint16]bool)
		c.udpMatchRanges = nil
		c.udpUnreliableRanges = nil
		c.serverCertMode = "selfsigned"
		c.serverHostname = serverIPv4
	}

	c.assignedIP = ip
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

	return ip, nil
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

func (c *Hysteria2Client) sendTCPFrame(data []byte) error {
	c.tcpWriteMu.Lock()
	defer c.tcpWriteMu.Unlock()
	return writeFrameToStream(c.tcpStream, data)
}

func (c *Hysteria2Client) sendMatchFrame(data []byte) error {
	if c.matchStream == nil {
		return fmt.Errorf("matchStream 未建立")
	}
	c.matchWriteMu.Lock()
	defer c.matchWriteMu.Unlock()
	return writeFrameToStream(c.matchStream, data)
}

func (c *Hysteria2Client) sendGameTCPFrame(data []byte) error {
	if c.gameTCPStream == nil {
		return fmt.Errorf("gameTCPStream 未建立")
	}
	c.gameTCPWriteMu.Lock()
	defer c.gameTCPWriteMu.Unlock()
	return writeFrameToStream(c.gameTCPStream, data)
}

func (c *Hysteria2Client) sendUDPFrame(data []byte) error {
	c.udpWriteMu.Lock()
	defer c.udpWriteMu.Unlock()
	return writeFrameToStream(c.udpStream, data)
}

func (c *Hysteria2Client) sendICMPFrame(data []byte) error {
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

func writeFrameToStream(stream *quic.Stream, data []byte) error {
	if len(data) > maxFrameSize {
		return fmt.Errorf("帧过大: %d", len(data))
	}
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err := stream.Write(buf)
	return err
}

func readFrame(stream *quic.Stream, buf []byte) ([]byte, error) {
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
