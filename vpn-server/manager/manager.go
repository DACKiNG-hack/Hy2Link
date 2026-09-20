package manager

//vpn-server\manager\manager.go

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpn-server/admin"
	"vpn-server/cert"
	"vpn-server/config"
	"vpn-server/quic"
	"vpn-server/store"
	"vpn-server/tun"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/obfs"
	quicgo "github.com/apernet/quic-go"
)

type modePreset struct {
	connWindow   int
	streamWindow int
	keepAlive    time.Duration
	maxStreams   int
	udpBufSize   int
}

var latencyPresets = map[string]modePreset{
	"low": {
		connWindow:   8388608,
		streamWindow: 4194304,
		keepAlive:    20 * time.Second,
		maxStreams:   50,
		udpBufSize:   4194304,
	},
	"balanced": {
		connWindow:   12582912,
		streamWindow: 6291456,
		keepAlive:    20 * time.Second,
		maxStreams:   80,
		udpBufSize:   4194304,
	},
	"throughput": {
		connWindow:   20971520,
		streamWindow: 8388608,
		keepAlive:    10 * time.Second,
		maxStreams:   100,
		udpBufSize:   4194304,
	},
}

const hardcodedBBRProfile = "ultra"

// ⭐ 新 ALPN 名字
const (
	alpnHysteria = "h3"
	alpnData     = "h3-data"
	alpnCtrl     = "h3-ctrl"
)

type Manager struct {
	mu        sync.RWMutex
	running   bool
	startedAt time.Time
	lastError string

	cfg     *config.ServerConfig
	cfgPath string

	userStore  *store.Store
	adminState *admin.AdminState

	certMgr *cert.Manager

	udpConn   *net.UDPConn
	obfsConn  net.PacketConn // ⭐ 混淆包装后的 PacketConn（底层是 udpConn）
	transport *quicgo.Transport
	listener  *quicgo.Listener

	hysteriaSrv server.Server
	dataServer  *quic.DataChannelServer
	ipAllocator *quic.IPAllocator

	serverTun *tun.TUNDevice
}

func New(cfg *config.ServerConfig, cfgPath string, userStore *store.Store, adminState *admin.AdminState, certMgr *cert.Manager) *Manager {
	return &Manager{
		cfg:        cfg,
		cfgPath:    cfgPath,
		userStore:  userStore,
		adminState: adminState,
		certMgr:    certMgr,
	}
}

func (m *Manager) CertManager() *cert.Manager {
	return m.certMgr
}

func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

func (m *Manager) Status() config.ServerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status := config.ServerStatus{
		Running:   m.running,
		StartedAt: m.startedAt,
		LastError: m.lastError,
		Port:      m.cfg.Port,
		Config:    m.cfg.Clone(),
	}
	if m.running {
		status.Uptime = time.Since(m.startedAt).Seconds()
	}
	return status
}

func (m *Manager) GetConfig() *config.ServerConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.Clone()
}

func (m *Manager) UpdateConfig(newCfg *config.ServerConfig) error {
	if err := newCfg.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return fmt.Errorf("服务端运行中，请先停止再修改配置")
	}
	if err := newCfg.Save(m.cfgPath); err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}
	m.cfg = newCfg
	log.Printf("⚙️ 配置已更新: %s", newCfg.String())
	return nil
}

func expandUDPSplitPorts(ranges []string) []int {
	out := make([]int, 0, 2048)
	seen := make(map[int]bool)
	for _, s := range ranges {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		var lo, hi int
		if i := strings.Index(s, "-"); i >= 0 {
			l, err1 := strconv.Atoi(strings.TrimSpace(s[:i]))
			h, err2 := strconv.Atoi(strings.TrimSpace(s[i+1:]))
			if err1 != nil || err2 != nil || l < 1 || h > 65535 || l > h {
				log.Printf("⚠️ [配置] 端口无效: %s，跳过", s)
				continue
			}
			lo, hi = l, h
		} else {
			p, err := strconv.Atoi(s)
			if err != nil || p < 1 || p > 65535 {
				log.Printf("⚠️ [配置] 端口无效: %s，跳过", s)
				continue
			}
			lo, hi = p, p
		}
		for p := lo; p <= hi; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

func (m *Manager) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("服务端已在运行")
	}
	cfg := m.cfg.Clone()
	m.mu.Unlock()

	lowPerf, _, _, latencyMode := m.userStore.GetPerformanceConfig()

	preset, ok := latencyPresets[latencyMode]
	if !ok {
		preset = latencyPresets["low"]
		latencyMode = "low"
	}

	udpBufSize := preset.udpBufSize
	maxIncomingStreams := preset.maxStreams
	keepAlivePeriod := preset.keepAlive
	streamWindow := preset.streamWindow
	connWindow := preset.connWindow

	if lowPerf {
		udpBufSize = 1048576
		maxIncomingStreams = 30
		keepAlivePeriod = 30 * time.Second
		streamWindow = 2097152
		connWindow = 4194304
		debug.SetGCPercent(200)
		log.Printf("🐢 [低性能模式] 已叠加生效")
	} else {
		debug.SetGCPercent(100)
	}

	bbrProfile := hardcodedBBRProfile

	log.Printf("🚀 [延迟模式=%s] connWindow=%d streamWindow=%d bbr=%s keepAlive=%v maxStreams=%d udpBuf=%d",
		latencyMode, connWindow, streamWindow, bbrProfile, keepAlivePeriod, maxIncomingStreams, udpBufSize)
	log.Printf("🚀 启动服务端: %s", cfg.String())

	if err := cfg.Validate(); err != nil {
		m.setError(err)
		return err
	}

	// ⭐ 加载证书
	if _, err := m.certMgr.Load(); err != nil {
		m.setError(err)
		return fmt.Errorf("加载证书失败: %v", err)
	}
	log.Printf("🔐 [证书] 模式=%s hostname=%s", m.certMgr.Mode(), m.certMgr.ServerHostname())

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", cfg.Port))
	if err != nil {
		m.setError(err)
		return fmt.Errorf("解析地址失败: %v", err)
	}
	udpConn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		m.setError(err)
		return fmt.Errorf("监听 UDP %d 失败: %v", cfg.Port, err)
	}
	_ = udpConn.SetReadBuffer(udpBufSize)
	_ = udpConn.SetWriteBuffer(udpBufSize)

	// ⭐ Salamander 混淆：整条 UDP socket 统一包装
	var obfsConn net.PacketConn = udpConn
	if cfg.ObfsEnabled {
		wrapped, err := obfs.WrapPacketConnSalamander(udpConn, []byte(cfg.ObfsPassword))
		if err != nil {
			udpConn.Close()
			m.setError(err)
			return fmt.Errorf("创建 Salamander 混淆器失败: %v", err)
		}
		obfsConn = wrapped
		log.Printf("🔒 [服务端] 已启用 Salamander 混淆（PSK 长度=%d）", len(cfg.ObfsPassword))
	} else {
		log.Printf("⚠️ [服务端] Salamander 混淆未启用")
	}

	transport := &quicgo.Transport{Conn: obfsConn}

	// ⭐ ALPN 改名
	tlsConf, err := m.certMgr.GetTLSConfig([]string{alpnHysteria, alpnData, alpnCtrl})
	if err != nil {
		transport.Close()
		udpConn.Close()
		m.setError(err)
		return fmt.Errorf("构建 TLS 配置失败: %v", err)
	}

	quicConf := &quicgo.Config{
		MaxIdleTimeout:       120 * time.Second,
		KeepAlivePeriod:      keepAlivePeriod,
		MaxIncomingStreams:   int64(maxIncomingStreams),
		InitialPacketSize:    1400,
		HandshakeIdleTimeout: 5 * time.Second,
		EnableDatagrams:      true,
	}
	listener, err := transport.Listen(tlsConf, quicConf)
	if err != nil {
		transport.Close()
		udpConn.Close()
		m.setError(err)
		return fmt.Errorf("创建 listener 失败: %v", err)
	}

	ipAllocator := quic.NewIPAllocator()
	if err := ipAllocator.SetIPPool(cfg.IPPoolStart, cfg.IPPoolEnd); err != nil {
		listener.Close()
		transport.Close()
		udpConn.Close()
		m.setError(err)
		return fmt.Errorf("设置 IP 池失败: %v", err)
	}
	if err := ipAllocator.SetSubnetMask(cfg.SubnetMask); err != nil {
		listener.Close()
		transport.Close()
		udpConn.Close()
		m.setError(err)
		return fmt.Errorf("设置子网掩码失败: %v", err)
	}

	auth := quic.NewCustomAuthenticatorWithAllocator(m.userStore, ipAllocator, cfg.MinClientVersion, cfg.MaxClientVersion)

	// ⭐ 用 certMgr 拿实际证书（hyCfg 需要 tls.Certificate）
	cert, err := m.certMgr.Load()
	if err != nil {
		listener.Close()
		transport.Close()
		udpConn.Close()
		m.setError(err)
		return fmt.Errorf("获取证书失败: %v", err)
	}

	hyCfg := &server.Config{
		TLSConfig: server.TLSConfig{
			Certificates: []tls.Certificate{cert},
		},
		QUICConfig: server.QUICConfig{
			InitialStreamReceiveWindow:     uint64(streamWindow),
			MaxStreamReceiveWindow:         uint64(streamWindow),
			InitialConnectionReceiveWindow: uint64(connWindow),
			MaxConnectionReceiveWindow:     uint64(connWindow),
			MaxIdleTimeout:                 120 * time.Second,
		},
		Authenticator: auth,
		Outbound: quic.NewDHCPOutbound(
			ipAllocator,
			cfg.TCPSplitEnabled, cfg.TCPSplitPorts,
			cfg.UDPReliableEnabled, cfg.UDPReliablePorts,
			cfg.UDPUnreliableEnabled, cfg.UDPUnreliablePorts,
			string(m.certMgr.Mode()), m.certMgr.ServerHostname(),
		),
		BandwidthConfig: server.BandwidthConfig{},
		CongestionConfig: server.CongestionConfig{
			Type:       "bbr",
			BBRProfile: bbrProfile,
		},
	}
	hysteriaSrv, err := server.NewServer(hyCfg)
	if err != nil {
		listener.Close()
		transport.Close()
		udpConn.Close()
		m.setError(err)
		return fmt.Errorf("创建控制面失败: %v", err)
	}

	var serverTun *tun.TUNDevice
	var serverVIP [4]byte
	if cfg.ServerTunEnabled {
		sTun, err := tun.CreateTUN("hy2-srv0", cfg.ServerTunIP, cfg.ServerTunMask, 1380)
		if err != nil {
			log.Printf("⚠️ 创建服务端 TUN 失败: %v（继续运行，本机投递不可用）", err)
		} else {
			serverTun = sTun
			ip := net.ParseIP(cfg.ServerTunIP).To4()
			if ip != nil {
				copy(serverVIP[:], ip)
			}
			log.Printf("✅ 服务端 TUN 已就绪: %s (IP=%s)", sTun.GetName(), cfg.ServerTunIP)
		}
	}

	var udpReliablePorts []int
	if cfg.UDPReliableEnabled {
		udpReliablePorts = expandUDPSplitPorts(cfg.UDPReliablePorts)
	}
	var udpUnreliablePorts []int
	if cfg.UDPUnreliableEnabled {
		udpUnreliablePorts = expandUDPSplitPorts(cfg.UDPUnreliablePorts)
	}

	// ⭐ 修复：原来无条件把 cfg.TCPSplitPorts 当作「游戏 TCP 端口」传给数据面，
	//    导致 TCPSplitEnabled=false 时服务端**仍然**会把这些端口的 TCP
	//    路由到 gameTCP 面（只有客户端侧按开关禁用了，两侧行为不一致）。
	//    现在开关真正生效：关闭时端口表为空，gameTCP 面不会被使用。
	var gamePorts []int
	if cfg.TCPSplitEnabled {
		gamePorts = cfg.TCPSplitPorts
	}

	log.Printf("🎮 [配置] TCP 拆分: %v (%d 个端口)，UDP 匹配: %v (%d 个端口)，UDP 对战: %v (%d 个端口)",
		cfg.TCPSplitEnabled, len(gamePorts),
		cfg.UDPReliableEnabled, len(udpReliablePorts),
		cfg.UDPUnreliableEnabled, len(udpUnreliablePorts))

	dataServer := quic.NewDataChannelServer(
		ipAllocator,
		m.adminState,
		m.userStore,
		auth, // ⭐ 安全审计 S1：数据面注册要用认证器记录的身份来校验
		serverTun,
		serverVIP,
		gamePorts,
		udpReliablePorts,
		udpUnreliablePorts,
	)

	if serverTun != nil {
		go dataServer.ServerTunReadLoop()
		go dataServer.TunWriteLoop()
	}

	go func() {
		obfsTag := "无混淆"
		if cfg.ObfsEnabled {
			obfsTag = "Salamander"
		}
		log.Printf("✅ 服务端已就绪: UDP :%d (ALPN: h3 + h3-data + h3-ctrl, %s)", cfg.Port, obfsTag)
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			alpn := conn.ConnectionState().TLS.NegotiatedProtocol
			switch alpn {
			case alpnHysteria:
				hysteriaSrv.HandleConn(conn)
			case alpnData:
				dataServer.HandleDataConn(conn)
			case alpnCtrl:
				dataServer.HandleCtrlConn(conn)
			default:
				log.Printf("⚠️ [服务端] 未知 ALPN: %q", alpn)
				conn.CloseWithError(0, "unknown ALPN")
			}
		}
	}()

	m.mu.Lock()
	m.running = true
	m.startedAt = time.Now()
	m.lastError = ""
	m.udpConn = udpConn
	m.obfsConn = obfsConn
	m.transport = transport
	m.listener = listener
	m.hysteriaSrv = hysteriaSrv
	m.dataServer = dataServer
	m.ipAllocator = ipAllocator
	m.serverTun = serverTun
	m.mu.Unlock()

	return nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return fmt.Errorf("服务端未运行")
	}
	m.running = false

	listener := m.listener
	transport := m.transport
	udpConn := m.udpConn
	hysteriaSrv := m.hysteriaSrv
	dataServer := m.dataServer
	serverTun := m.serverTun

	m.listener = nil
	m.transport = nil
	m.udpConn = nil
	m.obfsConn = nil
	m.hysteriaSrv = nil
	m.dataServer = nil
	m.serverTun = nil
	m.mu.Unlock()

	log.Printf("🛑 正在停止服务端...")

	if listener != nil {
		_ = listener.Close()
	}
	if hysteriaSrv != nil {
		_ = hysteriaSrv.Close()
	}
	if dataServer != nil {
		_ = dataServer.Close()
	}
	// transport.Close() 会关闭它持有的 PacketConn（obfsConn），obfsConn 会关闭底层 udpConn
	if transport != nil {
		_ = transport.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
	if serverTun != nil {
		_ = serverTun.Close()
		log.Printf("✅ 服务端 TUN 已关闭")
	}

	log.Printf("✅ 服务端已停止")
	return nil
}

func (m *Manager) Restart() error {
	m.mu.RLock()
	running := m.running
	m.mu.RUnlock()
	if running {
		if err := m.Stop(); err != nil {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return m.Start()
}

func (m *Manager) Kick(username string) error {
	m.mu.RLock()
	ds := m.dataServer
	m.mu.RUnlock()
	if ds == nil {
		return fmt.Errorf("服务端未运行")
	}
	return ds.Kick(username)
}

// KickVIP 只踢掉指定 VIP 的那一个连接（共用账号时按连接精确踢出）
func (m *Manager) KickVIP(vip string) error {
	m.mu.RLock()
	ds := m.dataServer
	m.mu.RUnlock()
	if ds == nil {
		return fmt.Errorf("服务端未运行")
	}
	return ds.KickVIP(vip)
}

func (m *Manager) setError(err error) {
	m.mu.Lock()
	m.lastError = err.Error()
	m.mu.Unlock()
}
