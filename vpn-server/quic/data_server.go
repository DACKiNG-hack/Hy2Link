package quic

//data_server.go

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	qcong "vpn-server/quic/congestion"

	"vpn-server/admin"
	"vpn-server/quic/congestion/bbr"
	"vpn-server/store"
	"vpn-server/tun"

	"github.com/apernet/quic-go"
)

const maxFrameSize = 65535
const numShards = 16

const (
	hbTypePing byte = 0x01
	hbTypePong byte = 0x02
)

const (
	gameDgMagic          = "HYUDP"
	gameDgTypeHello byte = 0x01
	gameDgTypeAck   byte = 0x02
)

var debugMode = strings.ToLower(os.Getenv("HY_DEBUG")) == "true"

func isDebugMode() bool { return debugMode }

var writeBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4+maxFrameSize)
		return &b
	},
}

var frameBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, maxFrameSize)
		return &b
	},
}

type connShard struct {
	mu    sync.RWMutex
	conns map[[4]byte]*clientStream
}

func getShardIndex(vip [4]byte) int {
	h := uint32(vip[0]) | uint32(vip[1])<<8 | uint32(vip[2])<<16 | uint32(vip[3])<<24
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	return int(h % numShards)
}

type clientStream struct {
	vip      string
	vipBytes [4]byte

	username string
	mode     string
	// peerIP 认证与数据面所在的 QUIC 对端 IP（不可伪造），用于断开时释放会话
	peerIP string

	// ⭐ 安全审计 S10：auxMu 保护下面全部「附属面」的指针字段。
	//
	// 这些字段原来被多个 goroutine 无锁读写：
	//   - handle*Conn 在建立/断开时写；
	//   - readTCPStream / readUDPStream / readMatchStream / ... 在转发时读。
	// 原来的 atomic.Bool 只保护了「就绪标志」，紧邻的指针不受保护，
	// 于是存在 TOCTOU：Load() 读到 true 之后 gameConn 可能已被置 nil，
	// 紧接着 SendDatagram 解引用 nil → panic → 整个服务端进程崩溃（远端可触发）。
	// 现在「标志 + 指针」都在同一把锁下读写，彻底消除该窗口。
	auxMu sync.RWMutex

	// dataConn：bulk TCP + 非匹配/非对战 UDP
	dataConn   *quic.Conn
	tcpStream  *quic.Stream
	tcpWriteMu sync.Mutex
	udpStream  *quic.Stream
	udpWriteMu sync.Mutex

	// ⭐ matchConn：匹配 UDP（独立连接，Cubic）
	matchConn    *quic.Conn
	matchStream  *quic.Stream
	matchWriteMu sync.Mutex

	// ⭐ gameTCPConn：游戏 TCP（BBR）
	gameTCPConn    *quic.Conn
	gameTCPStream  *quic.Stream
	gameTCPWriteMu sync.Mutex

	// ⭐ gameConn：对战 UDP datagram（QUIC-DC）
	gameConn          *quic.Conn
	gameDatagramReady atomic.Bool

	ctrlConn    *quic.Conn
	ctrlReady   atomic.Bool
	icmpStream  *quic.Stream
	icmpWriteMu sync.Mutex
	hbStream    *quic.Stream
	hbWriteMu   sync.Mutex

	lastSeenMu sync.Mutex
	lastSeen   time.Time
}

// ---------- 附属面指针的安全读写（安全审计 S10） ----------
//
// 约定：所有对上面那些指针字段的访问都必须经过这些方法，
// 不要再直接读写字段本身。

func (cs *clientStream) getDataConn() *quic.Conn {
	cs.auxMu.RLock()
	defer cs.auxMu.RUnlock()
	return cs.dataConn
}

func (cs *clientStream) getTCPStream() *quic.Stream {
	cs.auxMu.RLock()
	defer cs.auxMu.RUnlock()
	return cs.tcpStream
}

func (cs *clientStream) getUDPStream() *quic.Stream {
	cs.auxMu.RLock()
	defer cs.auxMu.RUnlock()
	return cs.udpStream
}

func (cs *clientStream) getMatchStream() *quic.Stream {
	cs.auxMu.RLock()
	defer cs.auxMu.RUnlock()
	return cs.matchStream
}

func (cs *clientStream) getMatchConn() *quic.Conn {
	cs.auxMu.RLock()
	defer cs.auxMu.RUnlock()
	return cs.matchConn
}

func (cs *clientStream) getGameTCPConn() *quic.Conn {
	cs.auxMu.RLock()
	defer cs.auxMu.RUnlock()
	return cs.gameTCPConn
}

func (cs *clientStream) getGameConn() *quic.Conn {
	cs.auxMu.RLock()
	defer cs.auxMu.RUnlock()
	return cs.gameConn
}

func (cs *clientStream) getCtrlConn() *quic.Conn {
	cs.auxMu.RLock()
	defer cs.auxMu.RUnlock()
	return cs.ctrlConn
}

func (cs *clientStream) getICMPStream() *quic.Stream {
	cs.auxMu.RLock()
	defer cs.auxMu.RUnlock()
	return cs.icmpStream
}

func (cs *clientStream) getHBStream() *quic.Stream {
	cs.auxMu.RLock()
	defer cs.auxMu.RUnlock()
	return cs.hbStream
}

// setBulkStreams 登记 bulk 面（dataConn + TCP/UDP 流）
func (cs *clientStream) setBulkStreams(conn *quic.Conn, tcp, udp *quic.Stream) {
	cs.auxMu.Lock()
	cs.dataConn = conn
	cs.tcpStream = tcp
	cs.udpStream = udp
	cs.auxMu.Unlock()
}

// setMatch 登记匹配面。先置指针，再算「就绪」。
func (cs *clientStream) setMatch(conn *quic.Conn, stream *quic.Stream) {
	cs.auxMu.Lock()
	cs.matchConn = conn
	cs.matchStream = stream
	cs.auxMu.Unlock()
}

// clearMatch 注销匹配面
func (cs *clientStream) clearMatch() {
	cs.auxMu.Lock()
	cs.matchConn = nil
	cs.matchStream = nil
	cs.auxMu.Unlock()
}

// setGameTCP 登记游戏 TCP 面
func (cs *clientStream) setGameTCP(conn *quic.Conn, stream *quic.Stream) {
	cs.auxMu.Lock()
	cs.gameTCPConn = conn
	cs.gameTCPStream = stream
	cs.auxMu.Unlock()
}

func (cs *clientStream) clearGameTCP() {
	cs.auxMu.Lock()
	cs.gameTCPConn = nil
	cs.gameTCPStream = nil
	cs.auxMu.Unlock()
}

// setGame 登记对战 UDP datagram 面。
// ⭐ 顺序很重要：先设指针，再置就绪标志。
func (cs *clientStream) setGame(conn *quic.Conn) {
	cs.auxMu.Lock()
	cs.gameConn = conn
	cs.gameDatagramReady.Store(true)
	cs.auxMu.Unlock()
}

// clearGame 注销对战 UDP 面。
// ⭐ 顺序与 setGame 相反：先清就绪标志，再置空指针，
// 与读者在同一把锁下互斥，读者不可能观察到「标志为真但指针为 nil」。
func (cs *clientStream) clearGame() {
	cs.auxMu.Lock()
	cs.gameDatagramReady.Store(false)
	cs.gameConn = nil
	cs.auxMu.Unlock()
}

// setCtrl 登记控制面
func (cs *clientStream) setCtrl(conn *quic.Conn, icmp, hb *quic.Stream) {
	cs.auxMu.Lock()
	cs.ctrlConn = conn
	cs.icmpStream = icmp
	cs.hbStream = hb
	cs.ctrlReady.Store(true)
	cs.auxMu.Unlock()
}

// clearCtrl 注销控制面。
// ⭐ 先清标志，再置空指针（避免「标志为真但流为 nil」）。
func (cs *clientStream) clearCtrl() {
	cs.auxMu.Lock()
	cs.ctrlReady.Store(false)
	cs.icmpStream = nil
	cs.hbStream = nil
	cs.ctrlConn = nil
	cs.auxMu.Unlock()
}

// closeAll 关闭该客户端持有的全部 QUIC 连接（幂等）。
// 先把指针快照出来再关闭，避免持锁调用可能阻塞/回调的 Close。
func (cs *clientStream) closeAll(reason string) {
	cs.auxMu.RLock()
	conns := []*quic.Conn{cs.dataConn, cs.matchConn, cs.gameTCPConn, cs.gameConn, cs.ctrlConn}
	cs.auxMu.RUnlock()

	for _, c := range conns {
		if c != nil {
			_ = c.CloseWithError(0, reason)
		}
	}
}

func (cs *clientStream) writeTCPFrame(data []byte) error {
	cs.tcpWriteMu.Lock()
	defer cs.tcpWriteMu.Unlock()
	stream := cs.getTCPStream()
	if stream == nil {
		return fmt.Errorf("TCP 流未就绪")
	}
	return writeFrameToStream(stream, data)
}

// ⭐ 匹配 UDP：走 matchConn stream
func (cs *clientStream) writeMatchFrame(data []byte) error {
	cs.matchWriteMu.Lock()
	stream := cs.getMatchStream()
	if stream == nil {
		cs.matchWriteMu.Unlock()
		// 降级：对端没建立 matchConn，走 dataConn UDP stream
		return cs.writeUDPFrame(data)
	}
	defer cs.matchWriteMu.Unlock()
	return writeFrameToStream(stream, data)
}

func (cs *clientStream) writeGameTCPFrame(data []byte) error {
	cs.gameTCPWriteMu.Lock()
	stream := cs.getGameTCPStreamLocked()
	if stream == nil {
		cs.gameTCPWriteMu.Unlock()
		return cs.writeTCPFrame(data)
	}
	defer cs.gameTCPWriteMu.Unlock()
	return writeFrameToStream(stream, data)
}

// getGameTCPStreamLocked 语义与 getGameTCPStream 相同，
// 单独命名以表明调用方已持有 gameTCPWriteMu。
func (cs *clientStream) getGameTCPStreamLocked() *quic.Stream {
	cs.auxMu.RLock()
	defer cs.auxMu.RUnlock()
	return cs.gameTCPStream
}

func (cs *clientStream) writeUDPFrame(data []byte) error {
	cs.udpWriteMu.Lock()
	defer cs.udpWriteMu.Unlock()
	stream := cs.getUDPStream()
	if stream == nil {
		return fmt.Errorf("UDP 流未就绪")
	}
	return writeFrameToStream(stream, data)
}

func (cs *clientStream) writeICMPFrame(data []byte) error {
	cs.icmpWriteMu.Lock()
	defer cs.icmpWriteMu.Unlock()
	stream := cs.getICMPStream()
	if stream == nil {
		return fmt.Errorf("ICMP 流未就绪")
	}
	return writeFrameToStream(stream, data)
}

func (cs *clientStream) writeHeartbeatFrame(frameType byte, payload []byte) error {
	totalLen := 1 + len(payload)
	if 4+totalLen > 4+maxFrameSize {
		return fmt.Errorf("心跳帧过大")
	}

	cs.hbWriteMu.Lock()
	defer cs.hbWriteMu.Unlock()

	// ⭐ 安全审计 S10：在写锁内取流，避免流指针被并发替换
	stream := cs.getHBStream()
	if stream == nil {
		return fmt.Errorf("心跳流未就绪")
	}

	bufPtr := writeBufPool.Get().(*[]byte)
	defer writeBufPool.Put(bufPtr)
	buf := *bufPtr

	binary.BigEndian.PutUint32(buf[:4], uint32(totalLen))
	buf[4] = frameType
	if len(payload) > 0 {
		copy(buf[5:], payload)
	}

	_, err := stream.Write(buf[:4+totalLen])
	return err
}

func (cs *clientStream) updateLastSeen() {
	cs.lastSeenMu.Lock()
	cs.lastSeen = time.Now()
	cs.lastSeenMu.Unlock()
}

func writeFrameToStream(stream *quic.Stream, data []byte) error {
	if len(data) > maxFrameSize {
		return fmt.Errorf("帧过大: %d", len(data))
	}
	bufPtr := writeBufPool.Get().(*[]byte)
	defer writeBufPool.Put(bufPtr)
	buf := *bufPtr

	binary.BigEndian.PutUint32(buf[:4], uint32(len(data)))
	copy(buf[4:], data)
	_, err := stream.Write(buf[:4+len(data)])
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

// maxRegFrameSize 注册帧的硬上限。
// 正常注册帧只有几十字节；绝不能对远端可控的流做无界读取。
const maxRegFrameSize = 512

func readRegFrame(stream *quic.Stream) (string, error) {
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	// ⭐ 安全审计 S8：原来用 io.ReadAll 无上限读取，
	//    攻击者可在 10 秒超时内持续灌数据，几十条连接即可打爆服务端内存。
	//    这里用 LimitReader 多读 1 字节以便区分「刚好等于上限」与「超限」。
	data, err := io.ReadAll(io.LimitReader(stream, maxRegFrameSize+1))
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("空注册帧")
	}
	if len(data) > maxRegFrameSize {
		return "", fmt.Errorf("注册帧过大: >%d 字节", maxRegFrameSize)
	}
	return strings.TrimSpace(string(data)), nil
}

type DataChannelServer struct {
	ctx         context.Context
	cancel      context.CancelFunc
	shards      [numShards]*connShard
	ipAllocator *IPAllocator
	adminState  *admin.AdminState
	userStore   *store.Store

	// ⭐ 安全审计 S1：数据面注册必须用认证阶段记录的身份来校验
	auth *CustomAuthenticator

	// ⭐ P2SP 阶段 1：隧道内信令
	//
	// ⚠️ p2pEnabled / signalReg 由 p2pMu 保护：EnableP2PSignal 可以在
	// **运行期**被再次调用（面板关掉 P2P 开关），而 acceptSignalStream /
	// signalReply 会在连接 goroutine 里读它们 —— 裸字段就是数据竞争。
	// 读取一律走 p2pOn() / signalRegistry()。
	p2pMu      sync.RWMutex
	p2pEnabled bool
	signalReg  *admin.SignalRegistry
	// punch 是阶段 1b 的打洞协调表（独立结构，见 punch.go）；
	// 与 signalReg 一样受 p2pMu 保护，关掉 P2P 时连同清理 goroutine 一起停掉。
	punch *punchTable

	// ⭐ D1-a：`peers` 请求的**每 VIP 滑动窗口限流**（键 = 请求方 VIP）。
	// ⚠️ 与 punchTable.rate 同款实现，但**独立**（枚举比打洞更"重"，上限更严：1 次/分钟）。
	// 必须按请求方计数，不能全局计数（否则一个客户端能把所有人限死）。
	peersRateMu sync.Mutex
	peersRate   map[string][]time.Time

	serverTun *tun.TUNDevice
	serverVIP [4]byte

	tunWriteChan chan []byte

	gamePorts map[uint16]bool

	// ⭐ 匹配端口（走 matchConn）
	udpMatchPorts map[uint16]bool
	// ⭐ 对战端口（走 gameConn datagram）
	udpUnreliablePorts map[uint16]bool
}

func (s *DataChannelServer) isGamePort(port uint16) bool {
	return s.gamePorts[port]
}

func (s *DataChannelServer) isUDPMatchPort(port uint16) bool {
	return s.udpMatchPorts[port]
}

func (s *DataChannelServer) isUDPUnreliablePort(port uint16) bool {
	return s.udpUnreliablePorts[port]
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

func extractTCPSrcPort(data []byte) (uint16, bool) {
	if len(data) < 20 {
		return 0, false
	}
	if (data[0]>>4)&0xF != 4 {
		return 0, false
	}
	if data[9] != 6 {
		return 0, false
	}
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl+4 {
		return 0, false
	}
	return binary.BigEndian.Uint16(data[ihl : ihl+2]), true
}

func extractUDPSrcPort(data []byte) (uint16, bool) {
	if len(data) < 20 {
		return 0, false
	}
	if (data[0]>>4)&0xF != 4 {
		return 0, false
	}
	if data[9] != 17 {
		return 0, false
	}
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl+4 {
		return 0, false
	}
	return binary.BigEndian.Uint16(data[ihl : ihl+2]), true
}

func extractUDPDstPort(data []byte) (uint16, bool) {
	if len(data) < 20 {
		return 0, false
	}
	if (data[0]>>4)&0xF != 4 {
		return 0, false
	}
	if data[9] != 17 {
		return 0, false
	}
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl+4 {
		return 0, false
	}
	return binary.BigEndian.Uint16(data[ihl+2 : ihl+4]), true
}

// NewDataChannelServer 参数名保留 udpReliablePorts，语义上等同"匹配端口"
func NewDataChannelServer(
	ipAllocator *IPAllocator,
	adminState *admin.AdminState,
	userStore *store.Store,
	auth *CustomAuthenticator,
	serverTun *tun.TUNDevice,
	serverVIP [4]byte,
	gamePorts []int,
	udpReliablePorts []int,
	udpUnreliablePorts []int,
) *DataChannelServer {
	ctx, cancel := context.WithCancel(context.Background())

	portMap := make(map[uint16]bool, len(gamePorts))
	for _, p := range gamePorts {
		if p > 0 && p <= 65535 {
			portMap[uint16(p)] = true
		}
	}

	matchMap := make(map[uint16]bool, len(udpReliablePorts))
	for _, p := range udpReliablePorts {
		if p > 0 && p <= 65535 {
			matchMap[uint16(p)] = true
		}
	}

	unrelMap := make(map[uint16]bool, len(udpUnreliablePorts))
	for _, p := range udpUnreliablePorts {
		if p > 0 && p <= 65535 {
			unrelMap[uint16(p)] = true
		}
	}

	s := &DataChannelServer{
		ctx:                ctx,
		cancel:             cancel,
		ipAllocator:        ipAllocator,
		adminState:         adminState,
		userStore:          userStore,
		auth:               auth,
		serverTun:          serverTun,
		serverVIP:          serverVIP,
		tunWriteChan:       make(chan []byte, 512),
		gamePorts:          portMap,
		udpMatchPorts:      matchMap,
		udpUnreliablePorts: unrelMap,
		peersRate:          make(map[string][]time.Time),
	}
	for i := 0; i < numShards; i++ {
		s.shards[i] = &connShard{
			conns: make(map[[4]byte]*clientStream),
		}
	}
	return s
}

// EnableP2PSignal 注入隧道内信令所需的依赖（P2SP 阶段 1）。
//
// 用 setter 而不是继续往 NewDataChannelServer 上加位置参数：构造函数已经有
// 9 个参数了。manager.Start 在 accept 循环启动**之前**调用它。
//
// ⭐ 运行期语义（面板把 p2pEnabled 从开改成关时）：
//   - 新连接：不再接受第 4 条信令流（acceptSignalStream 直接返回）；
//   - **已建立**的信令流：立即全部关闭并注销（CloseAllSinks），
//     不是「留着但不再处理」—— 留一条半死的通道会让客户端以为自己
//     还能打洞，而服务端又不再转发，问题会变得很难查。
//     客户端读协程随即收到流结束，SignalQuery 之后会明确报错 → 回落中继。
//   - 关掉再打开：登记表实例仍在（sinks 已清空），新连接可以重新挂载。
//
// 注意：面板改配置目前仍需**重启服务端**才生效（见 Manager.UpdateConfig），
// 所以现实中这条路径等价于「重启 = 断开」；这里实现的是「若将来接上热切换，
// 行为必须是这样」，并有测试覆盖。
func (s *DataChannelServer) EnableP2PSignal(enabled bool, reg *admin.SignalRegistry) {
	s.p2pMu.Lock()
	oldReg := s.signalReg
	oldPunch := s.punch
	s.p2pEnabled = enabled
	s.signalReg = reg
	if enabled {
		// 每次启用都换一张干净的表（旧表可能有残留 attempt）
		s.punch = newPunchTable()
	} else {
		s.punch = nil
	}
	s.p2pMu.Unlock()

	if !enabled {
		// 在锁外关闭：CloseSignal / 停 ticker 都会做 I/O 或等 goroutine，不能持锁
		if oldReg != nil {
			oldReg.CloseAllSinks("服务端关闭了 P2P")
		}
		if oldPunch != nil {
			oldPunch.close()
		}
	}

	if enabled {
		log.Printf("📡 [信令] 隧道内信令已启用（随 h3-ctrl 的第 4 条 stream 提供）")
	} else {
		log.Printf("📡 [信令] 隧道内信令未启用（P2P 关闭），不接受信令流")
	}
}

// p2pOn 读 P2P 开关（并发安全）
func (s *DataChannelServer) p2pOn() bool {
	s.p2pMu.RLock()
	defer s.p2pMu.RUnlock()
	return s.p2pEnabled
}

// signalRegistry 读登记表（并发安全）
func (s *DataChannelServer) signalRegistry() *admin.SignalRegistry {
	s.p2pMu.RLock()
	defer s.p2pMu.RUnlock()
	return s.signalReg
}

// punchTable 读打洞协调表（并发安全）
func (s *DataChannelServer) punchTable() *punchTable {
	s.p2pMu.RLock()
	defer s.p2pMu.RUnlock()
	return s.punch
}

func (s *DataChannelServer) register(vipBytes [4]byte, cs *clientStream) {
	idx := getShardIndex(vipBytes)
	shard := s.shards[idx]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if old, ok := shard.conns[vipBytes]; ok {
		log.Printf("⚠️ VIP %s 重复注册，踢掉旧连接", old.vip)
		// ⭐ 安全审计 S10：统一走 closeAll（内部持锁取快照再关闭）
		old.closeAll("replaced by new connection")
	}
	shard.conns[vipBytes] = cs
}

func (s *DataChannelServer) lookup(vipBytes [4]byte) (*clientStream, bool) {
	idx := getShardIndex(vipBytes)
	shard := s.shards[idx]
	shard.mu.RLock()
	cs, ok := shard.conns[vipBytes]
	shard.mu.RUnlock()
	return cs, ok
}

// ensureOnline 维护"在线状态"（`AdminState` 条目）—— **两条分支共用**（新建 / 接管复用）。
//
// ⚠️ 命名（review 提醒 1）：叫 `ensure*` 而不是 `touch*`/`upsert*` —— 它**既会新建也会更新**
//
//	（底层 `AdminState.OnConnect` 是 upsert：不存在则建、存在则更新并保留计数）。
//	"touch" 会让人误以为"只更新已存在的条目"。
//
// ⚠️ 2026-09-28（面板趋势图 bug · 修法 2 的调用面）：本函数必须由 `handleBulkDataConn` 的
// **两条分支之外**调用，**不能**只放在"新建 `clientStream`"的分支里。
//
//	为什么：若只管新建分支，则"**接管 + 身份相符（复用既有流）**"这条路径**不会维护条目** ⇒
//	一旦该 VIP 的条目此前已丢失（陈旧收尾误删 / 早期竞态），它就**永远不会被补回来**
//	⇒ `AddTraffic` 静默丢弃 ⇒ "Σ 每客户端字节 = 0" ⇒ **面板趋势图恒 0**。
//	这正是 A″（stale-stream 复用跳过 OnConnect）——本 bug 的**主触发链**。
//
// `AdminState.OnConnect` 已是 **upsert** 语义（修法 2）：同身份保留计数、刷新元数据与 `LastSeen`；
//
//	身份变化则视为新会话（防御第二道；第一道是 `handleBulkDataConn` 里的 X′ 拒绝复用）。
//
// 📌 抽出本函数的**额外好处**：它让"复用分支是否维护条目"变成**可单测的生产代码路径**，
//
//	而不是只能靠"测试体自己模拟调用"（那种写法是假守卫：注入"把调用退回新建分支"它照样绿 —— 已实测）。
//	守卫：`quic/admin_state_takeover_test.go` 的 `TestTakeoverReuseRefreshesAdminEntry`。
//
// 📌 `realAddr` 由调用方传入（**不要在本函数里 `conn.RemoteAddr()`**）：这样测试可以传任意地址，
//
//	而不必构造一个"可解引用"的 `quic.Conn`（零值解引用会 panic）。
func (s *DataChannelServer) ensureOnline(cs *clientStream, realAddr string) {
	if s.adminState == nil || cs == nil {
		return
	}
	// ⭐ 在线列表按 **VIP**（每连接唯一）作键，而不是用户名 ——
	//    否则同一账号被多个客户端共用时会互相覆盖。
	s.adminState.OnConnect(cs.vip, cs.username, cs.mode, cs.vip, realAddr)
}

// unregisterData 摘除登记，**仅当"当前登记的数据连接仍是 `myDataConn`"** 时执行。
//
// ⚠️ 2026-09-28（面板趋势图 bug · 修法 1）：判据从"`cur != cs`"改为"**当前 `cur` 的 `dataConn`
// 仍是 `myDataConn`**"。
//
//	为什么必须改：`cs` 是**可被接管复用的对象** —— 同一 VIP 的新数据连接会走"复用分支"
//	（`handleBulkDataConn` 里 `cs.setBulkStreams(newConn, …)`），此时 `shard.conns[vip]` 与
//	"旧连接手里的 `cs`"**是同一个指针** ⇒ 用 `cs` 作身份判据**无法区分新旧连接** ⇒
//	旧连接的**陈旧收尾**会 `delete` 掉新流刚建立的条目（`OnDisconnect`）⇒
//	`AdminState` 条目缺失 ⇒ "Σ 每客户端字节 = 0" ⇒ **面板趋势图恒 0**。
//
//	`myDataConn` 是"**登记时那条数据连接的标识**"（生产里就是 `*quic.Conn` 指针本身）：
//	每条连接各自持有它，且 `dataConn` 的唯一写入点是 `setBulkStreams`（接管时必刷新）⇒ 判据可靠。
//	（测试夹具用独立的小对象当标识，避免构造未初始化的 `quic.Conn`；见 `testConn`。）
func (s *DataChannelServer) unregisterData(vipBytes [4]byte, myDataConn *quic.Conn) bool {
	idx := getShardIndex(vipBytes)
	shard := s.shards[idx]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	cur, ok := shard.conns[vipBytes]
	if !ok {
		return false
	}
	// ⚠️ 身份判据：**当前这条登记的数据连接必须仍是我这条**。
	//	（不能比较 `cur != cs`：接管复用时那仍是同一个 `cs`。）
	if cur.getDataConn() != myDataConn {
		return false
	}
	delete(shard.conns, vipBytes)
	return true
}

func (s *DataChannelServer) count() int {
	total := 0
	for i := 0; i < numShards; i++ {
		s.shards[i].mu.RLock()
		total += len(s.shards[i].conns)
		s.shards[i].mu.RUnlock()
	}
	return total
}

// Kick 踢出某个用户名的**全部**在线连接。
//
// ⭐ 一个账号允许被多个客户端共用（见 authenticator.go 的说明），
// 因此不能只踢第一个匹配的连接 —— 那样共用账号时"踢人"会失效。
func (s *DataChannelServer) Kick(username string) error {
	n := s.kickAll(username)
	if n == 0 {
		return fmt.Errorf("用户 %s 不在线", username)
	}
	log.Printf("👢 踢出: %s（%d 个连接）", username, n)
	return nil
}

// KickVIP 只踢掉占用指定 VIP 的那**一个**连接。
//
// ⭐ 一个账号允许被多个客户端共用，面板的在线列表是「一连接一行」，
// 因此需要能按 VIP 精确踢出，而不是把该账号的所有连接一起踢掉。
func (s *DataChannelServer) KickVIP(vip string) error {
	ip := net.ParseIP(vip)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("无效的 VIP: %s", vip)
	}
	var b [4]byte
	copy(b[:], ip.To4())

	shard := s.shards[getShardIndex(b)]
	shard.mu.RLock()
	cs := shard.conns[b]
	shard.mu.RUnlock()

	if cs == nil {
		return fmt.Errorf("VIP %s 不在线", vip)
	}
	log.Printf("👢 踢出单个连接: %s (VIP %s)", cs.username, vip)
	cs.closeAll("kicked by admin")
	return nil
}

// kickAll 踢掉所有匹配用户名的连接，返回被踢的连接数（便于测试）。
func (s *DataChannelServer) kickAll(username string) int {
	count := 0
	for i := 0; i < numShards; i++ {
		shard := s.shards[i]

		// 先在读锁下收集目标，解锁后再关闭连接 ——
		// 避免持有分片锁时执行可能阻塞/回调的 CloseWithError。
		shard.mu.RLock()
		var targets []*clientStream
		for _, cs := range shard.conns {
			if cs.username == username {
				targets = append(targets, cs)
			}
		}
		shard.mu.RUnlock()

		for _, target := range targets {
			log.Printf("👢 踢出: %s (VIP %s)", username, target.vip)
			// ⭐ 安全审计 S10：统一走 closeAll
			target.closeAll("kicked by admin")
			count++
		}
	}
	return count
}

func (s *DataChannelServer) HandleDataConn(conn *quic.Conn) {
	s.goSafe("handleDataConn", func() { s.handleDataConn(conn) })
}

// goSafe 启动一个带 panic 兜底的 goroutine。
//
// ⭐ 安全审计 S10：转发路径上任何一次 nil 解引用/越界都会终结整个服务端进程
// （main 里没有 recover，托盘也会一起消失）。把故障隔离在单个连接内，
// 避免一个畸形或恶意客户端造成全局拒绝服务。
func (s *DataChannelServer) goSafe(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("💥 [%s] panic 已被捕获: %v\n%s", name, r, debug.Stack())
			}
		}()
		fn()
	}()
}

func (s *DataChannelServer) handleDataConn(conn *quic.Conn) {
	log.Printf("⏳ [服务端] 等待数据/游戏面客户端打开流 (%s)...", conn.RemoteAddr())

	acceptCtx, acceptCancel := context.WithTimeout(conn.Context(), 15*time.Second)
	defer acceptCancel()

	ctrlStream, err := conn.AcceptStream(acceptCtx)
	if err != nil {
		log.Printf("❌ [服务端] 接受控制流失败: %v", err)
		conn.CloseWithError(0, "no control stream")
		return
	}

	regData, err := readRegFrame(ctrlStream)
	if err != nil {
		log.Printf("❌ [服务端] 读取注册信息失败: %v", err)
		ctrlStream.Close()
		conn.CloseWithError(0, "no register")
		return
	}

	parts := strings.SplitN(regData, "\n", 4)
	if len(parts) != 4 {
		log.Printf("❌ [服务端] 无效注册格式: %q", regData)
		ctrlStream.Close()
		conn.CloseWithError(0, "invalid register")
		return
	}
	connType := strings.TrimSpace(parts[0])
	clientMode := strings.TrimSpace(parts[1]) // 客户端自报，仅用于日志
	username := strings.TrimSpace(parts[2])
	vipStr := strings.TrimSpace(parts[3])

	// ⭐ 安全审计 S1（Critical）：注册帧里的 mode/username/vip 全部由客户端自报，
	// 而 h3-data / h3-ctrl 这两条连接从不经过认证器。
	// 原来服务端直接采信，于是：
	//   - 无混淆时任何人不需要口令就能入网；
	//   - 注册别人的 VIP 会覆盖对方的 cs.tcpStream → 完整劫持；
	//   - mode 自报为 single 就不计流量 → 配额形同虚设。
	peerIP := peerIPOf(conn)
	serverMode, authorized := s.authorizePlane(connType, peerIP, username, vipStr)
	if !authorized {
		ctrlStream.Close()
		conn.CloseWithError(0, "unauthorized")
		return
	}
	if clientMode != serverMode {
		log.Printf("ℹ️ [安全] 客户端自报 mode=%q，服务端按 %q 处理 (%s)",
			clientMode, serverMode, username)
	}
	// ⭐ 一律使用服务端认定的模式，客户端无法通过自报绕过流量统计
	mode := serverMode

	switch connType {
	case "data":
		s.handleBulkDataConn(conn, ctrlStream, acceptCtx, mode, username, vipStr)
	case "data-match":
		s.handleMatchConn(conn, ctrlStream, acceptCtx, mode, username, vipStr)
	case "data-game-tcp":
		s.handleGameTCPConn(conn, ctrlStream, acceptCtx, mode, username, vipStr)
	case "data-game":
		s.handleGameDatagramConn(conn, ctrlStream, acceptCtx, mode, username, vipStr)
	default:
		log.Printf("❌ [服务端] 未知注册类型: %q", connType)
		ctrlStream.Close()
		conn.CloseWithError(0, "unknown conn type")
	}
}

// authorizePlane 校验某个「面」的注册帧身份（安全审计 S1）。
//
// ⭐ h3-data 的 4 个面与 h3-ctrl 都必须过这一关。
// 背景：h3-data / h3-ctrl 这两条连接**从不经过 hy-core 的认证器**，
// 它们只靠一帧明文注册信息声明自己是谁。因此服务端必须用
// 「认证阶段留下的授权记录 + QUIC 对端 IP」来核对：
//   - peerIP 来自 QUIC 连接，客户端无法伪造；
//   - username 必须有一次未过期的成功认证（用户名:密码 由 hy-core 校验）；
//   - vip 必须是服务端真通过 DHCP 租出过、且未被别的身份占用的地址。
//
// ⚠️ 历史教训：最初 S1 只覆盖了 h3-data（走 handleDataConn），
// 漏掉了走 HandleCtrlConn 的 h3-ctrl。那会让未认证的连接直接
// 用别人的 VIP 注册控制面，从而覆盖对方的 ctrl 面、以对方身份
// 注入 ICMP 并窃取对方 ICMP 回复。两条入口现在共用这一个函数。
func (s *DataChannelServer) authorizePlane(plane, peerIP, username, vipStr string) (mode string, ok bool) {
	if s.auth == nil {
		log.Printf("❌ [服务端] 认证器未初始化，拒绝 %s 面注册", plane)
		return "", false
	}
	mode, ok = s.auth.AuthorizeDataPlane(peerIP, username, vipStr)
	if !ok {
		log.Printf("🚫 [安全] 拒绝未授权的 %s 面注册: peer=%s user=%q vip=%q",
			plane, peerIP, username, vipStr)
	}
	return mode, ok
}

// peerIPOf 提取 QUIC 连接的对端 IP（不可被客户端伪造）
func peerIPOf(conn *quic.Conn) string {
	addr := conn.RemoteAddr()
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return udpAddr.IP.String()
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

func (s *DataChannelServer) handleBulkDataConn(
	conn *quic.Conn, ctrlStream *quic.Stream,
	acceptCtx context.Context, mode, username, vipStr string) {

	// ⭐ 安全审计 S1：username 已由 AuthorizeDataPlane 校验过（对应一个
	// 刚从同一 peerIP 认证成功的会话），这里不再需要「用对端 IP 兜底」。
	peerIP := peerIPOf(conn)

	parsedIP := net.ParseIP(vipStr)
	if parsedIP == nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "invalid vip")
		return
	}
	ip4 := parsedIP.To4()
	if ip4 == nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "not ipv4")
		return
	}
	var vipBytes [4]byte
	copy(vipBytes[:], ip4)

	log.Printf("✅ [服务端] bulk 控制流: mode=%s user=%s VIP=%s peer=%s",
		mode, username, vipStr, peerIP)

	tcpStream, err := conn.AcceptStream(acceptCtx)
	if err != nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "no tcp stream")
		return
	}
	udpStream, err := conn.AcceptStream(acceptCtx)
	if err != nil {
		ctrlStream.Close()
		tcpStream.Close()
		conn.CloseWithError(0, "no udp stream")
		return
	}

	// ⭐ 安全审计 S7：该 VIP 已被活跃数据面认领，租约不再参与过期回收
	if s.ipAllocator != nil {
		s.ipAllocator.MarkLeaseActive(vipStr)
	}

	cs, ok := s.lookup(vipBytes)

	// ⭐ 2026-09-28（面板趋势图 bug · 修法 X′）：**身份不符 ⇒ 不得接管既有流**。
	//
	// 为什么要拒：既有 `clientStream` 的身份字段（`username/mode/peerIP`）**只在其字面量里写过一次**
	// （全仓没有 `cs.username = …`）⇒ 直接 `setBulkStreams` 接管会**继承旧身份**：
	//   · 流量被记到**别人的账号**（`recordTraffic` 用 `cs.username`）⇒ 配额/计费串号；
	//   · 在线面板显示**别人的用户名**；
	//   · `AdminState` 的 upsert 会把两个客户端的数据混在一起。
	// 触发场景：旧连接被杀（无 FIN）⇒ `shards.conns[vip]` 仍指旧 cs ⇒ 该 VIP 被回收给**别的设备**
	// 后新设备连进来 ⇒ `lookup` 命中旧 cs。
	//
	// ⚠️ **顺序纪律（review 追问 A）**：必须**先 `unregisterData`、后 `closeAll`**。
	//	反了的话：`closeAll` 触发旧连接的 defer → `cleanupDataConnVIP` → 此时 `cur == cs`
	//	⇒ `unregisterData` 返回 true ⇒ **`OnDisconnect` 会把条目删掉**（"上边补、下边漏"）。
	//	先摘登记 ⇒ 旧连接收尾时 `cur` 已不是它（或为空）⇒ 必然早退 ⇒ 不删。
	//
	// ⚠️ 已知代价（记账）：`peerIP` 变化（同设备换网络 4G↔WiFi）也会被判为"身份不符" ⇒
	//	该客户端会以**新会话**出现（面板显示"重新上线"）。这是**如实**的（服务端可见的对端地址确实变了），
	//	但用户可能误解 ⇒ 记账为观察项；若将来要"同设备复用"，需把 `deviceID` 下传到数据面（独立切片）。
	if ok && cs != nil && (cs.username != username || cs.peerIP != peerIP) {
		log.Printf("⚠️ [服务端] VIP %s 的既有数据面属于 %q（peer=%s），新连接 %q（peer=%s）不得接管"+
			"⇒ 丢弃旧流并按新身份重建（避免流量/身份串号）",
			vipStr, cs.username, cs.peerIP, username, peerIP)
		s.unregisterData(vipBytes, cs.getDataConn()) // ① 先摘登记（按"当前登记的 conn"判据）
		cs.closeAll("identity mismatch on takeover") // ② 再关旧流（其收尾将因 cur 已变而早退）
		cs, ok = nil, false                          // ③ 强制走"新建"分支
	}

	if ok {
		// ⭐ 安全审计 S10：同一 VIP 重复注册时，先关掉旧 dataConn 再替换流指针。
		// 否则两条连接会同时向同一个 clientStream 写入，
		// 造成 QUIC 流上帧交错、数据损坏；旧连接的 deferred 清理也
		// 会因为 unregisterData 的 cur != cs 检查而正确地不再释放 IP。
		//
		// ⚠️ 覆盖缺口（review 追问 C，2026-09-28 留档）：**本 X′ 分支目前没有"走完整入口"的用例** ——
		//	`handleBulkDataConn` 需要真实 `*quic.Conn`，而本仓服务端测试**没有 QUIC 握手夹具**
		//	（`newSignalTestServer` 造的是"无 conn 的假流"）。现有的 `quic/admin_state_takeover_test.go`
		//	覆盖的是**它调用的生产函数**（`ensureOnline` / `cleanupDataConnVIP` / `unregisterData`），
		//	**不含**这里的身份判据与"先摘登记后关流"的顺序。⇒ 若要补齐，需先建"真连接测试夹具"（独立小切片）。
		if old := cs.getDataConn(); old != nil && old != conn {
			_ = old.CloseWithError(0, "replaced by new data conn")
		}
		cs.setBulkStreams(conn, tcpStream, udpStream)
	} else {
		cs = &clientStream{
			vip:      vipStr,
			vipBytes: vipBytes,
			username: username,
			mode:     mode,
			peerIP:   peerIP,
			lastSeen: time.Now(),
		}
		cs.setBulkStreams(conn, tcpStream, udpStream)
		s.register(vipBytes, cs)
		log.Printf("✅ bulk 数据面已建立: %s (mode=%s, 在线 %d)", username, mode, s.count())
	}

	// ⭐ 2026-09-28（面板趋势图 bug · 修法 2 的调用面）：**两条分支都必须维护在线状态**。
	//
	// 为什么必须放在 if/else 之外：本调用原先**只在"新建 clientStream"分支**里 ⇒
	//   · 首次连接：条目建立 ✅
	//   · **接管 + 身份相符（复用既有流）**：**不建条目** ⇒ 若该 VIP 的条目此前已丢失
	//     （陈旧收尾误删 / 启动早期竞态），它就**永远不会被补回来** ⇒ `AddTraffic` 静默丢弃
	//     ⇒ "Σ 每客户端字节 = 0" ⇒ **面板趋势图恒 0**（A″ 的"跳过 OnConnect"这一半）。
	//   ⇒ 这正是本 bug 的主触发链：**stale-stream 复用跳过 OnConnect**。
	//
	// `AdminState.OnConnect` 已是 **upsert** 语义（修法 2）：
	//   · 同身份 ⇒ **保留 `BytesIn/BytesOut`**、刷新元数据与 `LastSeen`、不动 `Connected`；
	//   · 身份变化 ⇒ 视为新会话、计数归零（防御第二道；第一道是上面的 X′ 拒绝复用）。
	//   ⇒ 因此"复用分支也调 OnConnect"**不会**让面板数字倒退、也**不会**混身份。
	// ⭐ 2026-09-28（面板趋势图 bug · 修法 2 的调用面）：**维护在线状态** —— 抽成 `ensureOnline`
	//	并由**两条分支共用**（见函数注释：为什么不能只放在"新建"分支里）。
	s.ensureOnline(cs, conn.RemoteAddr().String())

	s.goSafe("readTCPStream", func() { s.readTCPStream(tcpStream, cs) })
	s.goSafe("readUDPStream", func() { s.readUDPStream(udpStream, cs) })

	defer func() {
		s.cleanupDataConnVIP(vipBytes, vipStr, conn, username, peerIP)
		// ⭐ 安全审计 S10：统一注销其余各个面，再关闭本地流。
		// clearXxx 会先清就绪标志再置空指针，读者不会看到半更新状态。
		cs.closeAll("data conn closed")
		tcpStream.Close()
		udpStream.Close()
		ctrlStream.Close()
	}()

	<-conn.Context().Done()
}

// cleanupDataConnVIP 做「VIP 级」的连接收尾，返回是否真的执行了清理。
//
// ⚠️ 只有在**这条连接确实是该 VIP 当前占用者**时才清理（`unregisterData` 内部的
// `cur != cs` 检查）：旧连接的 defer 跑时，新连接可能已经顶上来 —— 无条件清理会
// 把**新会话**的 VIP 释放掉、并误删它的打洞协调记录（重连竞态）。
//
// ⭐ 抽成方法的原因：让上面那条防线可以被测试直接钉住
// （`TestDropByVIPKeepsReplacedConnAttempts`），而不是只靠「代码长这样」。
func (s *DataChannelServer) cleanupDataConnVIP(vipBytes [4]byte, vipStr string,
	myDataConn *quic.Conn, username, peerIP string) bool {
	// ⚠️ 修法 1（2026-09-28）：身份判据是 **`myDataConn`**（本连接自己的数据连接标识），不再是 `cs`。
	//	`cs` 会被"接管复用"复用（新连接把流装到旧 `cs` 上）⇒ 用它无法区分新旧连接；
	//	若陈旧收尾仍能通过判据，就会 `delete` 掉新流刚建立的 `AdminState` 条目（面板趋势图 bug 的成因之一）。
	if !s.unregisterData(vipBytes, myDataConn) {
		return false // 已被新连接顶掉（或本连接已不是当前登记）：什么都不做（重连竞态防线）
	}
	// ⭐ 1b-2B.2：清掉这个 VIP 的全部打洞协调记录。
	//
	// 打洞协调记录原本只靠 TTL(45s) 过期，而 peer-busy 的判据
	// activeResponderCount(peerVIP) 是**记在响应方头上**的 ⇒ 发起方掉线后，
	// 它留下的记录仍占着**对端**的名额，45s 内任何客户端打那个对端都可能被误判「忙」。
	// 踢人（Kick/KickVIP）会关闭连接 ⇒ 同样走这条收尾路径，一并覆盖。
	if pt := s.punchTable(); pt != nil {
		if n := pt.dropByVIP(vipStr); n > 0 {
			log.Printf("🧹 [打洞] %s 断开，清理其 %d 条协调记录（避免残留占对端名额）", vipStr, n)
		}
	}
	if s.ipAllocator != nil {
		s.ipAllocator.ReleaseByVirtualIP(vipStr)
	}
	// ⭐ 安全审计 S1：只释放本连接占用的 VIP；
	//    同一账号/同一出口 IP 下其它客户端的 VIP 不受影响。
	if s.auth != nil {
		s.auth.releaseSession(peerIP, username, vipStr)
	}
	if s.adminState != nil {
		s.adminState.OnDisconnect(vipStr)
	}
	log.Printf("bulk 数据面断开: %s (在线 %d)", username, s.count())
	return true
}

// ⭐ 匹配面：独立连接，Cubic
func (s *DataChannelServer) handleMatchConn(
	conn *quic.Conn, ctrlStream *quic.Stream,
	acceptCtx context.Context, mode, username, vipStr string) {

	log.Printf("✅ [服务端] 匹配面已连接 %s", conn.RemoteAddr())

	parsedIP := net.ParseIP(vipStr)
	if parsedIP == nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "invalid vip")
		return
	}
	ip4 := parsedIP.To4()
	if ip4 == nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "not ipv4")
		return
	}
	var vipBytes [4]byte
	copy(vipBytes[:], ip4)

	// ⭐ 安全审计 S1：username 已由 AuthorizeDataPlane 校验过，
	// 不再需要用对端 IP 兜底（原来的兜底会让未认证连接也能伪造一个身份）。

	matchStream, err := conn.AcceptStream(acceptCtx)
	if err != nil {
		log.Printf("❌ [服务端] 接受 match 流失败: %v", err)
		ctrlStream.Close()
		conn.CloseWithError(0, "no match stream")
		return
	}

	var cs *clientStream
	for i := 0; i < 50; i++ {
		c, ok := s.lookup(vipBytes)
		if ok {
			cs = c
			break
		}
		select {
		case <-s.ctx.Done():
			ctrlStream.Close()
			matchStream.Close()
			conn.CloseWithError(0, "")
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	if cs == nil {
		log.Printf("❌ [服务端] 匹配面等待 bulk 超时: %s", username)
		ctrlStream.Close()
		matchStream.Close()
		conn.CloseWithError(0, "bulk conn not found")
		return
	}

	cs.setMatch(conn, matchStream)
	log.Printf("✅ [服务端] 匹配面已关联: %s", username)

	s.goSafe("readMatchStream", func() { s.readMatchStream(matchStream, cs) })

	defer func() {
		cs.clearMatch()
		matchStream.Close()
		ctrlStream.Close()
		log.Printf("匹配面断开: %s", username)
	}()

	<-conn.Context().Done()
}

func (s *DataChannelServer) handleGameTCPConn(
	conn *quic.Conn, ctrlStream *quic.Stream,
	acceptCtx context.Context, mode, username, vipStr string) {

	// ⭐ 注入 BBR（替换默认 Cubic）
	bbrSender := bbr.NewBbrSender(
		bbr.DefaultClock{},
		conn.InitialPacketSize(),
		bbr.ProfileStandard,
	)
	conn.SetCongestionControl(bbrSender)

	log.Printf("✅ [服务端] 游戏 TCP 面已连接 %s（CC=BBR / profile=standard）", conn.RemoteAddr())

	parsedIP := net.ParseIP(vipStr)
	if parsedIP == nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "invalid vip")
		return
	}
	ip4 := parsedIP.To4()
	if ip4 == nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "not ipv4")
		return
	}
	var vipBytes [4]byte
	copy(vipBytes[:], ip4)

	// ⭐ 安全审计 S1：username 已由 AuthorizeDataPlane 校验过，
	// 不再需要用对端 IP 兜底（原来的兜底会让未认证连接也能伪造一个身份）。

	gameTCPStream, err := conn.AcceptStream(acceptCtx)
	if err != nil {
		log.Printf("❌ [服务端] 接受 game TCP 流失败: %v", err)
		ctrlStream.Close()
		conn.CloseWithError(0, "no game tcp stream")
		return
	}

	var cs *clientStream
	for i := 0; i < 50; i++ {
		c, ok := s.lookup(vipBytes)
		if ok {
			cs = c
			break
		}
		select {
		case <-s.ctx.Done():
			ctrlStream.Close()
			gameTCPStream.Close()
			conn.CloseWithError(0, "")
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	if cs == nil {
		log.Printf("❌ [服务端] 游戏 TCP 面等待 bulk 超时: %s", username)
		ctrlStream.Close()
		gameTCPStream.Close()
		conn.CloseWithError(0, "bulk conn not found")
		return
	}

	cs.setGameTCP(conn, gameTCPStream)
	log.Printf("✅ [服务端] 游戏 TCP 面已关联: %s", username)

	s.goSafe("readGameTCPStream", func() { s.readGameTCPStream(gameTCPStream, cs) })

	defer func() {
		cs.clearGameTCP()
		gameTCPStream.Close()
		ctrlStream.Close()
		log.Printf("游戏 TCP 面断开: %s", username)
	}()

	<-conn.Context().Done()
}

// ⭐ 游戏 UDP datagram 面（握手改用 stream 协商，抗丢包）
func (s *DataChannelServer) handleGameDatagramConn(
	conn *quic.Conn, ctrlStream *quic.Stream,
	acceptCtx context.Context, mode, username, vipStr string) {

	qdc := qcong.NewQUICDCController()
	qdc.SetMaxDatagramSize(conn.InitialPacketSize())
	conn.SetCongestionControl(qdc)
	log.Printf("🎯 [服务端 QUIC-DC] 已注入 gameConn %s", conn.RemoteAddr())

	parsedIP := net.ParseIP(vipStr)
	if parsedIP == nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "invalid vip")
		return
	}
	ip4 := parsedIP.To4()
	if ip4 == nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "not ipv4")
		return
	}
	var vipBytes [4]byte
	copy(vipBytes[:], ip4)

	// ⭐ 安全审计 S1：username 已由 AuthorizeDataPlane 校验过，
	// 不再需要用对端 IP 兜底（原来的兜底会让未认证连接也能伪造一个身份）。

	// ⭐ 接受 datagram 协商流（对应客户端第二条 stream）
	dgStream, err := conn.AcceptStream(acceptCtx)
	if err != nil {
		log.Printf("⚠️ [服务端] 接受 datagram 协商流失败: %v", err)
		ctrlStream.Close()
		conn.CloseWithError(0, "no datagram negotiate stream")
		return
	}

	// 读取协商请求
	_ = dgStream.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	n, err := dgStream.Read(buf)
	if err != nil || strings.TrimSpace(string(buf[:n])) != "datagram-negotiate" {
		log.Printf("⚠️ [服务端] Datagram 协商请求格式错误: %v", err)
		_ = dgStream.Close()
		ctrlStream.Close()
		conn.CloseWithError(0, "invalid datagram negotiate")
		return
	}

	// 等待 bulk 注册完成
	var cs *clientStream
	for i := 0; i < 50; i++ {
		c, ok := s.lookup(vipBytes)
		if ok {
			cs = c
			break
		}
		select {
		case <-s.ctx.Done():
			_ = dgStream.Close()
			ctrlStream.Close()
			conn.CloseWithError(0, "")
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	if cs == nil {
		log.Printf("❌ [服务端] 游戏 UDP 面等待 bulk 超时: %s", username)
		_ = dgStream.Close()
		ctrlStream.Close()
		conn.CloseWithError(0, "bulk conn not found")
		return
	}

	// 回 OK
	if _, werr := dgStream.Write([]byte("datagram-ok\n")); werr != nil {
		log.Printf("⚠️ [服务端] 发送协商回复失败: %v", werr)
		_ = dgStream.Close()
		ctrlStream.Close()
		conn.CloseWithError(0, "datagram negotiate ack failed")
		return
	}
	_ = dgStream.Close()

	cs.setGame(conn)
	log.Printf("✅ [服务端] 游戏 UDP 面已关联: %s（Datagram 已启用）", username)

	if len(s.udpUnreliablePorts) > 0 {
		s.goSafe("handleGameDatagrams", func() { s.handleGameDatagrams(conn, cs, username) })
	}

	defer func() {
		cs.clearGame()
		ctrlStream.Close()
		log.Printf("游戏 UDP 面断开: %s", username)
	}()

	<-conn.Context().Done()
}

func (s *DataChannelServer) HandleCtrlConn(conn *quic.Conn) {
	s.goSafe("handleCtrlConn", func() { s.handleCtrlConn(conn) })
}

func (s *DataChannelServer) handleCtrlConn(conn *quic.Conn) {
	log.Printf("⏳ [服务端] 等待控制面客户端打开 3 条流 (%s)...", conn.RemoteAddr())

	acceptCtx, acceptCancel := context.WithTimeout(conn.Context(), 15*time.Second)
	defer acceptCancel()

	ctrlStream, err := conn.AcceptStream(acceptCtx)
	if err != nil {
		conn.CloseWithError(0, "no control stream")
		return
	}

	regData, err := readRegFrame(ctrlStream)
	if err != nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "no register")
		return
	}

	parts := strings.SplitN(regData, "\n", 4)
	if len(parts) != 4 || parts[0] != "ctrl" {
		ctrlStream.Close()
		conn.CloseWithError(0, "invalid register")
		return
	}
	username := strings.TrimSpace(parts[2])
	vipStr := strings.TrimSpace(parts[3])

	// ⭐ 安全审计 S1（补齐）：控制面以前**没有**做身份校验 ——
	// 未认证的连接只要猜到一个在线 VIP，就能注册控制面并覆盖对方的
	// cs.ctrlConn/icmpStream/hbStream，从而以对方身份注入 ICMP、
	// 窃取对方的 ICMP 回复、伪造对方的心跳与延迟。
	// 现在与 h3-data 的 4 个面共用同一个校验。
	peerIP := peerIPOf(conn)
	if _, authorized := s.authorizePlane("ctrl", peerIP, username, vipStr); !authorized {
		ctrlStream.Close()
		conn.CloseWithError(0, "unauthorized")
		return
	}

	parsedIP := net.ParseIP(vipStr)
	if parsedIP == nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "invalid vip")
		return
	}
	ip4 := parsedIP.To4()
	if ip4 == nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "not ipv4")
		return
	}
	var vipBytes [4]byte
	copy(vipBytes[:], ip4)

	icmpStream, err := conn.AcceptStream(acceptCtx)
	if err != nil {
		ctrlStream.Close()
		conn.CloseWithError(0, "no icmp stream")
		return
	}
	hbStream, err := conn.AcceptStream(acceptCtx)
	if err != nil {
		ctrlStream.Close()
		icmpStream.Close()
		conn.CloseWithError(0, "no heartbeat stream")
		return
	}

	var cs *clientStream
	for i := 0; i < 50; i++ {
		c, ok := s.lookup(vipBytes)
		if ok {
			cs = c
			break
		}
		select {
		case <-s.ctx.Done():
			ctrlStream.Close()
			icmpStream.Close()
			hbStream.Close()
			conn.CloseWithError(0, "")
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	if cs == nil {
		ctrlStream.Close()
		icmpStream.Close()
		hbStream.Close()
		conn.CloseWithError(0, "data conn not found")
		return
	}

	cs.setCtrl(conn, icmpStream, hbStream)

	log.Printf("✅ 控制面已关联: %s", username)

	s.goSafe("readICMPStream", func() { s.readICMPStream(icmpStream, cs) })
	s.goSafe("handleHeartbeatStream", func() { s.handleHeartbeatStream(hbStream, cs) })

	// ⭐ P2SP 阶段 1：可选的**第 4 条** stream = 隧道内信令。
	//
	// 为什么放在这里：这条 stream 挂在已通过 S1 授权的 ctrl 连接上，
	// 所以服务端手里就有 cs（含 cs.vip），信令的身份完全由服务端推导，
	// 客户端不需要也不允许声明自己的 VIP。
	//
	// 关键：独立 goroutine + 自己的超时（见 acceptSignalStream），
	// 旧客户端不会开第 4 条流 → 超时后安静退出，**不影响**上面 3 条面。
	s.goSafe("acceptSignalStream", func() { s.acceptSignalStream(conn, cs) })

	defer func() {
		cs.clearCtrl()
		icmpStream.Close()
		hbStream.Close()
		ctrlStream.Close()
		log.Printf("控制面断开: %s", username)
	}()

	<-conn.Context().Done()
}

func (s *DataChannelServer) readTCPStream(stream *quic.Stream, cs *clientStream) {
	bufPtr := frameBufPool.Get().(*[]byte)
	defer frameBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		pkt, err := readFrame(stream, buf)
		if err != nil {
			return
		}
		if len(pkt) == 0 {
			continue
		}
		cs.updateLastSeen()

		dstIP, ok := extractDstIPv4(pkt)
		if !ok {
			continue
		}
		if isBroadcastOrMulticast(dstIP) {
			continue
		}
		if s.serverTun != nil && dstIP == s.serverVIP {
			s.deliverToLocal(pkt)
			continue
		}
		dst, ok := s.lookup(dstIP)
		if !ok {
			continue
		}
		if err := dst.writeTCPFrame(pkt); err != nil {
			log.Printf("TCP 转发到 %s 失败: %v", ipToString(dstIP), err)
			continue
		}
		s.recordTraffic(cs, dst, len(pkt))
	}
}

// ⭐ 从 matchConn 读到的包，转发到对端 matchConn
func (s *DataChannelServer) readMatchStream(stream *quic.Stream, cs *clientStream) {
	bufPtr := frameBufPool.Get().(*[]byte)
	defer frameBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		pkt, err := readFrame(stream, buf)
		if err != nil {
			errStr := err.Error()
			if errStr != "EOF" && !strings.Contains(errStr, "canceled") && !strings.Contains(errStr, "closed") {
				log.Printf("Match 流读取失败 (%s): %v", cs.username, err)
			}
			return
		}
		if len(pkt) == 0 {
			continue
		}
		cs.updateLastSeen()

		dstIP, ok := extractDstIPv4(pkt)
		if !ok {
			continue
		}
		if isBroadcastOrMulticast(dstIP) {
			continue
		}
		if s.serverTun != nil && dstIP == s.serverVIP {
			s.deliverToLocal(pkt)
			continue
		}
		dst, ok := s.lookup(dstIP)
		if !ok {
			continue
		}
		if err := dst.writeMatchFrame(pkt); err != nil {
			log.Printf("Match 转发到 %s 失败: %v", ipToString(dstIP), err)
			continue
		}
		s.recordTraffic(cs, dst, len(pkt))
	}
}

func (s *DataChannelServer) readGameTCPStream(stream *quic.Stream, cs *clientStream) {
	bufPtr := frameBufPool.Get().(*[]byte)
	defer frameBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		pkt, err := readFrame(stream, buf)
		if err != nil {
			errStr := err.Error()
			if errStr != "EOF" && !strings.Contains(errStr, "canceled") && !strings.Contains(errStr, "closed") {
				log.Printf("Game TCP 流读取失败 (%s): %v", cs.username, err)
			}
			return
		}
		if len(pkt) == 0 {
			continue
		}
		cs.updateLastSeen()

		dstIP, ok := extractDstIPv4(pkt)
		if !ok {
			continue
		}
		if isBroadcastOrMulticast(dstIP) {
			continue
		}
		if s.serverTun != nil && dstIP == s.serverVIP {
			s.deliverToLocal(pkt)
			continue
		}
		dst, ok := s.lookup(dstIP)
		if !ok {
			continue
		}
		if dstPort, ok := extractTCPDstPort(pkt); ok && s.isGamePort(dstPort) {
			if err := dst.writeGameTCPFrame(pkt); err != nil {
				log.Printf("Game TCP 转发到 %s 失败: %v", ipToString(dstIP), err)
				continue
			}
		} else {
			if err := dst.writeTCPFrame(pkt); err != nil {
				log.Printf("TCP 转发到 %s 失败: %v", ipToString(dstIP), err)
				continue
			}
		}
		s.recordTraffic(cs, dst, len(pkt))
	}
}

// ⭐ 游戏 UDP datagram 面（握手已在 stream 协商中完成）
func (s *DataChannelServer) handleGameDatagrams(conn *quic.Conn, cs *clientStream, username string) {
	defer cs.gameDatagramReady.Store(false)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		pkt, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			return
		}
		if len(pkt) == 0 {
			continue
		}
		cs.updateLastSeen()

		dstIP, ok := extractDstIPv4(pkt)
		if !ok {
			continue
		}
		if isBroadcastOrMulticast(dstIP) {
			continue
		}
		if s.serverTun != nil && dstIP == s.serverVIP {
			s.deliverToLocal(pkt)
			continue
		}
		dst, ok := s.lookup(dstIP)
		if !ok {
			continue
		}
		// ⭐ 对战 UDP：转发到对端 gameConn datagram
		// ⭐ 安全审计 S10：用 getGameConn 一次性取值，
		//    原来「先 Load 标志、再用指针」在两者之间可能被置 nil → panic。
		if gc := dst.getGameConn(); gc != nil {
			if err := gc.SendDatagram(pkt); err != nil {
				if debugMode {
					log.Printf("⚠️ [服务端] Datagram 转发失败: %v", err)
				}
			}
		} else {
			// 降级：对端没有 datagram 通道，走 dataConn UDP stream
			if err := dst.writeUDPFrame(pkt); err != nil {
				log.Printf("UDP 转发到 %s 失败: %v", ipToString(dstIP), err)
				continue
			}
		}
		s.recordTraffic(cs, dst, len(pkt))
	}
}

func (s *DataChannelServer) readUDPStream(stream *quic.Stream, cs *clientStream) {
	bufPtr := frameBufPool.Get().(*[]byte)
	defer frameBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		pkt, err := readFrame(stream, buf)
		if err != nil {
			return
		}
		if len(pkt) == 0 {
			continue
		}
		cs.updateLastSeen()

		dstIP, ok := extractDstIPv4(pkt)
		if !ok {
			continue
		}
		if isBroadcastOrMulticast(dstIP) {
			continue
		}
		if s.serverTun != nil && dstIP == s.serverVIP {
			s.deliverToLocal(pkt)
			continue
		}
		dst, ok := s.lookup(dstIP)
		if !ok {
			continue
		}

		// ⭐ 保底：客户端可能没升级，把匹配端口也从 dataConn 走
		if dstPort, ok := extractUDPDstPort(pkt); ok && s.isUDPMatchPort(dstPort) && dst.getMatchStream() != nil {
			if err := dst.writeMatchFrame(pkt); err != nil {
				log.Printf("Match 转发到 %s 失败: %v", ipToString(dstIP), err)
				continue
			}
			s.recordTraffic(cs, dst, len(pkt))
			continue
		}

		// 默认走 dataConn UDP stream
		if err := dst.writeUDPFrame(pkt); err != nil {
			log.Printf("UDP 转发到 %s 失败: %v", ipToString(dstIP), err)
			continue
		}
		s.recordTraffic(cs, dst, len(pkt))
	}
}

func (s *DataChannelServer) readICMPStream(stream *quic.Stream, cs *clientStream) {
	bufPtr := frameBufPool.Get().(*[]byte)
	defer frameBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		pkt, err := readFrame(stream, buf)
		if err != nil {
			return
		}
		if len(pkt) == 0 {
			continue
		}
		cs.updateLastSeen()

		dstIP, ok := extractDstIPv4(pkt)
		if !ok {
			continue
		}
		if s.serverTun != nil && dstIP == s.serverVIP {
			if resp := buildICMPEchoReply(pkt); resp != nil {
				if err := cs.writeICMPFrame(resp); err != nil {
					log.Printf("⚠️ ICMP 回复失败 (%s): %v", cs.username, err)
				}
			}
			continue
		}
		dst, ok := s.lookup(dstIP)
		if !ok {
			continue
		}
		if err := dst.writeICMPFrame(pkt); err != nil {
			log.Printf("ICMP 转发到 %s 失败: %v", ipToString(dstIP), err)
			continue
		}
	}
}

func (s *DataChannelServer) deliverToLocal(pkt []byte) {
	if s.serverTun == nil {
		return
	}
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case s.tunWriteChan <- cp:
	default:
		if debugMode {
			log.Printf("⚠️ TUN 写队列已满，丢弃包 (len=%d)", len(pkt))
		}
	}
}

const tunWriteWorkers = 4

func (s *DataChannelServer) TunWriteLoop() {
	if s.serverTun == nil {
		return
	}
	log.Printf("🔄 [服务端] TUN 写循环已启动（%d workers，无锁）", tunWriteWorkers)

	var wg sync.WaitGroup
	for i := 0; i < tunWriteWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			// ⭐ 安全审计 S10：TUN 写 worker 是全局协程，
			// 一次 panic 会带走整个进程，必须兜底。
			defer func() {
				if r := recover(); r != nil {
					log.Printf("💥 [TunWriteLoop worker=%d] panic 已被捕获: %v\n%s",
						workerID, r, debug.Stack())
				}
			}()
			for {
				select {
				case <-s.ctx.Done():
					return
				case pkt, ok := <-s.tunWriteChan:
					if !ok {
						return
					}
					start := time.Now()
					err := s.serverTun.Write(pkt)
					if dur := time.Since(start); dur > 5*time.Millisecond {
						log.Printf("⚠️ [服务端] TUN.Write 耗时 %v (worker=%d)", dur, workerID)
					}
					if err != nil {
						log.Printf("❌ [服务端] 写入 TUN 失败: %v (worker=%d)", err, workerID)
					}
				}
			}
		}(i)
	}
	wg.Wait()
	log.Printf("🔄 [服务端] TUN 写循环已退出")
}

func (s *DataChannelServer) ServerTunReadLoop() {
	if s.serverTun == nil {
		return
	}
	// ⭐ 安全审计 S10：这是全局协程，panic 会带走整个服务端进程
	defer func() {
		if r := recover(); r != nil {
			log.Printf("💥 [ServerTunReadLoop] panic 已被捕获: %v\n%s", r, debug.Stack())
		}
	}()
	log.Printf("🔄 [服务端] TUN 读循环已启动")
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		pkt, err := s.serverTun.Read()
		if err != nil {
			return
		}
		if len(pkt) < 20 {
			continue
		}
		if (pkt[0]>>4)&0xF != 4 {
			continue
		}

		dstIP, ok := extractDstIPv4(pkt)
		if !ok {
			continue
		}
		if dstIP == s.serverVIP {
			continue
		}
		dst, ok := s.lookup(dstIP)
		if !ok {
			continue
		}

		proto := pkt[9]
		var err2 error
		switch proto {
		case 6:
			if srcPort, ok := extractTCPSrcPort(pkt); ok && s.isGamePort(srcPort) {
				err2 = dst.writeGameTCPFrame(pkt)
			} else {
				err2 = dst.writeTCPFrame(pkt)
			}
		case 17:
			// ⭐ 按源端口分流
			var handled bool
			if srcPort, ok := extractUDPSrcPort(pkt); ok {
				// 匹配端口 → matchConn
				// ⭐ 安全审计 S10：getMatchStream/getGameConn 都是原子的 nil 检查
				if s.isUDPMatchPort(srcPort) && dst.getMatchStream() != nil {
					err2 = dst.writeMatchFrame(pkt)
					handled = true
				} else if s.isUDPUnreliablePort(srcPort) {
					// 对战端口 → gameConn datagram
					if gc := dst.getGameConn(); gc != nil {
						err2 = gc.SendDatagram(pkt)
						handled = true
					}
				}
			}
			if !handled {
				err2 = dst.writeUDPFrame(pkt)
			}
		case 1:
			err2 = dst.writeICMPFrame(pkt)
		default:
			err2 = dst.writeTCPFrame(pkt)
		}
		if err2 != nil {
			log.Printf("⚠️ [服务端] TUN 转发到 %s 失败: %v", ipToString(dstIP), err2)
		}
	}
}

func (s *DataChannelServer) handleHeartbeatStream(stream *quic.Stream, cs *clientStream) {
	defer stream.Close()

	bufPtr := frameBufPool.Get().(*[]byte)
	defer frameBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		pkt, err := readFrame(stream, buf)
		if err != nil {
			return
		}
		if len(pkt) < 1 {
			continue
		}

		frameType := pkt[0]
		switch frameType {
		case hbTypePing:
			cs.updateLastSeen()
			// ⭐ 解析客户端上报的 RTT（4 字节 big-endian）
			if len(pkt) >= 5 {
				ms := int32(binary.BigEndian.Uint32(pkt[1:5]))
				if ms < 0 {
					ms = 0
				}
				if s.adminState != nil && cs.username != "" {
					// ⭐ 按 VIP 作键，支持同一账号多客户端各自的延迟显示
					s.adminState.SetClientLatency(cs.vip, ms)
				}
			}
			if err := cs.writeHeartbeatFrame(hbTypePong, nil); err != nil {
				return
			}
		case hbTypePong:
			cs.updateLastSeen()
		}
	}
}

func (s *DataChannelServer) recordTraffic(cs, dst *clientStream, size int) {
	if s.adminState != nil {
		u := uint64(size)
		// ⭐ 在线统计按 VIP（每连接唯一）作键，支持同一账号多客户端共存
		s.adminState.AddTraffic(cs.vip, u, 0)
		s.adminState.AddTraffic(dst.vip, 0, u)
	}
	// ⭐ 安全审计 S1：原来这里是 `if cs.mode == "multi"`，
	// 而 mode 由客户端在注册帧里自报 —— 改成 "single" 就完全不计流量，
	// 配额/到期策略形同虚设。现在 mode 一律取服务端认定的值
	// （全局密码已移除，所有会话都是多用户模式），因此无条件计账。
	// 同一账号被多客户端共用时，流量累计到该账号（共用一个配额）。
	if s.userStore != nil {
		s.userStore.AddTraffic(cs.username, uint64(size))
	}
}

func isBroadcastOrMulticast(ip [4]byte) bool {
	if ip[0] >= 0xE0 && ip[0] <= 0xEF {
		return true
	}
	if ip[0] == 0xFF && ip[1] == 0xFF && ip[2] == 0xFF && ip[3] == 0xFF {
		return true
	}
	if ip[3] == 0xFF {
		return true
	}
	return ip == [4]byte{}
}

func extractDstIPv4(data []byte) ([4]byte, bool) {
	var zero [4]byte
	if len(data) < 20 {
		return zero, false
	}
	if (data[0]>>4)&0xF != 4 {
		return zero, false
	}
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || ihl > len(data) {
		return zero, false
	}
	var dst [4]byte
	copy(dst[:], data[16:20])
	return dst, true
}

func ipToString(ip [4]byte) string {
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]).String()
}

func (s *DataChannelServer) Close() error {
	s.cancel()
	return nil
}

func buildICMPEchoReply(req []byte) []byte {
	if len(req) < 28 {
		return nil
	}
	if (req[0]>>4)&0xF != 4 {
		return nil
	}
	ihl := int(req[0]&0x0F) * 4
	if ihl < 20 || ihl+8 > len(req) {
		return nil
	}
	if req[9] != 1 {
		return nil
	}
	icmpStart := ihl
	if req[icmpStart] != 8 {
		return nil
	}

	resp := make([]byte, len(req))
	copy(resp, req)

	var tmp [4]byte
	copy(tmp[:], resp[12:16])
	copy(resp[12:16], resp[16:20])
	copy(resp[16:20], tmp[:])

	resp[icmpStart] = 0
	resp[icmpStart+2] = 0
	resp[icmpStart+3] = 0
	cs := icmpChecksum(resp[icmpStart:])
	resp[icmpStart+2] = byte(cs >> 8)
	resp[icmpStart+3] = byte(cs & 0xFF)

	resp[10] = 0
	resp[11] = 0
	ipCS := ipv4Checksum(resp[:ihl])
	resp[10] = byte(ipCS >> 8)
	resp[11] = byte(ipCS & 0xFF)

	return resp
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(header[i])<<8 | uint32(header[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}
