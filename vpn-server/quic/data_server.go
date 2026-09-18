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

func (cs *clientStream) writeTCPFrame(data []byte) error {
	cs.tcpWriteMu.Lock()
	defer cs.tcpWriteMu.Unlock()
	return writeFrameToStream(cs.tcpStream, data)
}

// ⭐ 匹配 UDP：走 matchConn stream
func (cs *clientStream) writeMatchFrame(data []byte) error {
	if cs.matchStream == nil {
		// 降级：对端没建立 matchConn，走 dataConn UDP stream
		return cs.writeUDPFrame(data)
	}
	cs.matchWriteMu.Lock()
	defer cs.matchWriteMu.Unlock()
	return writeFrameToStream(cs.matchStream, data)
}

func (cs *clientStream) writeGameTCPFrame(data []byte) error {
	if cs.gameTCPStream == nil {
		return cs.writeTCPFrame(data)
	}
	cs.gameTCPWriteMu.Lock()
	defer cs.gameTCPWriteMu.Unlock()
	return writeFrameToStream(cs.gameTCPStream, data)
}

func (cs *clientStream) writeUDPFrame(data []byte) error {
	cs.udpWriteMu.Lock()
	defer cs.udpWriteMu.Unlock()
	return writeFrameToStream(cs.udpStream, data)
}

func (cs *clientStream) writeICMPFrame(data []byte) error {
	if cs.icmpStream == nil {
		return fmt.Errorf("ICMP 流未就绪")
	}
	cs.icmpWriteMu.Lock()
	defer cs.icmpWriteMu.Unlock()
	return writeFrameToStream(cs.icmpStream, data)
}

func (cs *clientStream) writeHeartbeatFrame(frameType byte, payload []byte) error {
	if cs.hbStream == nil {
		return fmt.Errorf("心跳流未就绪")
	}
	totalLen := 1 + len(payload)
	if 4+totalLen > 4+maxFrameSize {
		return fmt.Errorf("心跳帧过大")
	}

	cs.hbWriteMu.Lock()
	defer cs.hbWriteMu.Unlock()

	bufPtr := writeBufPool.Get().(*[]byte)
	defer writeBufPool.Put(bufPtr)
	buf := *bufPtr

	binary.BigEndian.PutUint32(buf[:4], uint32(totalLen))
	buf[4] = frameType
	if len(payload) > 0 {
		copy(buf[5:], payload)
	}

	_, err := cs.hbStream.Write(buf[:4+totalLen])
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

func readRegFrame(stream *quic.Stream) (string, error) {
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	data, err := io.ReadAll(stream)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("空注册帧")
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
		serverTun:          serverTun,
		serverVIP:          serverVIP,
		tunWriteChan:       make(chan []byte, 512),
		gamePorts:          portMap,
		udpMatchPorts:      matchMap,
		udpUnreliablePorts: unrelMap,
	}
	for i := 0; i < numShards; i++ {
		s.shards[i] = &connShard{
			conns: make(map[[4]byte]*clientStream),
		}
	}
	return s
}

func (s *DataChannelServer) register(vipBytes [4]byte, cs *clientStream) {
	idx := getShardIndex(vipBytes)
	shard := s.shards[idx]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if old, ok := shard.conns[vipBytes]; ok {
		log.Printf("⚠️ VIP %s 重复注册，踢掉旧连接", old.vip)
		if old.dataConn != nil {
			_ = old.dataConn.CloseWithError(0, "replaced by new connection")
		}
		if old.matchConn != nil {
			_ = old.matchConn.CloseWithError(0, "replaced by new connection")
		}
		if old.gameTCPConn != nil {
			_ = old.gameTCPConn.CloseWithError(0, "replaced by new connection")
		}
		if old.gameConn != nil {
			_ = old.gameConn.CloseWithError(0, "replaced by new connection")
		}
		if old.ctrlConn != nil {
			_ = old.ctrlConn.CloseWithError(0, "replaced by new connection")
		}
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

func (s *DataChannelServer) unregisterData(vipBytes [4]byte, cs *clientStream) bool {
	idx := getShardIndex(vipBytes)
	shard := s.shards[idx]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	cur, ok := shard.conns[vipBytes]
	if !ok || cur != cs {
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

func (s *DataChannelServer) Kick(username string) error {
	for i := 0; i < numShards; i++ {
		shard := s.shards[i]
		shard.mu.RLock()
		var target *clientStream
		for _, cs := range shard.conns {
			if cs.username == username {
				target = cs
				break
			}
		}
		shard.mu.RUnlock()

		if target != nil {
			log.Printf("👢 踢出: %s (VIP %s)", username, target.vip)
			if target.dataConn != nil {
				_ = target.dataConn.CloseWithError(0, "kicked by admin")
			}
			if target.matchConn != nil {
				_ = target.matchConn.CloseWithError(0, "kicked by admin")
			}
			if target.gameTCPConn != nil {
				_ = target.gameTCPConn.CloseWithError(0, "kicked by admin")
			}
			if target.gameConn != nil {
				_ = target.gameConn.CloseWithError(0, "kicked by admin")
			}
			if target.ctrlConn != nil {
				_ = target.ctrlConn.CloseWithError(0, "kicked by admin")
			}
			return nil
		}
	}
	return fmt.Errorf("用户 %s 不在线", username)
}

func (s *DataChannelServer) HandleDataConn(conn *quic.Conn) {
	go s.handleDataConn(conn)
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
	mode := strings.TrimSpace(parts[1])
	username := strings.TrimSpace(parts[2])
	vipStr := strings.TrimSpace(parts[3])

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

func (s *DataChannelServer) handleBulkDataConn(
	conn *quic.Conn, ctrlStream *quic.Stream,
	acceptCtx context.Context, mode, username, vipStr string) {

	if username == "" {
		if remoteAddr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			username = remoteAddr.IP.String()
		} else {
			username = "unknown-" + vipStr
		}
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

	log.Printf("✅ [服务端] bulk 控制流: mode=%s user=%s VIP=%s", mode, username, vipStr)

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

	cs, ok := s.lookup(vipBytes)
	if ok {
		cs.dataConn = conn
		cs.tcpStream = tcpStream
		cs.udpStream = udpStream
	} else {
		cs = &clientStream{
			vip:       vipStr,
			vipBytes:  vipBytes,
			username:  username,
			mode:      mode,
			dataConn:  conn,
			tcpStream: tcpStream,
			udpStream: udpStream,
			lastSeen:  time.Now(),
		}
		s.register(vipBytes, cs)
		if s.adminState != nil {
			s.adminState.OnConnect(username, username, mode, vipStr, conn.RemoteAddr().String())
		}
		log.Printf("✅ bulk 数据面已建立: %s (mode=%s, 在线 %d)", username, mode, s.count())
	}

	go s.readTCPStream(tcpStream, cs)
	go s.readUDPStream(udpStream, cs)

	defer func() {
		if s.unregisterData(vipBytes, cs) {
			if s.ipAllocator != nil {
				s.ipAllocator.ReleaseByVirtualIP(vipStr)
			}
			if s.adminState != nil {
				s.adminState.OnDisconnect(username)
			}
			log.Printf("bulk 数据面断开: %s (在线 %d)", username, s.count())
		}
		tcpStream.Close()
		udpStream.Close()
		ctrlStream.Close()
		if cs.matchConn != nil {
			_ = cs.matchConn.CloseWithError(0, "data conn closed")
		}
		if cs.gameTCPConn != nil {
			_ = cs.gameTCPConn.CloseWithError(0, "data conn closed")
		}
		if cs.gameConn != nil {
			_ = cs.gameConn.CloseWithError(0, "data conn closed")
		}
		if cs.ctrlConn != nil {
			_ = cs.ctrlConn.CloseWithError(0, "data conn closed")
		}
	}()

	<-conn.Context().Done()
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

	if username == "" {
		if ra, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			username = ra.IP.String()
		} else {
			username = "unknown-" + vipStr
		}
	}

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

	cs.matchConn = conn
	cs.matchStream = matchStream
	log.Printf("✅ [服务端] 匹配面已关联: %s", username)

	go s.readMatchStream(matchStream, cs)

	defer func() {
		cs.matchStream = nil
		cs.matchConn = nil
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

	if username == "" {
		if ra, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			username = ra.IP.String()
		} else {
			username = "unknown-" + vipStr
		}
	}

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

	cs.gameTCPConn = conn
	cs.gameTCPStream = gameTCPStream
	log.Printf("✅ [服务端] 游戏 TCP 面已关联: %s", username)

	go s.readGameTCPStream(gameTCPStream, cs)

	defer func() {
		cs.gameTCPStream = nil
		cs.gameTCPConn = nil
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

	if username == "" {
		if ra, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			username = ra.IP.String()
		} else {
			username = "unknown-" + vipStr
		}
	}

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

	cs.gameConn = conn
	cs.gameDatagramReady.Store(true)
	log.Printf("✅ [服务端] 游戏 UDP 面已关联: %s（Datagram 已启用）", username)

	if len(s.udpUnreliablePorts) > 0 {
		go s.handleGameDatagrams(conn, cs, username)
	}

	defer func() {
		cs.gameConn = nil
		cs.gameDatagramReady.Store(false)
		ctrlStream.Close()
		log.Printf("游戏 UDP 面断开: %s", username)
	}()

	<-conn.Context().Done()
}

func (s *DataChannelServer) HandleCtrlConn(conn *quic.Conn) {
	go s.handleCtrlConn(conn)
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

	cs.ctrlConn = conn
	cs.icmpStream = icmpStream
	cs.hbStream = hbStream
	cs.ctrlReady.Store(true)

	log.Printf("✅ 控制面已关联: %s", username)

	go s.readICMPStream(icmpStream, cs)
	go s.handleHeartbeatStream(hbStream, cs)

	defer func() {
		cs.ctrlReady.Store(false)
		cs.icmpStream = nil
		cs.hbStream = nil
		cs.ctrlConn = nil
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
		if dst.gameDatagramReady.Load() && dst.gameConn != nil {
			if err := dst.gameConn.SendDatagram(pkt); err != nil {
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
		if dstPort, ok := extractUDPDstPort(pkt); ok && s.isUDPMatchPort(dstPort) && dst.matchStream != nil {
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
				if s.isUDPMatchPort(srcPort) && dst.matchStream != nil {
					err2 = dst.writeMatchFrame(pkt)
					handled = true
				} else if s.isUDPUnreliablePort(srcPort) && dst.gameDatagramReady.Load() && dst.gameConn != nil {
					// 对战端口 → gameConn datagram
					err2 = dst.gameConn.SendDatagram(pkt)
					handled = true
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
					s.adminState.SetClientLatency(cs.username, ms)
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
		s.adminState.AddTraffic(cs.username, u, 0)
		s.adminState.AddTraffic(dst.username, 0, u)
	}
	if cs.mode == "multi" && s.userStore != nil {
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
