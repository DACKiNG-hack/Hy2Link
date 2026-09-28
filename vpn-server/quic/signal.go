package quic

// vpn-server/quic/signal.go
//
// P2SP 阶段 1：**隧道内**信令通道（服务端侧）。
//
// 载体：客户端在既有 h3-ctrl 连接上多开一条 stream（第 4 条）。
//   - 不动 6 条连接架构（只是同一条连接上多一条 stream）；
//   - 不动 h3-ctrl 的注册帧（仍是 4 行明文）；
//   - 不经过 hy-core 的 Outbound/RequestHook —— 那条路上拿不到身份（见交付说明）。
//
// ⭐ 身份来源：这条 stream 挂在**已通过 S1 授权的 ctrl 连接**上，
// 所以服务端手里就有该连接所属的 clientStream（cs），
// **调用方的 VIP 就是 cs.vip，完全由服务端推导，客户端不声明 VIP**。
// 对端 VIP 由客户端指定，但必须是一个**当前在线**的 clientStream 的 VIP，
// 因此 A 无法借信令去探测/污染任意地址。
//
// ⭐ 通道形态（阶段 1b 的前置条件）：
// 打洞要求双方**同时发包**，所以「A 想连 B」必须由服务端**主动推**给 B，
// 纯请求—响应做不到。因此：
//   - 客户端侧是「常驻读协程 + 写请求等响应」；
//   - 服务端侧把这条流包装成 admin.SignalSink 挂进登记表（VIP → 流），
//     于是服务端随时可以 SendTo(vip, payload) 主动下行；
//   - 流结束时注销，注销带「是不是我这一条」的判据，避免误注销重连后的新流。
//
// 协议：一条双向 stream，上下行各自独立（QUIC stream 的两个方向互不干扰），
// 每条消息 = 4 字节大端长度 + JSON（复用数据面的 writeFrameToStream/readFrame）。
//
//	客户端 → 服务端
//	  {"type":"register","peerVIP":"192.168.30.12","publicAddr":"1.2.3.4:30001",
//	   "natType":"full-cone","metadata":"<64位hex，可选>"}
//	服务端 → 客户端
//	  {"type":"registered"}                                   // peerVIP 为空
//	  {"type":"peer","peerOnline":true,"peerPublicAddr":"5.6.7.8:40002",
//	   "peerNATType":"symmetric","peerMetadata":"<hex，可能为空>"}
//	  {"type":"error","error":"..."}
//	  <1b 起：服务端主动下行的打洞请求（消息类型待定，客户端读协程已预留通道>

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apernet/quic-go"

	"vpn-server/admin"
)

const (
	// signalStreamAcceptTimeout 等待客户端打开第 4 条 stream 的时间。
	// 旧客户端永远不会打开它，超时后安静退出即可，不能影响已有的 3 条面。
	//
	// ⚠️ 与客户端 NAT 探测超时的余量关系（BUG-A 的边界）：
	// 客户端的 NAT 探测总超时是 natDetectTotalTimeout = 10 秒
	// （vpn-tool/backend/quic/nat.go），必须 **小于** 这个 20 秒 ——
	// 客户端是「NAT 探测完成 → 建流并立刻写第一帧」，如果探测比这个窗口还慢，
	// 服务端就已经放弃 accept，那条流永远没人接（推送能力静默失效）。
	// 客户端侧有 TestNATProbeTimeoutFitsServerAcceptWindow 盯着这个余量。
	signalStreamAcceptTimeout = 20 * time.Second

	// ⭐ 冻结的协议约束 1（客户端读协程分派处也有同样一份）：
	// 1b 的**推送**消息类型必须与应答类型 {registered, peer, error} **不相交**。
	// 客户端读协程是按 type 分派的：属于应答类型的消息会被投进「等待槽」，
	// 一旦推送复用了这三个名字，它就会被当成某个在飞请求的应答消耗掉
	// （真正的应答随后到达时反而没人等），或者把错误的响应交给调用方。
	// 推送类型建议用动词式命名并加前缀区分，例如 "punch-request"。
	//
	// signalMsgTypeRegister 客户端上报 + 查询
	signalMsgTypeRegister   = "register"
	signalMsgTypeRegistered = "registered"
	signalMsgTypePeer       = "peer"
	signalMsgTypeError      = "error"

	// ⭐ 阶段 1b：打洞协调（三集合见 P2SP-阶段1b-设计文档.md §2）
	//
	// 请求（c→s）：punch-intent（A 请求协调）、punch-ready（B 回报自己的 punch 地址）
	// 推送（s→c）：punch-invite（请 B 参与）、punch-peer（告知 A：B 已就绪）、
	//             punch-busy（⭐1b-2B：该响应方已满，告知 A 立即收工）
	//
	// ⚠️ 约束 1：推送类型必须与「应答 ∪ 请求」都不相交（三集合两两不相交）。
	signalMsgTypePunchIntent = "punch-intent"
	signalMsgTypePunchReady  = "punch-ready"
	signalMsgTypePunchInvite = "punch-invite"
	signalMsgTypePunchPeer   = "punch-peer"
	// signalMsgTypePunchBusy ⭐ 1b-2B：**推送**（服务端 → 发起方 A）。
	//
	// 为什么「忙」由服务端判定而不是由响应方 B 上报（记账见交付说明的差异表）：
	// B 的并发上限 `punchMaxResponder=2` 是**客户端常量**，B 只会静默忽略多出来的邀请；
	// 而「B 已满」这件事服务端完全知道 —— 那些 invite 本来就是服务端推给 B 的。
	// 所以服务端用「该响应方的活跃 attempt 数 ≥ relayMaxResponderInvites」判定即可，
	// 语义等价，且**只需一个新类型**（B→s 的上报会再多一个请求类型，且更容易漏）。
	signalMsgTypePunchBusy = "punch-busy"

	// ⭐ D1-a：**枚举在线对端**（预打洞侦察的前置）
	//
	//	peers      请求（c→s）：列出「当前可打洞的在线对端 VIP」
	//	peers-list 应答（s→c）：VIP 列表（+ 是否因上限被截断）
	//
	// ⚠️ 应答不叫 `peers`（与请求同名会让日志/抓包无法区分请求与应答）。
	// ⚠️ 边界五项第 3 项变更：信令类型常量 18 → 20（两端各 9 → 10）。
	signalMsgTypePeers     = "peers"
	signalMsgTypePeersList = "peers-list"

	// signalStreamErrorCode 关闭信令流时给对端的 QUIC 流错误码（应用自定义）
	signalStreamErrorCode = 0
)

// signalRequestTypes / signalResponseTypes / signalPushTypes 是三张互不相交的集合（约束 1）。
// 测试会断言两两交集为空、且每个类型常量都在其中之一。
var (
	signalRequestTypes  = []string{signalMsgTypeRegister, signalMsgTypePunchIntent, signalMsgTypePunchReady, signalMsgTypePeers}
	signalResponseTypes = []string{signalMsgTypeRegistered, signalMsgTypePeer, signalMsgTypeError, signalMsgTypePeersList}
	signalPushTypes     = []string{signalMsgTypePunchInvite, signalMsgTypePunchPeer, signalMsgTypePunchBusy}
)

// signalMessage 上下行共用的消息结构（按 type 取用不同字段）
type signalMessage struct {
	Type string `json:"type"`

	// register（客户端 → 服务端）
	PeerVIP    string `json:"peerVIP,omitempty"`
	PublicAddr string `json:"publicAddr,omitempty"`
	NATType    string `json:"natType,omitempty"`
	Metadata   string `json:"metadata,omitempty"`

	// ⭐ 阶段 1b：打洞协调字段（请求/推送共用）
	//
	//	AttemptID         一次打洞尝试的关联 ID（16 hex）
	//	PunchAddr         **punch socket** 的公网地址（≠ PublicAddr，那是 QUIC socket 的）
	//	                  为空是显式语义：「我无法广告打洞地址」
	//	DirectFingerprint 发起方直连自签证书的 SHA-256（64 hex），响应方拨号时固定
	//	WindowMs          打洞窗口（发起方决定，服务端 clamp 后转达）
	AttemptID         string `json:"attemptId,omitempty"`
	PunchAddr         string `json:"punchAddr,omitempty"`
	DirectFingerprint string `json:"directFingerprint,omitempty"`
	WindowMs          int    `json:"windowMs,omitempty"`

	// ⭐ 1b-3（A1）：punchAddrs 同一个 punch socket 的**全部**候选地址（同 IP 多端口）。
	//
	// 为什么需要它：realm 的对称 NAT 端口预测**只在同一 IP 有 ≥2 个相邻端口（差 ≤4）时**
	// 才会触发（`realm/punch_engine.go: predictablePortGroup`）；只广告单地址 ⇒ 预测永不生效。
	// 客户端自己算候选（观测值 + 预测值），服务端只做校验与转发。
	//
	// 兼容：旧客户端不发 ⇒ 为空 ⇒ 服务端只转发 punchAddr（单地址），行为等价 1b-2B。
	PunchAddrs []string `json:"punchAddrs,omitempty"`

	// peer（服务端 → 客户端）
	PeerOnline     bool   `json:"peerOnline,omitempty"`
	PeerPublicAddr string `json:"peerPublicAddr,omitempty"`
	PeerNATType    string `json:"peerNATType,omitempty"`
	PeerMetadata   string `json:"peerMetadata,omitempty"`

	// ⭐ 冻结的协议约束 2（定稿选择 B：新增字段，而不是改 peerOnline 的含义）：
	//   - peerOnline      = 阶段 1a 的原语义，**逐字未改**：
	//                       数据面在线 **且** 信令表里有该 VIP 的登记
	//                       （即「查得到它对外的公网地址」，登记 5 分钟 TTL）；
	//   - peerSignalReady = 服务端**能向对端主动推送**（对端的信令流 sink 存在）。
	// 打洞（1b）要求两者都为真：只有地址、但服务端推不过去「A 想连你」时，
	// 双方无法同时发包，只能回落中继。
	//
	// 为什么选 B 而不是 A：改 peerOnline 的含义会让「对端在线但推不过去」
	// 与「对端彻底离线」变得无法区分（排障时最需要区分的就是这两种），
	// 也会让 1a 已有的 peerOnline 语义/断言失效；新增字段是纯增量，
	// 老客户端读到它只是忽略（omitempty 不影响原有解析）。
	PeerSignalReady bool `json:"peerSignalReady,omitempty"`

	// ⭐ 1b-2B：中继 RTT 估计（服务端 → 客户端，随 peer 应答返回）。
	//
	//	relayRttMs = RTT(查询方↔服务端) + RTT(服务端↔对端)
	//
	// 用途：客户端用它做 standby 判据（直连 RTT 是否明显劣于中继）。
	// **任一侧 RTT 未知时为 0（omitempty → 字段不下发）**，客户端看到 0 就不做 standby
	// 判断（等价于 1b-2A 的行为，保证旧服务端/新客户端兼容）。
	//
	// ⚠️ 近似性：它假设「A→S 与 S→A、S→B 与 B→S」的路径延迟对称，
	// 实测误差约 10~20%，而 standby 阈值是 1.2×（20% 余量）——处于可接受范围；
	// 若将来误判频繁，可改为「服务端在中继转发时打时间戳」（改动更大，未做）。
	RelayRttMs int `json:"relayRttMs,omitempty"`

	// ⭐ D1-a：peers-list 应答 —— 在线对端 VIP 列表 + 是否被上限截断
	//
	// ⚠️ **只回 VIP + signalReady**（不回公网地址/NAT：隐私 + 预打洞不需要）。
	// 截断 = signalReady=true 优先、组内按 VIP 排序、取前 200（确定性）。
	Peers          []SignalPeerEntry `json:"peers,omitempty"`
	PeersTruncated bool              `json:"peersTruncated,omitempty"`

	// error
	Error string `json:"error,omitempty"`
}

// SignalPeerEntry `peers-list` 里的一个条目（D1-a）
type SignalPeerEntry struct {
	VIP         string `json:"vip"`
	SignalReady bool   `json:"signalReady,omitempty"`
}

// ---------- 下行通道（admin.SignalSink 的服务端实现）----------

// signalStreamSink 把一条 QUIC 双向流包装成 admin.SignalSink。
//
// ⚠️ 必须自己带写锁：这条流上的写入有两个来源 ——
//
//	① acceptSignalStream 里的应答（读协程）；
//	② 登记表的主动推送（别的客户端的查询/1b 的打洞请求）。
//
// 两个 goroutine 同时 Write 同一条 QUIC 流会把帧内容交错，必须串行化。
type signalStreamSink struct {
	stream  *quic.Stream
	writeMu sync.Mutex
}

func newSignalStreamSink(stream *quic.Stream) *signalStreamSink {
	return &signalStreamSink{stream: stream}
}

// writeMessage 序列化并写出一条消息（4 字节长度前缀 + JSON）
func (k *signalStreamSink) writeMessage(msg signalMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return k.SendSignal(data)
}

// SendSignal 实现 admin.SignalSink
func (k *signalStreamSink) SendSignal(payload []byte) error {
	if k == nil || k.stream == nil {
		return fmt.Errorf("信令流已关闭")
	}
	k.writeMu.Lock()
	defer k.writeMu.Unlock()
	return writeFrameToStream(k.stream, payload)
}

// CloseSignal 实现 admin.SignalSink
//
// ⚠️ 必须 CancelRead：QUIC 里 Stream.Close() **只关写方向**（发 FIN），
// 读方向仍然开着，acceptSignalStream 的读循环会一直卡在 readFrame 上，
// 关掉 P2P 之后那个 goroutine 就永远不退了。CancelRead 让阻塞的 Read 立刻返回。
func (k *signalStreamSink) CloseSignal() error {
	if k == nil || k.stream == nil {
		return nil
	}
	k.stream.CancelRead(signalStreamErrorCode)
	return k.stream.Close()
}

// signalWriter 是「能回一条消息」的最小接口。
//
// ⭐ 抽出来是为了可测：handler 只需要能回消息，不必依赖真实的 QUIC 流
// （*signalStreamSink 实现它；测试里塞假 sink 就能断言回包内容）。
type signalWriter interface {
	writeMessage(signalMessage) error
}

// ---------- 隧道内信令流 ----------

// acceptSignalStream 在 ctrl 连接上接受**可选**的信令流（第 4 条 stream）并服务它。
//
// ⭐ 与既有 3 条面完全解耦：
//   - 在独立 goroutine 里跑（调用方用 goSafe 启动）；
//   - 用 conn.Context() + 自己的超时，不用 handleCtrlConn 的 15 秒 acceptCtx；
//   - 超时 / 出错只记日志，绝不关闭 conn，也不碰 cs 的其它字段。
//
// ⭐ 外层是**循环**：客户端可能因为超时/网络抖动把流丢掉再重开
// （见客户端 resetSignalStream / signalReopenCooldown）——那时重开的流
// 还是这条 ctrl 连接上的新 stream，服务端必须还能接住，
// 否则客户端之后每次查询都会白等到超时。
//
// 代价控制：第一条流等 signalStreamAcceptTimeout（旧客户端永远不开第 4 条流，
// 超时后安静退出，不留常驻 goroutine）；一旦服务过一条流，就继续等
// （超时后接着等），因为这个客户端已经证明它支持信令 —— 这个 goroutine
// 的生命周期仍然绑在 conn.Context() 上。
func (s *DataChannelServer) acceptSignalStream(conn *quic.Conn, cs *clientStream) {
	// P2P 关闭时不接受信令流（最小攻击面）
	if cs == nil || !s.p2pOn() || s.signalRegistry() == nil {
		return
	}
	reg := s.signalRegistry()

	served := false
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-conn.Context().Done():
			return
		default:
		}
		if !s.p2pOn() {
			return
		}

		ctx, cancel := context.WithTimeout(conn.Context(), signalStreamAcceptTimeout)
		stream, err := conn.AcceptStream(ctx)
		cancel()

		if err != nil {
			if !served {
				// 旧客户端不会开第 4 条流，属正常情况，DEBUG 级别即可
				if isDebugMode() {
					log.Printf("ℹ️ [信令] 未收到信令流（%s）：%v", cs.vip, err)
				}
				return
			}
			// 服务过之后：连接/服务端还在就继续等客户端重开
			if conn.Context().Err() != nil || s.ctx.Err() != nil {
				return
			}
			if !s.p2pOn() {
				return
			}
			if isDebugMode() {
				log.Printf("ℹ️ [信令] %s 的信令流已结束，继续等待重开：%v", cs.vip, err)
			}
			continue
		}

		served = true
		s.serveSignalStream(conn, cs, stream, reg)
	}
}

// serveSignalStream 服务一条信令流（阻塞到这条流结束）
func (s *DataChannelServer) serveSignalStream(
	conn *quic.Conn, cs *clientStream, stream *quic.Stream, reg *admin.SignalRegistry) {

	// ⭐ 先挂载下行通道再进入读循环：这样在对端第一条 register 之前
	//    就已经能被推送（1b 的打洞请求不能被前一条消息的顺序耽误）。
	sink := newSignalStreamSink(stream)
	reg.AttachSink(cs.vip, sink)
	defer func() {
		// ⭐ 注销只在「挂着的还是我这一条」时生效：
		// 客户端重连会先挂上新 sink，旧流的 defer 随后才跑。
		if reg.DetachSink(cs.vip, sink) {
			log.Printf("📴 [信令] 信令流已注销: %s (user=%s)", cs.vip, cs.username)
		}
		_ = sink.CloseSignal()
	}()

	log.Printf("📡 [信令] 隧道内信令流已建立: %s (user=%s)", cs.vip, cs.username)

	bufPtr := frameBufPool.Get().(*[]byte)
	defer frameBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-conn.Context().Done():
			return
		default:
		}

		// 运行期关掉 P2P：本条流会被 CloseAllSinks 关闭，
		// 这里再确认一次，保证「关闭之后不再处理任何信令」。
		if !s.p2pOn() {
			log.Printf("📴 [信令] P2P 已关闭，结束信令流: %s", cs.vip)
			return
		}

		pkt, err := readFrame(stream, buf)
		if err != nil {
			return
		}
		if len(pkt) == 0 {
			continue
		}

		var msg signalMessage
		if err := json.Unmarshal(pkt, &msg); err != nil {
			_ = sink.writeMessage(signalMessage{
				Type:  signalMsgTypeError,
				Error: "invalid json",
			})
			continue
		}

		// ⭐ 请求白名单（约束 1：推送类型不得作为请求；未知类型一律拒绝）
		var err2 error
		switch msg.Type {
		case signalMsgTypeRegister:
			err2 = s.handleSignalRegister(sink, cs, &msg)
		case signalMsgTypePunchIntent:
			err2 = s.handlePunchIntent(sink, cs, &msg)
		case signalMsgTypePunchReady:
			err2 = s.handlePunchReady(sink, cs, &msg)
		case signalMsgTypePeers:
			err2 = s.handleSignalPeers(sink, cs, &msg)
		case signalMsgTypePunchInvite, signalMsgTypePunchPeer:
			err2 = sink.writeMessage(signalMessage{
				Type:  signalMsgTypeError,
				Error: "push type not allowed as request",
			})
		default:
			err2 = sink.writeMessage(signalMessage{
				Type:  signalMsgTypeError,
				Error: "unknown message type",
			})
		}
		if err2 != nil {
			log.Printf("⚠️ [信令] %s 处理失败: %v", cs.vip, err2)
		}
	}
}

// registerLogDedupWindow 「同一 VIP + 同一地址/NAT」重复登记时，
// 这个窗口内的后续登记不再打日志（只为降噪，登记本身照常刷新）。
const registerLogDedupWindow = 5 * time.Second

// shouldLogRegister 判断这次 register 是否值得记一行日志。
//
// ⭐ 为什么会有「重复登记」：见 signalReply 里的说明 —— 客户端开流时那帧
// 「让流可见」的唤醒帧本身就是一次 register，紧接着真正的 register 请求
// 又发一次；两者内容逐字相同。这条规则把它们合并成一行。
//
// 纯函数（时间由调用方传入），便于单测。
func shouldLogRegister(prev admin.PeerInfo, hadPrev bool, addr, nat string, now time.Time) bool {
	if !hadPrev {
		return true
	}
	if prev.PublicAddr != addr || prev.NATType != nat {
		return true
	}
	return now.Sub(prev.LastSeen) >= registerLogDedupWindow
}

// relayRTTLookup 读「某个 clientStream 到服务端」的 RTT（毫秒）；0 = 未知。
//
// ⚠️ 是变量（可注入）而不是直接调 quic-go：单测里造不出带 ConnectionStats 的 *quic.Conn，
// 注入后就能精确测「两个分量相加」「任一侧未知返回 0」等分支。
var relayRTTLookup = func(cs *clientStream) int {
	if cs == nil {
		return 0
	}
	conn := cs.getCtrlConn()
	if conn == nil {
		return 0
	}
	rtt := conn.ConnectionStats().SmoothedRTT
	if rtt <= 0 {
		return 0
	}
	return int(rtt.Milliseconds())
}

// relayRTTMsFor 中继 RTT 估计 = RTT(查询方↔服务端) + RTT(服务端↔对端)。
// 任一侧未知（0）→ 返回 0（客户端据此不做 standby 判断）。
func relayRTTMsFor(s *DataChannelServer, cs *clientStream, peerVIP string) int {
	peer, ok := s.lookupVIP(peerVIP)
	if !ok || peer == nil {
		return 0
	}
	a := relayRTTLookup(cs)
	b := relayRTTLookup(peer)
	if a <= 0 || b <= 0 {
		return 0
	}
	return a + b
}

// handleSignalRegister 处理一次 register：登记自己 + （可选）查询对端。
func (s *DataChannelServer) handleSignalRegister(sink signalWriter, cs *clientStream, msg *signalMessage) error {
	return sink.writeMessage(s.signalReply(cs, msg))
}

// validateSignalSelfFields 校验「客户端对自身的观测」三件套。
//
// ⭐ 抽出来是为了让 punch-intent / punch-ready（它们是 register 的超集）
// 能在**建协调记录之前**就把非法字段挡掉，避免留下死记录并污染限流计数。
func validateSignalSelfFields(publicAddr, natType, metadata string) error {
	if err := admin.ValidatePublicAddr(publicAddr); err != nil {
		return err
	}
	if !admin.ValidNATType(natType) {
		return fmt.Errorf("无效的 natType: %q", natType)
	}
	if _, err := admin.NormalizeMetadata(metadata); err != nil {
		return err
	}
	return nil
}

// signalReply 计算对一条 register 消息的应答。
//
// ⭐ 拆出来是为了能单测：写入 stream 的部分无法在单测里构造，
// 但「身份怎么来、对端能不能查到」这些关键逻辑都在这里。
//
// ⭐ 调用方的 VIP 一律取 cs.vip（服务端在 S1 授权阶段认定的值），
// 消息里根本没有 myVIP 字段 —— 客户端无法让服务端把登记挂到别人的 VIP 上。
func (s *DataChannelServer) signalReply(cs *clientStream, msg *signalMessage) signalMessage {
	if cs == nil || cs.vip == "" {
		return signalMessage{Type: signalMsgTypeError, Error: "no client identity"}
	}
	// ⭐ fail-closed：P2P 关闭（含运行期关闭）后不再接受任何信令
	if !s.p2pOn() {
		return signalMessage{Type: signalMsgTypeError, Error: "signaling disabled"}
	}
	if s.signalRegistry() == nil {
		return signalMessage{Type: signalMsgTypeError, Error: "signaling disabled"}
	}
	reg := s.signalRegistry()

	// ① 登记自己。publicAddr / natType / metadata 是客户端对自身的观测
	//    （不是身份），但仍然全部校验；vip 由服务端给出。
	//
	// ⭐ 先取旧条目：只用于给日志降噪（见 shouldLogRegister），
	//    必须赶在 Update 覆盖 LastSeen 之前取。
	prev, hadPrev := reg.Get(cs.vip)
	if err := reg.Update(cs.vip, msg.PublicAddr, msg.NATType, msg.Metadata); err != nil {
		return signalMessage{Type: signalMsgTypeError, Error: err.Error()}
	}
	// 心跳式刷新：让对端能通过 lookup 感知本连接仍然在线
	cs.updateLastSeen()

	peerVIP := strings.TrimSpace(msg.PeerVIP)
	if peerVIP == "" {
		// ⭐ 日志降噪（登记行为本身不受影响，只是少打几行）：
		//    客户端首次建信令流时会**连发两帧 register** ——
		//      第一帧是「让流对服务端可见」的唤醒帧（QUIC 流在写入首字节前
		//      对服务端不可见，见 vpn-tool/backend/quic/signal.go 的说明），
		//      第二帧才是真正的 register 请求；两帧内容完全相同。
		//    此外每次 SignalQuery 也会再登记一次。
		//    所以「同一 VIP + 同一地址/NAT 在 5 秒内重复上报」只记第一行。
		if shouldLogRegister(prev, hadPrev, msg.PublicAddr, msg.NATType, time.Now()) {
			log.Printf("📡 [信令] 登记 %s → %s (%s)", cs.vip, msg.PublicAddr, msg.NATType)
		}
		return signalMessage{Type: signalMsgTypeRegistered}
	}

	// ② 查询对端：对端必须是一个**当前在线**的数据面连接。
	//    用 lookup 而不是信令表，这样「在线」由数据面权威判断，
	//    也顺带拒绝了借信令对任意地址做探测。
	//
	// ⚠️ peerOnline 的**精确**语义（阶段 1a 就是这样，本次逐字保留）：
	//    数据面在线 **且** 信令表里有该 VIP 的登记 ——
	//    也就是「查得到它的公网地址」。所以下面 PeerOnline=true 是
	//    写在 reg.Get 成功分支**里面**的：
	//      - 数据面在线但还没登记 → peerOnline=false（拿不到地址）
	//      - 数据面离线但有残留登记 → peerOnline=false（对端已经不在了）
	//    这与「对端数据面单纯在线」不是一回事（见 peerSignalReady 的说明）。
	resp := signalMessage{Type: signalMsgTypePeer}
	if _, online := s.lookupVIP(peerVIP); online {
		if peer, ok := reg.Get(peerVIP); ok {
			resp.PeerOnline = true
			resp.PeerPublicAddr = peer.PublicAddr
			resp.PeerNATType = peer.NATType
			resp.PeerMetadata = peer.Metadata
		}
	}
	// ⭐ 协议约束 2（定稿选 B）：单独汇报「服务端能否主动推给它」。
	//    判据就是这条 VIP 有没有挂上下行通道（sink）——
	//    sink 只在「对端的信令流已被 accept 并挂载」时存在，
	//    所以它精确对应「服务端推得过去」这件事。
	//
	// 两者的关系（1b 判定能不能打洞时用）：
	//   - peerOnline=true   → 查得到地址（信令表里有登记，5 分钟 TTL）
	//   - peerSignalReady=true → 推得过去（sink 存在）
	//   - sink 存在**必然**意味着数据面在线：信令流挂在 ctrl 面上，
	//     而 ctrl 面必须等数据面注册完成才会关联（见 handleCtrlConn）。
	resp.PeerSignalReady = reg.HasSink(peerVIP)

	// ⭐ 1b-2B：中继 RTT 估计 = RTT(查询方↔服务端) + RTT(服务端↔对端)
	//
	// 两个分量都从**各自 ctrl 连接**的 QUIC 统计里读（ctrl 面是长连接、一直在跑心跳，
	// 它的 SmoothedRTT 就是「这一端到服务端」的往返延迟）。
	// 任一侧读不到（连接刚建立/已关闭）→ 保持 0，客户端据此不做 standby 判断。
	resp.RelayRttMs = relayRTTMsFor(s, cs, peerVIP)

	log.Printf("📡 [信令] %s 查询 %s → online=%v signalReady=%v addr=%q nat=%q meta=%v",
		cs.vip, peerVIP, resp.PeerOnline, resp.PeerSignalReady, resp.PeerPublicAddr,
		resp.PeerNATType, resp.PeerMetadata != "")

	return resp
}

// PushSignal 服务端向某个 VIP **主动下行**一条信令消息（阶段 1b 的打洞请求用）。
//
// 这就是「拉取式」缺的那一半：B 不需要先发问，服务端也能把
// 「A 想连你」推给 B 的信令流。
//
// ⭐⭐ 冻结的协议约束 1（1b 强化版）：**推送消息的 type 必须与「应答集合 ∪ 请求集合」都不相交**。
// 客户端读协程按 type 分派：应答类型会被投进「等待中的请求槽」，
// 于是推送会被当成某个在飞请求的应答消费掉（真正的应答随后到达时反而没人等），
// 或者把没请求过的响应交给调用方；而与**请求**同名则会让请求白名单与推送出口互相污染。
// 合法推送名只有 signalPushTypes 里的那些（例：punch-invite / punch-peer）。
//
// 相关：客户端侧同一份约束写在 dispatchSignalMessage 上，
// 完整说明见 P2SP-阶段1b-设计文档.md §2。
func (s *DataChannelServer) PushSignal(vip string, msg signalMessage) error {
	if !s.p2pOn() {
		return fmt.Errorf("P2P 未启用，无法推送信令")
	}
	if isRequestOrResponseType(msg.Type) {
		// 约束 1 的运行时兜底：真发生了就报错，别静默把通道搞乱
		return fmt.Errorf("推送消息 type=%q 与请求/应答类型冲突（协议约束 1）", msg.Type)
	}
	if msg.Type == "" {
		return fmt.Errorf("推送消息 type 不能为空")
	}
	reg := s.signalRegistry()
	if reg == nil {
		return fmt.Errorf("信令未初始化")
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return reg.SendTo(vip, payload)
}

// isRequestOrResponseType 判断某个 type 是否属于「请求 ∪ 应答」（推送禁止使用）
func isRequestOrResponseType(t string) bool {
	for _, v := range signalRequestTypes {
		if v == t {
			return true
		}
	}
	for _, v := range signalResponseTypes {
		if v == t {
			return true
		}
	}
	return false
}

// ---------- ⭐ D1-a：枚举在线对端（peers / peers-list）----------

const (
	// peersListMax 单次 `peers-list` 最多返回的 VIP 条数（超出则确定性截断）。
	//
	// ⚠️ 记账（方案 §6.2.1）：大 VPN（>200 客户端）下**第 200 名之后的对端不可见**。
	// 触发条件与候选分批方案（cursor / offset / 批量点名）见 D1-a 方案文档；
	// 在补上分批能力之前，`peersTruncated=true` 就是「你看到的不全」的唯一信号。
	peersListMax = 200
	// peersRateLimit / peersRateWindow：每个 VIP 的频率上限（滑动窗口）。
	// 比打洞限流更严（枚举要遍历注册表，且客户端不该频繁枚举）。
	peersRateLimit  = 1
	peersRateWindow = time.Minute

	// peersRateLimitedCode 限流时的 error 文案。
	//
	// ⚠️ 必须与客户端 `vpn-tool/backend/quic/signal.go` 的 `peersRateLimitedCode`
	// **逐字一致**（两端没有共享包，只能靠常量 + 注释 + 双端测试钉住）——
	// 不一致时客户端会把「限流」误判为「其它错误」，最坏情况是把它当「不支持」缓存。
	peersRateLimitedCode = "peers-rate-limited"
)

// enumerableVIPs ⭐ **枚举范围的唯一出口**。
//
// 凡是「列出在线对端」都必须经过本函数 —— handler 里**不得**直接遍历注册表。
// 为什么把它单独抽出来：它是**权限/隔离点**。当前实现是「同一 VPN 内全量可见」
// （与「能不能打洞」的能力边界恰好一致），但将来引入多租户/房间时，
// 只需改这一处实现，**消息格式与客户端零改动**。
//
// ⚠️ 记账（方案 §5.2）：**当前尚无租户隔离**；若用于多租户部署，
// 需先在此处完成隔离实现（不得只在 handler 里加判断）。
//
// 判据与既有 `peerOnline` **逐字一致**：数据面在线（lookupVIP）**且**信令表有登记（Get）。
// 这样保证「列出来的每一个都查得到」，不会出现「枚举里有它、SignalQuery 说它不在线」的自相矛盾。
// 调用方必须自行**排除自己**。
func (s *DataChannelServer) enumerableVIPs(cs *clientStream) []string {
	if cs == nil || cs.vip == "" {
		return nil
	}
	reg := s.signalRegistry()
	if reg == nil || !s.p2pOn() {
		return nil // fail-closed：P2P 关闭（含运行期关闭）后不枚举
	}
	vips := reg.VIPs()
	out := make([]string, 0, len(vips))
	for _, vip := range vips {
		if vip == cs.vip {
			continue // 不需要跟自己打洞
		}
		if _, online := s.lookupVIP(vip); !online {
			continue // 数据面已离线（残留登记未过期）⇒ 不出现在列表里
		}
		if _, hasReg := reg.Get(vip); !hasReg {
			continue // 没有登记 ⇒ 拿不到地址 ⇒ 与 peerOnline=false 等价
		}
		out = append(out, vip)
	}
	return out
}

// peersSnapshot 生成 peers-list 的条目（**确定性顺序** + 上限截断）。
//
// 排序口径（方案 §6.2，review 补充 A）：**先按 signalReady=true 分组，组内按 VIP 排序**。
// 理由：能推到的对端才有预打洞价值；纯按 VIP 排序会让高段 VIP 永久排在窗口外。
func (s *DataChannelServer) peersSnapshot(cs *clientStream) ([]SignalPeerEntry, bool) {
	vips := s.enumerableVIPs(cs)
	reg := s.signalRegistry()

	type entry struct {
		vip string
		rdy bool
	}
	entries := make([]entry, 0, len(vips))
	for _, v := range vips {
		entries = append(entries, entry{vip: v, rdy: reg.HasSink(v)})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].rdy != entries[j].rdy {
			return entries[i].rdy // true 在前
		}
		return entries[i].vip < entries[j].vip // 组内字典序（确定性）
	})

	truncated := false
	if len(entries) > peersListMax {
		entries = entries[:peersListMax]
		truncated = true
	}
	out := make([]SignalPeerEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, SignalPeerEntry{VIP: e.vip, SignalReady: e.rdy})
	}
	return out, truncated
}

// peersRateAllows 每个 VIP 的滑动窗口限流（键 = **请求方 VIP**，与打洞限流同口径）。
//
// ⚠️ 必须按请求方计数，不能全局计数（否则一个客户端能把所有人限死）。
func (s *DataChannelServer) peersRateAllows(vip string, now time.Time) bool {
	if vip == "" {
		return false
	}
	s.peersRateMu.Lock()
	defer s.peersRateMu.Unlock()
	kept := s.peersRate[vip][:0]
	for _, at := range s.peersRate[vip] {
		if now.Sub(at) <= peersRateWindow {
			kept = append(kept, at)
		}
	}
	if len(kept) >= peersRateLimit {
		s.peersRate[vip] = kept
		return false
	}
	s.peersRate[vip] = append(kept, now)
	return true
}

// handleSignalPeers 处理 `peers` 请求：返回在线对端 VIP 列表（受权限/限流/上限约束）。
func (s *DataChannelServer) handleSignalPeers(sink signalWriter, cs *clientStream, _ *signalMessage) error {
	if cs == nil || cs.vip == "" {
		return sink.writeMessage(signalMessage{Type: signalMsgTypeError, Error: "no client identity"})
	}
	if !s.p2pOn() || s.signalRegistry() == nil {
		return sink.writeMessage(signalMessage{Type: signalMsgTypeError, Error: "signaling disabled"})
	}
	if !s.peersRateAllows(cs.vip, time.Now()) {
		// 客户端对这条**只记日志、不重试**（与 rate-limited 同风格）
		return sink.writeMessage(signalMessage{Type: signalMsgTypeError, Error: peersRateLimitedCode})
	}
	peers, truncated := s.peersSnapshot(cs)
	log.Printf("📡 [信令] %s 枚举在线对端 → %d 个（截断=%v）", cs.vip, len(peers), truncated)
	return sink.writeMessage(signalMessage{
		Type:           signalMsgTypePeersList,
		Peers:          peers,
		PeersTruncated: truncated,
	})
}

// lookupVIP 按 VIP 字符串查询在线数据面连接
func (s *DataChannelServer) lookupVIP(vip string) (*clientStream, bool) {
	parsed := net.ParseIP(vip)
	if parsed == nil {
		return nil, false
	}
	ip4 := parsed.To4()
	if ip4 == nil {
		return nil, false
	}
	var b [4]byte
	copy(b[:], ip4)
	return s.lookup(b)
}
