package quic

// vpn-tool/backend/quic/signal.go
//
// P2SP 阶段 1：**隧道内**信令通道（客户端侧）。
//
// 载体：在既有 h3-ctrl 连接上多开一条 stream（第 4 条）。
//   - 客户端**不声明自己的 VIP** —— 服务端从 ctrl 连接的 S1 授权里推导；
//   - 本机地址/NAT 类型是「对自身的观测」，随 register 一起上报；
//   - 首次 register 不要求对端（只把自己登记上去，让对端能查到我）；
//     之后可以用 SignalQuery 查询指定对端。
//
// ⭐ 通道形态：**常驻读协程 + 写请求等响应**。
//
// 为什么不能是「发一问、读一答」：打洞要求双方**同时发包**，所以
// 「A 想连 B」必须由服务端**主动推**给 B。B 如果只在被查询时才读流，
// 就永远收不到这条推送 —— 拉取式在「A 主动连 B」的场景下不成立。
//
// 因此：
//   - 一条常驻读协程独占这条流的读方向，统一处理所有下行；
//   - SignalQuery 退化成「装好等待槽 → 写请求 → 等响应」的薄封装；
//   - 服务端主动下行（未定义 type）走 push 钩子，通道已预留（见 SignalPush）。
//
// 与既有 3 条 ctrl 流（register/icmp/hb）完全解耦：
// 信令流是可选的，打不开或出错只记日志，P2P 不可用即回落到中继。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
)

const (
	// signalTimeout 单次信令请求的**等待应答**超时（读方向不设截止时间，
	// 见 writeSignalMessage 的注释：SetDeadline 会误杀常驻读协程）。
	// 必须设：如果服务端的 P2P 被关掉（不会 accept 第 4 条流），
	// 客户端写入会因流控而阻塞/无人应答，没有超时就永久卡住。
	signalTimeout = 5 * time.Second

	// signalCloseWait 关闭信令流后等待读协程退出的上限（诊断用）。
	signalCloseWait = 2 * time.Second

	// signalReopenCooldown 流被**对端/网络**断开后的重开冷却。
	// 场景：服务端运行期关掉 P2P → 流被服务端关闭；若不加冷却，
	// 客户端每次 SignalQuery 都会重开一条没人接的流并白等 signalTimeout。
	// 自己主动关闭（超时/退出）不算，见 resetSignalStream。
	signalReopenCooldown = 30 * time.Second

	// 消息类型（与服务端 vpn-server/quic/signal.go 保持一致）
	signalMsgTypeRegister   = "register"
	signalMsgTypeRegistered = "registered"
	signalMsgTypePeer       = "peer"
	signalMsgTypeError      = "error"

	// ⭐ 阶段 1b：打洞协调（三集合见 P2SP-阶段1b-设计文档.md §2）
	signalMsgTypePunchIntent = "punch-intent" // 请求：A 请求服务端协调
	signalMsgTypePunchReady  = "punch-ready"  // 请求：B 回报自己的 punch 地址
	signalMsgTypePunchInvite = "punch-invite" // 推送：请 B 参与
	signalMsgTypePunchPeer   = "punch-peer"   // 推送：告知 A「B 已就绪」
	// ⭐ 1b-2B：推送：告知 A「该响应方已满」，立即收工（不必等 40s 超时）
	signalMsgTypePunchBusy = "punch-busy"

	// ⭐ D1-a：**枚举在线对端**（预打洞侦察的前置）。
	//
	//	peers      请求（c→s）：列出「当前可打洞的在线对端 VIP」
	//	peers-list 应答（s→c）：VIP 列表（+ 是否因上限被截断）
	//
	// ⚠️ 应答**不叫** `peers`（与请求同名）：类型名即身份，客户端读协程按 type 分派，
	//    同名会让日志/抓包无法区分请求与应答（见 D1-a 方案 §2.2）。
	signalMsgTypePeers     = "peers"
	signalMsgTypePeersList = "peers-list"

	// signalStreamErrorCode 关闭信令流时给对端的 QUIC 流错误码（应用自定义）
	signalStreamErrorCode = 0

	// peersRateLimitedCode 服务端限流 `peers` 时的 error 文案。
	//
	// ⚠️ 必须与服务端 `vpn-server/quic/signal.go` 的 `handleSignalPeers` 保持**逐字一致**
	// （两端没有共享包，只能靠常量 + 注释 + 双端测试钉住）。
	peersRateLimitedCode = "peers-rate-limited"

	// alpnDirect 直连（客户端↔客户端）QUIC 的 ALPN。
	// ⚠️ 必须与 hy-core 的三个 ALPN（h3 / h3-data / h3-ctrl）都不同：
	// 复用会让「同一 ALPN 对应两种完全不同的连接用途」，也会让 A 的直连 listener
	// 被 hysteria 客户端误当成服务端。服务端 QUIC listener 不注册它。
	alpnDirect = "h3-direct"
)

// signalExchangeWait 等信令应答的上限（初值 = `signalTimeout`）。
//
// ⚠️⚠️ **只测试用的可覆盖点：生产代码不得写它**（review 追问 3②）。
//
//	唯一的写点是测试辅助 `overrideSignalExchangeWait`（`signal_ctx_test.go`），
//	**且**它只改这一个包级变量、用完由 `t.Cleanup` 还原并校验。
//	生产路径只**读**（超时分支与错误文案都读它，见 `signalExchange`）。
//	若有人在生产代码里给它赋值 ⇒ 线上信令超时会瞬时变化、且 `signalTimeout`
//	这个「唯一真相源」失效 —— 所以 `TestSignalExchangeWaitIsTestOnly` 用**源码级扫描**
//	把这条契约钉死（本仓没有 CI grep 步骤，就把它写成用例）。
//
// 为什么当初不是常量：只有「把等待上限拉长到 60s」才能把「随 ctx 取消立即返回」
// 与「白等到超时」在时间尺度上拉开（量级差 300 倍），否则那条用例没有牙。
var signalExchangeWait = signalTimeout

// 三张互不相交的集合（约束 1：推送 ⊥ (应答 ∪ 请求)）
var (
	signalRequestTypes  = []string{signalMsgTypeRegister, signalMsgTypePunchIntent, signalMsgTypePunchReady, signalMsgTypePeers}
	signalResponseTypes = []string{signalMsgTypeRegistered, signalMsgTypePeer, signalMsgTypeError, signalMsgTypePeersList}
	signalPushTypes     = []string{signalMsgTypePunchInvite, signalMsgTypePunchPeer, signalMsgTypePunchBusy}
)

// isPunchPushType 是否是打洞相关的推送（交给 punchManager，而不是普通 push 钩子）
func isPunchPushType(t string) bool {
	return t == signalMsgTypePunchInvite || t == signalMsgTypePunchPeer || t == signalMsgTypePunchBusy
}

// signalMessage 上下行共用的消息结构
type signalMessage struct {
	Type string `json:"type"`

	// register（客户端 → 服务端）
	PeerVIP    string `json:"peerVIP,omitempty"`
	PublicAddr string `json:"publicAddr,omitempty"`
	NATType    string `json:"natType,omitempty"`
	Metadata   string `json:"metadata,omitempty"`

	// ⭐ 阶段 1b：打洞协调字段（与服务端字段名/顺序严格一致）
	AttemptID         string `json:"attemptId,omitempty"`
	PunchAddr         string `json:"punchAddr,omitempty"`
	DirectFingerprint string `json:"directFingerprint,omitempty"`
	WindowMs          int    `json:"windowMs,omitempty"`

	// ⭐ 1b-3（A1）：punchAddrs 同一个 punch socket 的**全部**候选地址（同 IP 多端口）。
	//
	//	为什么需要它：realm 的对称 NAT 端口预测只在「同一 IP 的 ≥2 个相邻端口（差 ≤4）」
	//	时才触发（realm/punch_engine.go: predictablePortGroup）；只广告单地址 ⇒
	//	预测逻辑一次都不会跑。客户端把观测到的全部映射都广告出去。
	//
	//	兼容：旧服务端/旧对端不认识该字段 → 忽略，只认 punchAddr（单地址，等价 1b-2B）。
	PunchAddrs []string `json:"punchAddrs,omitempty"`

	// peer（服务端 → 客户端）
	PeerOnline     bool   `json:"peerOnline,omitempty"`
	PeerPublicAddr string `json:"peerPublicAddr,omitempty"`
	PeerNATType    string `json:"peerNATType,omitempty"`
	PeerMetadata   string `json:"peerMetadata,omitempty"`
	// PeerSignalReady = 服务端**能向对端主动推送**（对端的信令流 sink 存在）。
	// 与 PeerOnline（数据面在线）是两个独立判断，见下面 SignalPeer 的说明。
	PeerSignalReady bool `json:"peerSignalReady,omitempty"`

	// ⭐ 1b-2B：中继 RTT 估计（服务端 → 客户端，随 peer 应答下发；0/未知时不下发）
	RelayRttMs int `json:"relayRttMs,omitempty"`

	// ⭐ D1-a：peers-list 应答 —— 在线对端 VIP 列表 + 是否被上限截断。
	//
	// ⚠️ **只回 VIP + signalReady**，不回公网地址/NAT（隐私：批量下发会让任一已认证客户端
	//    一次拿到全网对端地址；逐对查询的暴露面小得多，且预打洞本来不需要）。
	// 截断顺序 = signalReady=true 优先分组、组内按 VIP 排序，取前 200（确定性）。
	Peers          []SignalPeerEntry `json:"peers,omitempty"`
	PeersTruncated bool              `json:"peersTruncated,omitempty"`

	// error
	Error string `json:"error,omitempty"`
}

// SignalPeerEntry `peers-list` 里的一个条目（D1-a）。
//
// ⚠️ SignalReady 是**查询那一刻的快照**（服务端此刻能否推给该 VIP）⇒ 客户端**不缓存**
// 该列表（上限 30s），只把它当「优先尝试」的提示；真正的可用性由打洞协商期决定。
type SignalPeerEntry struct {
	VIP         string `json:"vip"`
	SignalReady bool   `json:"signalReady,omitempty"`
}

// ---------- ⭐ D1-a：枚举在线对端 ----------

// ErrPeersUnsupported 表示**服务端不认识 `peers` 请求**（旧服务端）。
//
// 契约（方案 §7）：客户端据此**静默降级** —— 记 info 日志、不重试、不弹提示、
// 不计入失败，并缓存该结论（本次连接内只探测一次）。上层预打洞侦察应直接跳过。
var ErrPeersUnsupported = errors.New("服务端不支持在线对端枚举（旧服务端）")

// ErrPeersRateLimited 表示服务端**限流**了本次枚举（1 次/分钟/VIP）。
//
// ⭐ 为什么必须与 ErrPeersUnsupported **分开**（review 追问 4）：
// 调用方若把「太频繁」误判成「不支持」并缓存，本连接内就**再也不试** peers ⇒ 功能永久失效。
// 语义差别：
//   - Unsupported = 服务端**永远**不会支持（本次连接内可缓存，不必再试）
//   - RateLimited = 只是**这次太快**（等一会儿就能成功；**绝不缓存**）
var ErrPeersRateLimited = errors.New("在线对端枚举请求过于频繁（服务端限流）")

// PeersQuery 请求服务端列出「当前可打洞的在线对端」。
//
// ⚠️ 时效性（方案 §2.4）：返回的是**查询那一刻的快照** ——
//   - **不要**长期缓存（如需缓存，上限 30s）；
//   - 每轮预打洞应**重新请求**；
//   - `SignalReady` 只作「优先尝试」的提示，**不得**当「一定成功」的前提；
//   - `SignalReady=false` 的对端**不要永久拉黑**（可能只是信令流刚断）。
//
// 降级：旧服务端回 `unknown message type` ⇒ 返回 `ErrPeersUnsupported`（errors.Is 可判）。
//
// ⭐ 第 2 步-B（review 追问 3）：**接收 `ctx`**，让调用方的取消能立刻生效。
//
// 为什么必须（原来没有）：本函数内部要走一次同步信令往返（`signalTimeout`=5s），
// 而预打洞调度器正是在这一句上阻塞。若 `ctx` 不生效，`punchManager.close()` 里
// 的 `m.jobs.Wait()` 要等到**超时**才能返回 ⇒ 「取消立即返回」的契约不成立。
// 现在的语义：`ctx` 在往返中途被取消 ⇒ 立刻返回 `ctx.Err()`（不丢流：
// 应答槽由 `signalExchange` 的 defer 摘掉，晚到的应答被安全丢弃
// —— 见 signalPending/generation 的既有机制）。
//
// 既有调用方一律传 `context.Background()`（本包外还有信号查询/打洞会话等）。
func (c *Hysteria2Client) PeersQuery(ctx context.Context) (peers []SignalPeerEntry, truncated bool, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !c.P2PEffective() {
		return nil, false, fmt.Errorf("P2P 未启用（服务端开关=%v）", c.P2PServerEnabled())
	}
	// ⭐ 单次探测缓存：已知服务端不支持 ⇒ 直接返回，不再打一次往返。
	if c.peersUnsupported.Load() {
		return nil, false, ErrPeersUnsupported
	}

	resp, err := c.signalRoundTripCtx(ctx, signalMessage{Type: signalMsgTypePeers})
	if err != nil {
		// ⭐ 错误分三类，**绝不混用**（review 追问 4）：
		//   ① 明确的「不认识该类型」⇒ ErrPeersUnsupported（**可缓存**：本次连接内不再试）
		//   ② 明确的「限流」          ⇒ ErrPeersRateLimited（**不可缓存**：等一会儿就能成功）
		//   ③ 其它（超时/网络/流断开） ⇒ 原样返回，且**不缓存**任何结论
		switch {
		case strings.Contains(err.Error(), "unknown message type"):
			c.peersUnsupported.Store(true)
			log.Printf("ℹ️ [信令] 服务端不支持在线对端枚举（旧服务端）——" +
				"本次连接内不再探测，预打洞侦察静默跳过")
			return nil, false, ErrPeersUnsupported
		case strings.Contains(err.Error(), peersRateLimitedCode):
			// ⚠️ 不缓存：这是**暂时**的，下一次（或稍后）仍应尝试
			log.Printf("ℹ️ [信令] 在线对端枚举被服务端限流（%s）——本次跳过，稍后可再试",
				peersRateLimitedCode)
			return nil, false, ErrPeersRateLimited
		default:
			// ⚠️ **超时不算「不支持」**：超时可能是「服务端忙 / 网络慢」，
			//    把它当成「不支持」并缓存会永久放弃（下次明明支持也不再试）。
			return nil, false, err
		}
	}
	return resp.Peers, resp.PeersTruncated, nil
}

// PeersUnsupportedCached 本机是否已缓存「服务端不支持枚举」的结论（诊断/UI 用）。
func (c *Hysteria2Client) PeersUnsupportedCached() bool {
	return c.peersUnsupported.Load()
}

// SignalPeer 一次对端查询的结果（供阶段 1 的打洞逻辑与 UI 使用）
type SignalPeer struct {
	VIP        string `json:"vip"`
	Online     bool   `json:"online"`
	PublicAddr string `json:"publicAddr"`
	NATType    string `json:"natType"`
	Metadata   string `json:"metadata"`

	// ⭐ 冻结的协议约束 2（定稿选 B：新增字段，而不是把 Online 的含义改掉）。
	//
	//	Online      = 阶段 1a 的原语义，**逐字未改**：
	//	              对端数据面在线 **且** 信令表里有它的登记
	//	              （也就是「服务端查得到它对外的公网地址」，登记 5 分钟 TTL）。
	//	              ⚠️ 它并不等于「对端数据面在线」这一件事。
	//	SignalReady = 服务端**能向对端主动推送**（对端的信令流 sink 存在）。
	//
	// 打洞前必须两个都为真：Online=false 时我们连它的公网地址都拿不到；
	// SignalReady=false 时服务端推不过去「A 想连你」，双方无法同时发包
	// —— 这两种情况都只能回落中继。
	//
	// 关系：SignalReady=true 必然意味着数据面在线（sink 只在信令流被服务端
	// accept 之后存在，而信令流挂在必须等数据面就绪才关联的 ctrl 面上）。
	SignalReady bool `json:"signalReady"`

	// ⭐ 1b-2B：中继 RTT 估计（服务端随 peer 应答下发）。
	//
	//	RelayRTTMs = RTT(本机↔服务端) + RTT(服务端↔对端)
	//
	// 用途：standby 判据（直连 RTT 是否明显劣于中继）。**0 = 服务端不知道**（旧服务端或
	// 某侧刚建立连接），此时客户端**不做** standby 判断 —— 等价于 1b-2A 的行为。
	RelayRTTMs int `json:"relayRttMs"`
}

// SignalPush 服务端**主动下行**的信令消息（阶段 1b 的打洞请求会走这里）。
//
// ⭐ 冻结的协议约束 1（1b 强化版）：Type 必须与「请求 ∪ 应答」都不相交
// （请求：register / punch-intent / punch-ready；应答：registered / peer / error），
// 详见 dispatchSignalMessage 上的说明。
type SignalPush struct {
	Type       string `json:"type"`
	PeerVIP    string `json:"peerVIP,omitempty"`
	PublicAddr string `json:"publicAddr,omitempty"`
	NATType    string `json:"natType,omitempty"`
	Metadata   string `json:"metadata,omitempty"`
	Error      string `json:"error,omitempty"`

	// 打洞推送携带的字段
	AttemptID         string `json:"attemptId,omitempty"`
	PunchAddr         string `json:"punchAddr,omitempty"`
	DirectFingerprint string `json:"directFingerprint,omitempty"`
	WindowMs          int    `json:"windowMs,omitempty"`
}

// SignalPushFromMessage 把内部消息转成对外的推送结构
func SignalPushFromMessage(msg signalMessage) SignalPush {
	return SignalPush{
		Type:              msg.Type,
		PeerVIP:           msg.PeerVIP,
		PublicAddr:        msg.PublicAddr,
		NATType:           msg.NATType,
		Metadata:          msg.Metadata,
		Error:             msg.Error,
		AttemptID:         msg.AttemptID,
		PunchAddr:         msg.PunchAddr,
		DirectFingerprint: msg.DirectFingerprint,
		WindowMs:          msg.WindowMs,
	}
}

// SetSignalPushHandler 注册服务端主动下行的处理钩子（阶段 1b 使用）。
//
// ⚠️ 处理器在**读协程**里同步执行，不要阻塞（阻塞会拖延同一条流上
// 后续的应答；超过 signalCloseWait 还会让关闭流程只能超时返回）。
func (c *Hysteria2Client) SetSignalPushHandler(fn func(SignalPush)) {
	c.signalMu.Lock()
	c.signalPush = fn
	c.signalMu.Unlock()
}

// ---------- 流的打开 / 关闭 ----------

// ensureSignalStream 确保信令流存在（没有就打开、启动常驻读协程，并立刻登记自己）。
//
// ⭐⭐ 一个必须知道的 QUIC 语义（这里的坑，实测确认）：
// 客户端 OpenStreamSync 出来的流，**在对端写入第一个字节之前对服务端不可见**。
// 服务端为此要卡在 AcceptStream 上：如果客户端开完流却不写，
// 服务端就会等到 signalStreamAcceptTimeout(20s) 超时并放弃这条流 ——
// 结果是服务端**永远拿不到这条流、也就永远无法主动推送**。
// 所以这里开完流立刻写一帧 register（它本身就是「登记自己」，
// 打洞要用的地址/NAT 类型正好一起带过去）。
//
// ⭐ 也正因如此，本函数要求 NAT 探测已经拿到公网地址：
// 没有公网地址就既发不出合法的 register，也打不了洞。
// 通道「有内容可说」时才存在，语义最清楚。
func (c *Hysteria2Client) ensureSignalStream() error {
	addr, nat, ok := c.signalSelfInfo()
	if !ok {
		return fmt.Errorf("NAT 探测尚未完成或未取得公网地址，无法建立信令流")
	}

	// 串行化「打开」，避免两个 goroutine 同时看到 nil 各开一条流
	c.signalOpenMu.Lock()
	defer c.signalOpenMu.Unlock()
	return c.ensureSignalStreamLocked(addr, nat)
}

// ensureSignalStreamLocked 调用方必须持有 signalOpenMu
func (c *Hysteria2Client) ensureSignalStreamLocked(addr, nat string) error {
	c.signalMu.Lock()
	alive := c.signalStream != nil
	deadUntil := c.signalDeadUntil
	c.signalMu.Unlock()
	if alive {
		return nil
	}
	if !deadUntil.IsZero() && time.Now().Before(deadUntil) {
		return fmt.Errorf("信令通道刚断开，%.0f 秒后重试",
			time.Until(deadUntil).Seconds())
	}
	if !c.P2PEffective() {
		return fmt.Errorf("P2P 未启用（服务端开关=%v）", c.P2PServerEnabled())
	}
	if c.ctrlConn == nil {
		return fmt.Errorf("控制面未建立，无法建立信令流")
	}

	stream, err := c.ctrlConn.OpenStreamSync(c.ctrlCtx)
	if err != nil {
		return fmt.Errorf("打开信令流失败: %w", err)
	}

	gen := make(chan struct{})
	c.signalMu.Lock()
	c.signalStream = stream
	c.signalGen = gen
	c.signalDeadUntil = time.Time{}
	c.signalMu.Unlock()

	go c.signalReadLoop(stream, gen)

	// ⭐ 立刻写一帧让自己的流对服务端可见（见上面的注释），
	//    同时完成「登记自己」这一步。这是**不等待应答**的写入：
	//    服务端回的 registered 会由读协程当作「无人等待的应答」安静丢掉。
	if err := c.writeSignalMessage(stream, signalMessage{
		Type:       signalMsgTypeRegister,
		PublicAddr: addr,
		NATType:    nat,
	}); err != nil {
		c.closeSignalStreamLocked("首次登记写入失败")
		return fmt.Errorf("信令流首次登记失败: %w", err)
	}

	log.Printf("📡 [信令] 隧道内信令流已建立（h3-ctrl 的第 4 条 stream）")
	return nil
}

// closeSignalStream 关闭信令流并等读协程退出（幂等，可重复调用）。
func (c *Hysteria2Client) closeSignalStream() {
	c.resetSignalStream("连接关闭")
}

// resetSignalStream 主动丢弃当前信令流：关闭 → 等读协程退出 → 允许下次重开。
//
// 调用者：Close() / cleanupPartial() / 请求超时 / 写入失败。
func (c *Hysteria2Client) resetSignalStream(reason string) {
	c.signalOpenMu.Lock()
	defer c.signalOpenMu.Unlock()
	c.closeSignalStreamLocked(reason)
}

// closeSignalStreamLocked 调用方必须持有 signalOpenMu
func (c *Hysteria2Client) closeSignalStreamLocked(reason string) {
	// ⭐ D1-a：换流/重连 ⇒ 清掉「服务端不支持 peers」的缓存（下次重连可再试一次）。
	c.peersUnsupported.Store(false)
	c.signalMu.Lock()
	stream, gen := c.signalStream, c.signalGen
	c.signalStream = nil
	c.signalGen = nil
	c.signalPending = nil
	c.signalMu.Unlock()

	if stream == nil {
		return
	}

	// ⚠️ 必须 CancelRead 而不是只 Close()：
	// QUIC 里 Stream.Close() **只关写方向**（发 FIN），读方向还开着，
	// 读协程会一直卡在 readFrame 上不出来（实测：读协程数永远归不了零）。
	// CancelRead 会让阻塞中的 Read 立刻返回错误，读协程随即退出。
	stream.CancelRead(signalStreamErrorCode)
	_ = stream.Close()
	if gen != nil {
		select {
		case <-gen:
		case <-time.After(signalCloseWait):
			log.Printf("⚠️ [信令] 读协程未在 %v 内退出（%s）", signalCloseWait, reason)
		}
	}

	// 是我们自己关的：清掉冷却，允许立刻重开（例如超时后重试）
	c.signalMu.Lock()
	c.signalDeadUntil = time.Time{}
	c.signalMu.Unlock()

	log.Printf("📴 [信令] 信令流已关闭（%s）", reason)
}

// signalReaderCount 当前活跃的信令读协程数（测试/诊断用；正常只可能是 0 或 1）
func (c *Hysteria2Client) signalReaderCount() int32 {
	return atomic.LoadInt32(&c.signalReaders)
}

// ---------- 常驻读协程 ----------

// signalReadLoop 是信令流唯一的读者：所有下行消息都在这里统一处理。
//
// 退出条件：流被关闭 / 网络断开 / 服务端关闭。退出时 close(gen) 唤醒所有等待者。
func (c *Hysteria2Client) signalReadLoop(stream *quic.Stream, gen chan struct{}) {
	atomic.AddInt32(&c.signalReaders, 1)
	defer atomic.AddInt32(&c.signalReaders, -1)
	defer close(gen) // ⭐ 唤醒所有等待应答/等待重开的调用者

	defer func() {
		c.signalMu.Lock()
		if c.signalStream == stream {
			c.signalStream = nil
			c.signalGen = nil
			// 不是我们主动关的（主动关会在 resetSignalStream 里清掉冷却）
			c.signalDeadUntil = time.Now().Add(signalReopenCooldown)
		}
		c.signalMu.Unlock()
		_ = stream.Close()
		log.Printf("📴 [信令] 读协程退出（信令通道关闭）")
	}()

	buf := make([]byte, maxFrameSize)
	for {
		pkt, err := readFrame(stream, buf)
		if err != nil {
			// 正常关闭也会走到这里（服务端关 P2P / 客户端退出），不刷错误日志
			return
		}
		if len(pkt) == 0 {
			continue
		}
		var msg signalMessage
		if err := json.Unmarshal(pkt, &msg); err != nil {
			log.Printf("⚠️ [信令] 下行消息不是合法 JSON，已忽略: %v", err)
			continue
		}
		c.dispatchSignalMessage(msg)
	}
}

// isResponseType 判断一个下行 type 是不是「应答」（协议约束 1 的判据）。
//
// 应答类型走等待槽，其它一律是推送 → 走 push 钩子。1b 新增推送类型时，
// 只要不落在这三个名字里就自动安全。
// isResponseType 该 type 是否属于「应答集合」。
//
// ⚠️ 必须**引用集合变量**（`signalResponseTypes`），不要写死名字清单：
// 本函数与 `dispatchSignalMessage` 是**两处分派点**，各自写一份硬编码清单就会漂移
// （D1-a 实测：只给 isResponseType 加了 `peers-list`、漏了分派处 ⇒ 应答落到
// `default` 被当成推送丢弃 ⇒ 请求一直等到 5s 超时）。
// 现在两处都只认这一份集合 ⇒ 新增应答类型只需改集合，两个分派点自动一致。
func (c *Hysteria2Client) isResponseType(t string) bool {
	for _, v := range signalResponseTypes {
		if v == t {
			return true
		}
	}
	return false
}

// dispatchSignalMessage 把一条下行消息分派给「等待中的请求」或「push 钩子」。
//
// ⭐⭐ 冻结的协议约束 1（服务端 PushSignal 处有同样一份）：
//
//	1b 的**推送**消息类型必须与应答类型 {registered, peer, error} **不相交**。
//
// 为什么：分派就是按 type 做的 —— 上面这三个类型一律被当作**应答**
// 投进 `signalPending` 等待槽。如果推送复用了这三个名字：
//   - 推送会被当成某个正在飞的请求的应答消耗掉（槽位被清空），
//     真正的应答随后到达时已经没人等 → 调用方等到超时；
//   - 更糟的是调用方可能把推送内容当成对端信息使用（张冠李戴）。
//
// 所以 1b 新增推送类型时必须另起名字（例："punch-request"、"punch-result"）。
// 服务端 PushSignal 里有同名校验会直接拒绝复用的 type；客户端这里用
// 「**不是应答 ⇒ 一律当推送**」兜底：未知 type 也交给 push 钩子，绝不投进等待槽。
func (c *Hysteria2Client) dispatchSignalMessage(msg signalMessage) {
	// ⚠️ 判据**只认集合变量**（`isResponseType` 内部引用 `signalResponseTypes`）——
	//    这里**不得**再写一份硬编码名字清单（D1-a 踩过：两份清单漂移 ⇒ 应答被当推送丢弃）。
	if c.isResponseType(msg.Type) {
		// 这些是**应答**：交给正在等待的请求
		c.signalMu.Lock()
		ch := c.signalPending
		c.signalPending = nil
		c.signalMu.Unlock()
		if ch == nil {
			// 建流时那一帧「让流可见」的 register 是 fire-and-forget，
			// 它的 registered 应答本来就没有等待者 —— 正常，不用记日志。
			// 其它类型的无主应答才值得报出来。
			if msg.Type != signalMsgTypeRegistered {
				log.Printf("⚠️ [信令] 收到没有请求对应的应答 type=%q，已忽略", msg.Type)
			}
			return
		}
		select {
		case ch <- msg:
		default: // 槽位是 1 缓冲，正常不会走到这里
		}
		return
	}
	// 非应答类型 ⇒ 一律当**推送**处理（未知 type 也走这里，绝不投进等待槽）。
	//
	// ⚠️ 这一支**必须保留**（方案 §2.3）：将来新增的推送类型若尚未被客户端识别，
	//    也要能走到 push 钩子；若这里写成 `return` 静默丢弃，新推送类型就会"看起来没生效"。
	log.Printf("📡 [信令] 收到服务端主动下行 type=%q（交给 push 处理）", msg.Type)
	// 打洞推送先交给 punchManager（它才是真正的消费者）
	if isPunchPushType(msg.Type) {
		c.deliverPunchPush(msg)
	}
	c.signalMu.Lock()
	h := c.signalPush
	c.signalMu.Unlock()
	if h != nil {
		h(SignalPushFromMessage(msg))
	}
}

// deliverPunchPush 把打洞推送交给 punchManager。
//
// ⚠️ 本函数在读协程里执行，**绝不能阻塞**（1a 的钩子约束）：
// punchManager.onPush 只做「投递到 channel」这一件事。
func (c *Hysteria2Client) deliverPunchPush(msg signalMessage) {
	c.punchMu.Lock()
	mgr := c.punchMgr
	c.punchMu.Unlock()
	if mgr != nil {
		mgr.onPush(msg)
	}
}

// ---------- 请求—响应 ----------

// signalRoundTrip 发一条消息并等一条应答（薄封装：写 + 等读协程投递）。
//
// ⭐ 用 signalReqMu 串行化整个往返：协议**没有请求 ID**，
// 同一条流上并发两个请求就无法把它们各自的应答对应回去。
func (c *Hysteria2Client) signalRoundTrip(msg signalMessage) (*signalMessage, error) {
	return c.signalRoundTripCtx(nil, msg)
}

// signalRoundTripCtx 是 `signalRoundTrip` 的 **可取消**版本（⭐ 第 2 步-B）。
//
// 语义：`ctx` 在等应答期间被取消 ⇒ 立即返回 `ctx.Err()`；`nil` 等价于「不可取消」
// （与 `signalRoundTrip` 逐字同行为 ⇒ 既有调用方**零影响**）。
func (c *Hysteria2Client) signalRoundTripCtx(ctx context.Context, msg signalMessage) (*signalMessage, error) {
	c.signalReqMu.Lock()
	defer c.signalReqMu.Unlock()

	if err := c.ensureSignalStream(); err != nil {
		return nil, err
	}
	return c.signalExchange(ctx, msg)
}

// signalExchange 写一条请求并等应答；调用方必须持有 signalReqMu（见上）
func (c *Hysteria2Client) signalExchange(ctx context.Context, msg signalMessage) (*signalMessage, error) {
	ch := make(chan signalMessage, 1)
	c.signalMu.Lock()
	stream, gen := c.signalStream, c.signalGen
	if stream == nil || gen == nil {
		c.signalMu.Unlock()
		return nil, fmt.Errorf("信令流未建立")
	}
	// ⭐ 先装好等待槽再写：应答只可能在写之后到达
	c.signalPending = ch
	c.signalMu.Unlock()

	defer func() {
		c.signalMu.Lock()
		if c.signalPending == ch {
			c.signalPending = nil
		}
		c.signalMu.Unlock()
	}()

	if err := c.writeSignalMessage(stream, msg); err != nil {
		c.resetSignalStream("写入失败")
		return nil, fmt.Errorf("发送信令失败: %w", err)
	}

	timer := time.NewTimer(signalExchangeWait)
	defer timer.Stop()

	select {
	case resp := <-ch:
		if resp.Type == signalMsgTypeError {
			return nil, fmt.Errorf("服务端拒绝: %s", resp.Error)
		}
		return &resp, nil
	case <-timer.C:
		// ⭐ 超时后必须把这条流扔掉：协议没有请求 ID，晚到的应答
		//    无法与下一次请求区分，留着就会把旧应答当成新应答。
		c.resetSignalStream("等待应答超时")
		return nil, fmt.Errorf("等待信令应答超时（%v）", signalExchangeWait)
	case <-gen:
		return nil, fmt.Errorf("信令流已关闭")
	case <-c.ctrlCtx.Done():
		return nil, fmt.Errorf("连接已关闭")
	case <-ctxDone(ctx):
		// ⭐ 第 2 步-B：调用方取消 ⇒ 立即返回（不再白等到 signalTimeout）。
		//    ⚠️ 不 resetSignalStream：取消是调用方的正常收尾（如 punchManager.close()），
		//    流本身没坏；读协程仍在，晚到的应答由 signalPending 的 defer 安全丢弃。
		return nil, ctx.Err()
	}
}

// ctxDone 取 ctx 的取消信号；`nil` 返回 nil（在 select 里等价于「永不触发」）
func ctxDone(ctx context.Context) <-chan struct{} {
	if ctx == nil {
		return nil
	}
	return ctx.Done()
}

// writeSignalMessage 写出一条消息并加上**写**截止时间。
//
// ⚠️ 只能用 SetWriteDeadline，绝不能用 SetDeadline：后者会连读方向
// 一起加截止时间，把常驻读协程从 readFrame 里踹出来，整条流被误判断开、
// 之后再也收不到任何主动下行（这正是「拉取式」的坑）。
func (c *Hysteria2Client) writeSignalMessage(stream *quic.Stream, msg signalMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	c.signalWriteMu.Lock()
	defer c.signalWriteMu.Unlock()

	_ = stream.SetWriteDeadline(time.Now().Add(signalTimeout))
	defer func() { _ = stream.SetWriteDeadline(time.Time{}) }()
	return writeFrameToStream(stream, data)
}

// signalSelfInfo 取本机用于上报的地址/NAT 类型
func (c *Hysteria2Client) signalSelfInfo() (addr, natType string, ok bool) {
	res, ready := c.NATResult()
	if !ready {
		return "", "", false
	}
	addr = strings.TrimSpace(res.PublicAddr)
	if addr == "" {
		return "", "", false
	}
	nat := string(res.Type)
	if nat == "" {
		nat = string(NATUnknown)
	}
	return addr, nat, true
}

// registerSignalSelf 把自己登记到服务端（不带 peerVIP），让对端能查到我。
// 由 NAT 探测完成后自动调用；失败只记日志。
//
// ⭐ BUG-A 边界（明确跳过，不会带空地址写 register）：
//   - 探测**没跑完**（natReady=false）→ signalSelfInfo 返回 ok=false → 直接返回；
//   - 探测跑完但**失败**（所有 STUN 都不可达 → classifyNAT 返回 PublicAddr=""）
//     → 同样 ok=false → 直接返回。
//
// 两种情况都**不会**建信令流、**不会**发出任何 register 帧
// （ensureSignalStream 顶部也有同一道闸）。测试：
// TestRegisterSignalSelfSkippedWithoutPublicAddr。
func (c *Hysteria2Client) registerSignalSelf() {
	if !c.P2PEffective() {
		return
	}
	addr, nat, ok := c.signalSelfInfo()
	if !ok {
		log.Printf("ℹ️ [信令] 尚未取得公网地址，暂不登记（P2P 暂不可用）")
		return
	}

	resp, err := c.signalRoundTrip(signalMessage{
		Type:       signalMsgTypeRegister,
		PublicAddr: addr,
		NATType:    nat,
	})
	if err != nil {
		log.Printf("⚠️ [信令] 登记失败: %v", err)
		return
	}
	if resp.Type == signalMsgTypeRegistered {
		log.Printf("📡 [信令] 已登记 %s (%s)", addr, nat)
	}
}

// SignalQuery 查询指定对端 VIP 的信令信息。
//
// 同时会把本机当前的地址/NAT 类型再登记一次（协议就是这样设计的：
// 一条 register 消息既上报自己、又查询对端）。
//
// 阶段 1a 只做「交换地址」；打洞在 1b 里用返回的 Metadata 进行。
func (c *Hysteria2Client) SignalQuery(peerVIP string) (SignalPeer, error) {
	if !c.P2PEffective() {
		return SignalPeer{}, fmt.Errorf("P2P 未启用（服务端开关=%v）", c.P2PServerEnabled())
	}
	peerVIP = strings.TrimSpace(peerVIP)
	if peerVIP == "" {
		return SignalPeer{}, fmt.Errorf("对端 VIP 不能为空")
	}
	addr, nat, ok := c.signalSelfInfo()
	if !ok {
		return SignalPeer{}, fmt.Errorf("NAT 探测尚未完成或未取得公网地址，无法上报自己")
	}

	resp, err := c.signalRoundTrip(signalMessage{
		Type:       signalMsgTypeRegister,
		PeerVIP:    peerVIP,
		PublicAddr: addr,
		NATType:    nat,
	})
	if err != nil {
		return SignalPeer{}, err
	}

	return SignalPeer{
		VIP:         peerVIP,
		Online:      resp.PeerOnline,
		PublicAddr:  resp.PeerPublicAddr,
		NATType:     resp.PeerNATType,
		Metadata:    resp.PeerMetadata,
		SignalReady: resp.PeerSignalReady,
		// ⭐ 1b-2B：中继 RTT 估计（0 = 服务端不知道 → 客户端不做 standby 判断）
		RelayRTTMs: resp.RelayRttMs,
	}, nil
}

// SignalStreamReady 本机此刻是否已经建好信令流（本地视角，诊断/UI 用）。
//
// ⚠️ 与 SignalPeer.SignalReady 不是一回事：那个说的是「**对端**的信令流
// 就绪、服务端推得过去」，这个是「**我**的信令流建好了」。
func (c *Hysteria2Client) SignalStreamReady() bool {
	c.signalMu.Lock()
	defer c.signalMu.Unlock()
	return c.signalStream != nil
}
