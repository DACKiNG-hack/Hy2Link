package admin

// vpn-server/admin/signal.go
//
// P2SP 信令登记表（阶段 1 起改由**隧道内**的 ctrl stream 调用）。
//
// 阶段 0 曾把信令做成面板 HTTP 接口（/api/signal/exchange），阶段 1 已迁移到
// 隧道内：客户端在 h3-ctrl 连接上多开一条 stream，由 vpn-server/quic 的
// 控制面 handler 直接调用本文件里的登记表。
//
// 为什么迁移（三条理由都成立）：
//  1. 面板默认只监听 127.0.0.1，远端客户端根本连不到；
//  2. 为了让客户端能访问而把面板暴露出去，违背 S13 的原则；
//  3. 隧道内信令能**天然获得身份** —— ctrl 连接已经过 S1 授权，
//     服务端手里就有这条连接所属的 VIP（cs.vip），
//     不需要客户端自报 myVIP，也不会有面板那套「谁都能调」的鉴权问题。
//
// 本文件只负责「存」与「取」+ TTL 清理，**不关心**传输方式与协议格式
// （那些在 vpn-server/quic/signal.go 里）。

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// SignalEntryTTL 超过这个时间没有更新的登记视为离线
	SignalEntryTTL = 5 * time.Minute
	// signalCleanupInterval 后台清理间隔
	signalCleanupInterval = 1 * time.Minute

	// MetadataLen 打洞 metadata 长度（字节）。
	// 约定：发起方生成 32 字节随机值，经信令通道交给服务端，
	// 响应方从登记表里取到同一份 metadata 再打洞。
	// metadata 的时效性由登记条目的 TTL（SignalEntryTTL = 5 分钟）保证。
	MetadataLen = 32
)

// validNATTypes 允许上报的 NAT 类型白名单。
// 与客户端 vpn-tool/backend/quic/nat.go 里的常量保持一致。
var validNATTypes = map[string]bool{
	"full-cone":       true,
	"restricted-cone": true,
	"port-restricted": true,
	"symmetric":       true,
	"unknown":         true,
}

// ValidNATType 白名单校验（供隧道内信令 handler 与测试复用）
func ValidNATType(s string) bool {
	return validNATTypes[s]
}

// PeerInfo 一个客户端的信令登记信息
type PeerInfo struct {
	VIP        string `json:"vip"`
	PublicAddr string `json:"publicAddr"`
	NATType    string `json:"natType"`
	// Metadata 打洞用的一次性共享值（发起方生成，见 MetadataLen）。
	// 为空表示该客户端本次还没有发起过打洞。
	Metadata string    `json:"metadata,omitempty"`
	LastSeen time.Time `json:"lastSeen"`
}

// SignalSink 是服务端向某个 VIP **主动下行**信令的出口（P2SP 阶段 1b 用）。
//
// 为什么需要它：打洞要求双方**同时发包**，所以「A 想连 B」必须由服务端
// 主动推给 B。纯请求—响应模型里 B 不发问就永远收不到 —— 这也是
// 信令不能只是「拉取式」的原因。
//
// 接口定义在 admin 包、实现放在 vpn-server/quic（依赖方向：quic → admin），
// 这样登记表不必依赖 quic-go，测试里也能塞一个假实现。
//
// ⚠️ 实现必须是**可比较**的类型（指针），DetachSink 靠比较接口值来判断
// 「现在挂着的是不是我自己」，避免把重连后的新流误注销。
type SignalSink interface {
	// SendSignal 下行一条消息。payload 是已序列化的消息体，
	// 分帧方式由实现方决定（隧道内信令是 4 字节大端长度 + 载荷）。
	SendSignal(payload []byte) error
	// CloseSignal 关闭这条信令通道（服务端关闭 P2P、或流被新连接替换时调用）。
	CloseSignal() error
}

// sameSink 判断两个 sink 是否为同一个实现实例。
//
// ⚠️ 直接写 a == b 在「动态类型不可比较」时会 panic，
// 而这条路径由网络输入驱动（重连替换），不能用 panic 换正确性。
func sameSink(a, b SignalSink) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ta, tb := reflect.TypeOf(a), reflect.TypeOf(b)
	if ta != tb || !ta.Comparable() {
		return false
	}
	return a == b
}

// SignalRegistry 信令登记表，key 是 VIP。
//
// ⭐ VIP 必须由**服务端**给出（隧道内信令里就是 cs.vip），
// 绝不能采信客户端自报的 VIP —— 这是「同隧道内 A 不能冒充 B」的基础。
type SignalRegistry struct {
	mu    sync.RWMutex
	peers map[string]*PeerInfo
	// sinks 是 VIP → 该客户端当前那条信令流的下行出口（与 peers 分开存：
	// peers 是「可序列化给外部看的信息」，sinks 是活的连接引用，不能混）。
	//
	// 生命周期与 peers 不同：sink 跟着**流**走，不跟 TTL 走 ——
	// 客户端只要流还活着就随时能收推送，即使它 5 分钟没上报过（条目已过期）。
	sinks map[string]SignalSink
	ttl   time.Duration
}

func NewSignalRegistry(ttl time.Duration) *SignalRegistry {
	if ttl <= 0 {
		ttl = SignalEntryTTL
	}
	r := &SignalRegistry{
		peers: make(map[string]*PeerInfo),
		sinks: make(map[string]SignalSink),
		ttl:   ttl,
	}
	go r.cleanupLoop()
	return r
}

// Update 登记/刷新某个 VIP 的信息。
//
// vip 由调用方（服务端）给出；publicAddr / natType / metadata 来自客户端，
// 因此这里做全部校验：任何一项不合法都返回错误且**不写入**。
func (r *SignalRegistry) Update(vip, publicAddr, natType, metadata string) error {
	if vip == "" {
		return fmt.Errorf("vip 不能为空")
	}
	if err := ValidatePublicAddr(publicAddr); err != nil {
		return err
	}
	if !ValidNATType(natType) {
		return fmt.Errorf("无效的 natType: %q", natType)
	}
	meta, err := NormalizeMetadata(metadata)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// 已存在的条目：metadata 传空表示「不修改」，避免只上报地址时把
	// 之前发起的打洞 metadata 抹掉。
	if old, ok := r.peers[vip]; ok && meta == "" {
		meta = old.Metadata
	}
	r.peers[vip] = &PeerInfo{
		VIP:        vip,
		PublicAddr: publicAddr,
		NATType:    natType,
		Metadata:   meta,
		LastSeen:   time.Now(),
	}
	return nil
}

// Get 查询某个 VIP 的信息（返回副本，不暴露内部指针）
func (r *SignalRegistry) Get(vip string) (PeerInfo, bool) {
	r.mu.RLock()
	p, ok := r.peers[vip]
	r.mu.RUnlock()
	if !ok {
		return PeerInfo{}, false
	}
	if time.Since(p.LastSeen) > r.ttl {
		r.mu.Lock()
		// 复查一次，避免并发下误删刚刷新的记录
		if cur, still := r.peers[vip]; still && time.Since(cur.LastSeen) > r.ttl {
			delete(r.peers, vip)
		}
		r.mu.Unlock()
		return PeerInfo{}, false
	}
	return *p, true
}

// Count 当前登记数（监控/日志用）
func (r *SignalRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.peers)
}

// VIPs ⭐ D1-a：返回当前**有登记**的全部 VIP 快照（顺序不保证 —— 需要确定性时调用方自行排序）。
//
// 这是注册表**唯一**的可枚举入口（新增方法而不是把 `peers` 暴露出去：
// 调用方拿不到内部 map，也就不会在持有登记表锁时做 I/O）。
//
// ⚠️ 语义边界：「有登记」≠「在线」。登记有 5 分钟 TTL，已离线的客户端可能仍在表里，
// 所以调用方**必须**再用数据面在线判定过滤 —— quic 层的 `enumerableVIPs`
// 已把「lookupVIP 在线 且 Get 有登记」这条判据封在里面（与 peerOnline 逐字一致）。
func (r *SignalRegistry) VIPs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.peers))
	for vip := range r.peers {
		out = append(out, vip)
	}
	return out
}

// ---------- 下行通道（VIP → 信令流）----------

// AttachSink 把某个 VIP 的信令流出口挂上登记表。
//
// 同一 VIP 重复挂载 = 客户端重连（旧的流可能还没完全消失），
// 以**最新**的为准：旧 sink 会被替换掉，但这里**不主动关闭**旧的
// ——关闭由调用方（quic 层的 defer / CloseAllSinks）负责，
// 避免在持有登记表锁时做 I/O。
func (r *SignalRegistry) AttachSink(vip string, sink SignalSink) {
	if vip == "" || sink == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sinks[vip] = sink
}

// DetachSink 注销某个 VIP 的信令流出口（流结束时调用）。
//
// ⭐ 只有当「当前挂着的仍然是同一个 sink」时才注销：
// 客户端重连会先挂上新的 sink，旧流的 defer 随后才跑，
// 无条件删除会误伤新流。
//
// 返回是否真的注销了。
func (r *SignalRegistry) DetachSink(vip string, sink SignalSink) bool {
	if vip == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cur, ok := r.sinks[vip]
	if !ok || !sameSink(cur, sink) {
		return false
	}
	delete(r.sinks, vip)
	return true
}

// SendTo 向某个 VIP 主动下行一条消息（payload 是已序列化的消息体）。
//
// ⭐ 调用 sink 时不持有登记表的锁：写 QUIC 流可能被流控阻塞，
// 在这里持锁会把整张表（所有客户端的下行）一起卡住。
func (r *SignalRegistry) SendTo(vip string, payload []byte) error {
	r.mu.RLock()
	sink, ok := r.sinks[vip]
	r.mu.RUnlock()
	if !ok || sink == nil {
		return fmt.Errorf("VIP %s 没有可用的信令通道（未连接或未开 P2P）", vip)
	}
	return sink.SendSignal(payload)
}

// SinkCount 当前挂着下行通道的 VIP 数（监控/测试用）
func (r *SignalRegistry) SinkCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sinks)
}

// HasSink 某个 VIP 是否挂着下行通道（测试/诊断用）
func (r *SignalRegistry) HasSink(vip string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.sinks[vip]
	return ok
}

// CloseAllSinks 关闭并清空所有下行通道，返回被关闭的数量。
//
// 用途：运行时关闭 P2P 开关（见 DataChannelServer.EnableP2PSignal）。
// 同样先在锁内取快照、再在锁外关闭。
func (r *SignalRegistry) CloseAllSinks(reason string) int {
	r.mu.Lock()
	snapshot := make([]SignalSink, 0, len(r.sinks))
	for _, s := range r.sinks {
		snapshot = append(snapshot, s)
	}
	r.sinks = make(map[string]SignalSink)
	r.mu.Unlock()

	for _, s := range snapshot {
		if s != nil {
			_ = s.CloseSignal()
		}
	}
	if len(snapshot) > 0 {
		log.Printf("🔌 [信令] 已关闭 %d 条下行通道（%s）", len(snapshot), reason)
	}
	return len(snapshot)
}

func (r *SignalRegistry) cleanupLoop() {
	ticker := time.NewTicker(signalCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		removed := 0
		r.mu.Lock()
		for vip, p := range r.peers {
			if now.Sub(p.LastSeen) > r.ttl {
				delete(r.peers, vip)
				removed++
			}
		}
		// ⚠️ 故意**不清理 sinks**：下行通道跟着 QUIC 流走，
		// 只要流还活着就还能收推送，与「多久没上报」无关。
		// 流的结束由 quic 层的 DetachSink / CloseAllSinks 负责。
		r.mu.Unlock()
		if removed > 0 {
			log.Printf("🧹 [信令] 清理 %d 条过期登记，剩余 %d 条", removed, r.Count())
		}
	}
}

// ---------- 校验工具 ----------

// ValidatePublicAddr 校验 "ip:port" 形式的外部地址
func ValidatePublicAddr(addr string) error {
	if addr == "" {
		return fmt.Errorf("publicAddr 不能为空")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("publicAddr 必须形如 ip:port（%v）", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("publicAddr 的 IP 部分无效: %q", host)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("publicAddr 不能是未指定地址: %q", host)
	}
	// 只接受纯数字端口（不要用 net.LookupPort，它会去做服务名解析甚至联网）
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("publicAddr 的端口无效: %q", port)
	}
	return nil
}

// NormalizeMetadata 规范化/校验打洞 metadata（十六进制字符串）。
// 空字符串是合法的（表示本次没有发起打洞），原样返回 ""。
func NormalizeMetadata(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return "", nil
	}
	if len(s) != MetadataLen*2 {
		return "", fmt.Errorf("metadata 必须是 %d 字节（%d 个十六进制字符），实际 %d 个",
			MetadataLen, MetadataLen*2, len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("metadata 不是合法的十六进制: %v", err)
	}
	return s, nil
}

// ---------- P2SP 阶段 1b：打洞字段的校验与夹取 ----------

const (
	// PunchWindowDefaultMs 打洞窗口默认值（与 realm 的默认 10s 一致）
	PunchWindowDefaultMs = 10000
	// PunchWindowMinMs / PunchWindowMaxMs 服务端夹取范围（防御：防恶意客户端让对端长时间打洞）
	PunchWindowMinMs = 3000
	PunchWindowMaxMs = 15000
)

// ClampPunchWindowMs 把客户端给的窗口夹到合法范围；0/负数取默认值。
//
// ⭐ 窗口由**发起方**决定，服务端只做夹取（§0.4 决策）——夹取权纯粹是防御。
func ClampPunchWindowMs(v int) int {
	if v <= 0 {
		return PunchWindowDefaultMs
	}
	if v < PunchWindowMinMs {
		return PunchWindowMinMs
	}
	if v > PunchWindowMaxMs {
		return PunchWindowMaxMs
	}
	return v
}

// ValidatePunchAttemptID 校验 attemptId：16 个十六进制字符（8 字节随机）
func ValidatePunchAttemptID(s string) error {
	s = strings.TrimSpace(s)
	if len(s) != 16 {
		return fmt.Errorf("attemptId 必须是 16 个十六进制字符，实际 %d 个", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("attemptId 不是合法的十六进制: %v", err)
	}
	return nil
}

// ValidatePunchAddr 校验打洞地址（punch socket 的公网地址）。
//
// allowEmpty=true 时允许空串（punch-ready / punch-peer 里「我无法广告地址」的显式表达）。
//
// ⭐ 比 ValidatePublicAddr 更严：**额外拒绝私网 / 环回 / 链路本地 / 组播**。
// 理由（安全）：punchAddr 会成为**对端发包的目标地址** ——
// 如果允许客户端广告 10.x / 127.0.0.1，恶意客户端就能让对端把 UDP 打洞包
// 发到内网任意地址（变相的 SSRF / 内网端口探测 / 反射）。
func ValidatePunchAddr(s string, allowEmpty bool) error {
	s = strings.TrimSpace(s)
	if s == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("punchAddr 不能为空")
	}
	if err := ValidatePublicAddr(s); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("punchAddr 的 IP 部分无效: %q", host)
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return fmt.Errorf("punchAddr 不能是私网/环回/链路本地/组播地址: %q", host)
	}
	return nil
}

// ValidateDirectFingerprint 校验直连自签证书指纹（SHA-256 的 64 位十六进制）
func ValidateDirectFingerprint(s string) error {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) != 64 {
		return fmt.Errorf("directFingerprint 必须是 64 个十六进制字符（SHA-256），实际 %d 个", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("directFingerprint 不是合法的十六进制: %v", err)
	}
	return nil
}

// MaxPunchAddrs 每个 punch socket 的候选地址数上限（⭐1b-3）。
//
// 为什么必须有上限（安全）：punchAddrs 是**对端会逐个发包的目标列表**。
// 恶意客户端可以借此让对端朝指定 IP 的多个端口喷 UDP 包（反射/放大）。
// 单地址时代这个放大是 ×1；不设上限就会变成 ×N。
//
// 取 32 与 realm 的 `symmetricNATMaxPortsPerHost`（每个 IP 最多补 32 个端口）对齐 ——
// 预测窗口本身也只有这么大，再多的候选只是浪费对端的发包预算。
const MaxPunchAddrs = 32

// ValidatePunchAddrs 校验候选打洞地址列表（⭐1b-3，punchAddrs 字段）。
//
// 规则：
//   - 数量 ≤ MaxPunchAddrs；
//   - 每个元素都要过 ValidatePunchAddr（非空、公网、非私网/环回/链路本地/组播）；
//   - 不重复；
//   - **同一个 IP**：候选是「同一个 socket 的一组映射」，混入别的 IP 没有意义，
//     而且是放大攻击的常见形态（一堆 IP）⇒ 直接拒绝；
//   - anchorIP 非空时，候选 IP 必须与它一致（「以观测值为锚」）：
//     A1 阶段 anchor = punchAddr/publicAddr 的 IP（客户端自报，只能保证一致性）；
//     A2 阶段 anchor 换成**服务端观测到的** IP（可信锚）。
//
// 空列表是合法的（旧客户端/未观测到 ⇒ 服务端只转发 punchAddr）。
func ValidatePunchAddrs(addrs []string, anchorIP string) error {
	if len(addrs) == 0 {
		return nil
	}
	if len(addrs) > MaxPunchAddrs {
		return fmt.Errorf("punchAddrs 最多 %d 个，实际 %d 个", MaxPunchAddrs, len(addrs))
	}
	anchorIP = strings.TrimSpace(anchorIP)
	seen := make(map[string]struct{}, len(addrs))
	var groupIP string
	for i, raw := range addrs {
		addr := strings.TrimSpace(raw)
		if err := ValidatePunchAddr(addr, false); err != nil {
			return fmt.Errorf("punchAddrs[%d]: %w", i, err)
		}
		if _, dup := seen[addr]; dup {
			return fmt.Errorf("punchAddrs[%d] 重复: %q", i, addr)
		}
		seen[addr] = struct{}{}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return fmt.Errorf("punchAddrs[%d]: %w", i, err)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("punchAddrs[%d] 的 IP 无效: %q", i, host)
		}
		// Unmap：::ffff:1.2.3.4 与 1.2.3.4 要算同一个 IP
		norm := ip.String()
		if v4 := ip.To4(); v4 != nil {
			norm = v4.String()
		}
		if groupIP == "" {
			groupIP = norm
		} else if norm != groupIP {
			return fmt.Errorf("punchAddrs 必须属于同一个 IP：%q 与 %q 不一致", groupIP, norm)
		}
	}
	if anchorIP != "" {
		want := anchorIP
		if ip := net.ParseIP(anchorIP); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				want = v4.String()
			} else {
				want = ip.String()
			}
		}
		if groupIP != want {
			return fmt.Errorf("punchAddrs 的 IP(%q) 与 punchAddr 的 IP(%q) 不一致", groupIP, want)
		}
	}
	return nil
}
