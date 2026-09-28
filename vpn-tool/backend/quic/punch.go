package quic

// vpn-tool/backend/quic/punch.go
//
// P2SP 阶段 1b-1：客户端侧的**打洞会话**。
//
// 设计见 P2SP-阶段1b-设计文档.md。本文件实现：
//   - A（发起方）状态机：Querying → Discovering → Intent → Punching → Handshaking → Probing → Direct
//   - B（响应方）状态机：Validating → PreparingSTUN → Punching → Handshaking → Probing → Direct
//   - 预算门（40s 硬上限 + deadline-aware 阶段超时 + 重试最小余额）
//   - 地址过滤（peerFilterConn，含 IPv4-in-IPv6 归一化）
//   - 直连认证（Q1：B 固定 A 的自签证书指纹）
//   - 应用层 echo 探针（RTT 测量，1b-2 复用为路径健康检查）
//
// ⚠️ 并发形态（1b 的 -race 验收核心）：
//   - **状态迁移只在一个 goroutine 里串行发生**（runInitiator / runResponder）；
//   - push 到达、超时、UI 查询都只通过 channel / 锁投递事件；
//   - push 钩子（OnPush）只做「投递到 channel」，绝不阻塞信令读协程。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/extras/v2/realm"
	"github.com/apernet/quic-go"
)

// ---------- 状态与原因码（UI 契约，见设计 §10） ----------

const (
	P2PStateQuerying    = "querying"
	P2PStateDiscovering = "discovering"
	P2PStateIntent      = "intent"
	P2PStatePunching    = "punching"
	P2PStateHandshaking = "handshaking"
	P2PStateProbing     = "probing"
	P2PStateDirect      = "direct"
	P2PStateFailed      = "failed"
	// ⭐ 1b-2B：standby 是**设计内的正常状态**（直连质量不佳 → 暂时走中继、连接保留），
	// 不是失败。之前复用 P2PStateFailed 会让 UI 弹「直连失败」错误提示 + 错误日志，
	// 与「系统正在按设计工作」的事实相反，所以单列一个状态。
	P2PStateStandby = "standby"
	// ⭐ 1b-4 第一步：试用期（先验后切）——打洞+握手已成功，但**数据仍走中继**，
	// 等试用期判定质量达标才装路由表切直连。它是**正常状态**（不是失败）：
	// 前端按 info 级呈现、不弹提示。
	P2PStateTrial = "trial"
)

// 原因码（稳定英文标识；中文文案见 p2pReasonText）
const (
	P2PReasonOKDirect              = "ok-direct"
	P2PReasonNATSymmetric          = "nat-symmetric"
	P2PReasonNATUnknown            = "nat-unknown"
	P2PReasonPeerUnreachable       = "peer-unreachable"
	P2PReasonPeerNotReady          = "peer-not-ready"
	P2PReasonLocalNoPunchAddr      = "local-no-punch-addr"
	P2PReasonPeerNoPunchAddr       = "peer-no-punch-addr"
	P2PReasonPunchTimeout          = "punch-timeout"
	P2PReasonDirectHandshakeFailed = "direct-handshake-failed"
	P2PReasonFingerprintMismatch   = "fingerprint-mismatch"
	P2PReasonProbeTimeout          = "probe-timeout"
	P2PReasonRateLimited           = "rate-limited"
	P2PReasonPeerBusy              = "peer-busy"
	P2PReasonAttemptTimeout        = "attempt-timeout"
	P2PReasonSessionExpired        = "session-expired"
	P2PReasonServerP2PDisabled     = "server-p2p-disabled"
	P2PReasonCancelled             = "cancelled"
	P2PReasonDirectLost            = "direct-lost" // 1b-2
	// ⭐ 2026-09-27（真机 Bug 3）：**对端主动关闭**（应用层 CONNECTION_CLOSE）。
	//
	//	与本机链路质量无关（多半是对端自己的判据判负 / 仲裁 / 收尾）
	//	⇒ 不排退避、不推进任何 streak（见 `classifyPathFail` 的 `failPeerClosed`），
	//	且 UI 不显示「重试」（`p2pRetryable=false`：要不要再连由对端决定）。
	P2PReasonPeerClosed = "peer-closed"
	// P2PReasonQualityDegraded 直连质量不佳 → 进 standby（⭐1b-2B）。
	// 与 P2PReasonDirectLost 的区别：那条是**直连真的断了**（已回退且不再保留路径），
	// 这条是**直连还活着但更慢**（保留连接与探针，稍后自动复查）。
	P2PReasonQualityDegraded = "quality-degraded"
	// ⭐ 1b-4 第一步：试用期质量不达标 ⇒ 关路径（「打洞成功但质量差」这一类）。
	// 与 probe-timeout / direct-lost 同属「质量差」退避档（5m/15m/30m/1h）。
	P2PReasonQualityPoor = "quality-poor"
	// ⭐ 1b-4 第一步：进入试用期（`p2p:status` 的 `trial` 事件带的原因码）。
	//
	// 它不是失败：通道已打通、数据仍走中继，等质量判定。前端按 info 级呈现、不弹提示。
	// 单列一个原因码（而不是复用 ok-direct）是为了让「正在试用」与「已经切过去」
	// 在事件流里可区分（排障/统计时不用去比对 state 字段）。
	P2PReasonTrialProbing = "trial-probing"
)

// p2pReasonText 中文文案（后端直接给，前端兜底用）
var p2pReasonText = map[string]string{
	P2PReasonOKDirect:              "已建立直连",
	P2PReasonNATSymmetric:          "双方都是对称 NAT（NAT4+NAT4），无法直连（如实回落中继）",
	P2PReasonNATUnknown:            "未能识别 NAT 类型，暂不尝试直连",
	P2PReasonPeerUnreachable:       "对端不在线",
	P2PReasonPeerNotReady:          "对端尚未就绪（信令通道未建立）",
	P2PReasonLocalNoPunchAddr:      "本机无法获取打洞地址（STUN 不可达）",
	P2PReasonPeerNoPunchAddr:       "对端无法提供打洞地址",
	P2PReasonPunchTimeout:          "打洞超时（网络未放行）",
	P2PReasonDirectHandshakeFailed: "直连握手失败",
	P2PReasonFingerprintMismatch:   "对端身份校验未通过，已放弃直连（详见日志）",
	P2PReasonProbeTimeout:          "直连通了但探针无回应",
	P2PReasonRateLimited:           "直连尝试过于频繁，已限流",
	P2PReasonPeerBusy:              "对端正忙（并发打洞已满）",
	P2PReasonAttemptTimeout:        "直连尝试超时（预算耗尽）",
	P2PReasonSessionExpired:        "会话信息已过期，需重新发起",
	P2PReasonServerP2PDisabled:     "服务端未启用 P2P 直连",
	P2PReasonCancelled:             "已取消",
	P2PReasonPeerClosed:            "对端已关闭这条直连（非本机链路问题，稍后会自动重试）",
	P2PReasonDirectLost:            "直连已断开，已回退到中继",
	P2PReasonQualityDegraded:       "直连质量不佳，已暂时切回中继（连接保留，稍后自动复查）",
	P2PReasonQualityPoor:           "直连质量不达标，已放弃本次直连（稍后重试）",
	P2PReasonTrialProbing:          "通道已建立，正在试用期验证质量（数据仍走中继）",
}

// cooldownForReason 失败后的冷却时长（⭐1b-2B：按原因分级；⭐1b-4 第 3 步：忙走小台阶）
//
// ⚠️ 本函数现在只表示「**没有 streak 上下文时**的基准值」：
// 真正的冷却由会话收尾时用 `ladderForBusy(busyStreak[vip])`（或 rate 的对应 streak）算出。
// 保留它是因为既有调用点/测试需要「该类原因的**起步**冷却」，且它是台阶第 0 档的权威值。
func cooldownForReason(reason string) time.Duration {
	switch reason {
	case P2PReasonRateLimited, P2PReasonPeerBusy:
		// 「忙」不是失败：服务端限流/对端已满都是暂时状态，从最短档起步
		return punchBusyCooldown
	default:
		return punchCooldown
	}
}

// ---------- ⭐ 1b-4 第 3 步：busy / rate-limited 的**独立小台阶** ----------
//
// 设计（范围文档 §3.2 + 实施计划 §7）：
//
//	30s → 60s → 120s → 300s（**第四档起恒 5min 封顶**）
//
// 关键约束：
//   - **「忙」不是失败**：本台阶**绝不**推进 `pathManager` 的 step / qualityStep
//     （那两条是「打洞失败」「质量差」的 streak）——本文件里的两条 map 是**独立的第三条/第四条** streak；
//   - `peer-busy`（对端忙）与 `rate-limited`（服务端限流）**各记各的**：
//     两者成因不同（一个是对方没余力，一个是本机额度用尽），混在一条 streak 里会让
//     「交替发生」时台阶涨得比任何单一成因都快，诊断时也分不清是谁在忙；
//   - streak 的寿命与 `cooldown` 对齐：冷却都过了 ⇒ 那次忙已经无关 ⇒ 惰性清掉（见 pruneBusyLocked）。
const (
	// punchBusyCooldown 台阶第 0 档（= 1b-2B 时代的固定值；短冷却语义不变）
	punchBusyCooldown = 30 * time.Second // ⭐1b-2B：对端「忙」后的短冷却（不是失败）
	// punchBusyCooldownMax 台阶**最后一档**（= 5min 封顶值）。
	// ⚠️ 它必须与 `punchBusyLadder` 的最后一个元素**相等**（有测试钉住），
	//    以免「封顶值」与「台阶末档」两处各写一个数字而漂移。
	punchBusyCooldownMax = 5 * time.Minute
	// punchBusyStreakMaxEntries 两个 streak map 各自的条数上限（兜底，防长期运行无限累积）。
	//
	// ⚠️ 超出时**拒绝新增**而**不淘汰已有**：淘汰会让某个对端的 streak 静默归零
	//    （下次从 30s 重新涨），比「少记一个新对端」更难排查。1024 远超现实规模，
	//    正常永远碰不到（冷却过期的条目会被 pruneBusyLocked 清掉）。
	punchBusyStreakMaxEntries = 1024
)

// punchBusyLadder busy/rate-limited 小台阶（**完整列出所有档，含封顶档**）。
//
// ⚠️ review 追问 5：封顶值**显式写进台阶**（而不是让 `ladderForBusy` 在越界时返回另一个常量）
// —— 这样将来要加中间档（例如 30s→60s→120s→**180s**→5min），只改这一行即可，
// 不会出现「台阶改了、封顶常量忘了跟」的两处漂移。
var punchBusyLadder = []time.Duration{
	30 * time.Second, 60 * time.Second, 120 * time.Second, 5 * time.Minute,
}

// ladderForBusy 按 streak 取 busy/rate 冷却时长（**纯函数**）。
//
// 参数语义（⚠️ 极其容易写反，本步踩过 off-by-one）：
//
//	`streak` = 这是第 (streak+1) 次连续「忙」**之前**的计数
//	⇒ 第 1 次忙传 0、第 2 次传 1 ……；调用方必须**先取档、再自增**。
//
// 越界（第 len(ladder)+1 次及以后）⇒ 恒取台阶末档（= punchBusyCooldownMax）。
func ladderForBusy(streak int) time.Duration {
	if streak < 0 {
		streak = 0
	}
	if streak >= len(punchBusyLadder) {
		streak = len(punchBusyLadder) - 1
	}
	return punchBusyLadder[streak]
}

// isBusyReason 该原因是否属于「忙」类（走小台阶 + 独立 streak）
func isBusyReason(reason string) bool {
	return reason == P2PReasonPeerBusy || reason == P2PReasonRateLimited
}

// bumpBusyStreakLocked 推进对应 streak 并按台阶算出本次冷却（**调用方必须已持 m.mu**）
//
// 语义（实施计划 §7.2 的定论 + review 追问 2 的明确）：
//   - 本次是 busy/rate ⇒ **按「当前触发原因」用对应的那条 streak**：
//     `peer-busy` 只读/推进 `busyPeerStreak`，`rate-limited` 只读/推进 `rateStreak`。
//     ⚠️ 两条 streak **各自独立计数**（绝不混算）：交替 busy→rate→busy 的冷却是
//     **30s → 30s → 60s**（不是 30s → 60s → 120s）——混算会让「两种成因交替」涨档比
//     任何单一成因都快，而两种成因的对策完全不同（一个等对端、一个等本机额度）；
//   - 本次是**其它失败**（punch-timeout / nat-symmetric / 握手失败 …）⇒ **两条 streak 都清零**
//     （streak 的语义是「**连续**同类失败」：插进一次别的失败就说明「这次不是忙」）；
//   - 成功的情况不在这里（由调用方直接清零，见 noteSessionOutcomeLocked）。
func (m *punchManager) bumpBusyStreakLocked(peerVIP, reason string) time.Duration {
	if m.busyPeerStreak == nil || m.rateStreak == nil {
		return cooldownForReason(reason)
	}
	// 惰性清理：冷却已过期的条目顺手删掉（零新 goroutine，与第 2 步-A 同纪律）
	m.pruneBusyLocked(time.Now())
	if !isBusyReason(reason) {
		delete(m.busyPeerStreak, peerVIP)
		delete(m.rateStreak, peerVIP)
		return cooldownForReason(reason)
	}
	if reason == P2PReasonRateLimited {
		if _, ok := m.rateStreak[peerVIP]; !ok && len(m.rateStreak) >= punchBusyStreakMaxEntries {
			return punchBusyCooldown // 兜底：不新增（也不淘汰别人）
		}
		// ⚠️ 先按**已发生**的连击数取档，再自增（顺序不能反！）：
		//    `ladderForBusy(n)` 里的 n = 「这是第 n+1 次连续忙」之前的计数
		//    ⇒ 第 1 次忙必须取第 0 档(30s)。先自增会整体错一档（第 1 次就给 60s）。
		d := ladderForBusy(m.rateStreak[peerVIP])
		m.rateStreak[peerVIP]++
		return d
	}
	if _, ok := m.busyPeerStreak[peerVIP]; !ok && len(m.busyPeerStreak) >= punchBusyStreakMaxEntries {
		return punchBusyCooldown
	}
	d := ladderForBusy(m.busyPeerStreak[peerVIP])
	m.busyPeerStreak[peerVIP]++
	return d
}

// pruneBusyLocked 惰性清理：冷却已过期（或不存在）的对端，其 streak 也一并删掉。
//
// ⚠️ 调用方必须已持 m.mu。零 I/O、零回调、零新 goroutine。
// 语义：「冷却都过了 ⇒ 那次忙已经无关」 ⇒ 下次忙从 30s 重新起算（这是期望行为）。
func (m *punchManager) pruneBusyLocked(now time.Time) {
	for vip := range m.busyPeerStreak {
		if until, ok := m.cooldown[vip]; !ok || !now.Before(until) {
			delete(m.busyPeerStreak, vip)
		}
	}
	for vip := range m.rateStreak {
		if until, ok := m.cooldown[vip]; !ok || !now.Before(until) {
			delete(m.rateStreak, vip)
		}
	}
}

// P2PReasonText 返回原因码的中文文案
func P2PReasonText(code string) string {
	if s, ok := p2pReasonText[code]; ok {
		return s
	}
	return "直连不可用"
}

// p2pRetryable 该原因是否值得重试（UI 用它决定是否显示「重试」）
func p2pRetryable(code string) bool {
	switch code {
	case P2PReasonNATSymmetric, P2PReasonPeerUnreachable, P2PReasonPeerNoPunchAddr,
		P2PReasonFingerprintMismatch, P2PReasonServerP2PDisabled, P2PReasonCancelled,
		// ⭐ 2026-09-27：对端主动关闭 ⇒ 本机「重试」没有意义（要不要再连由对端决定）
		P2PReasonPeerClosed,
		// ⭐ 1b-2B：standby 会自动复查并切回，不需要用户手动重试
		P2PReasonQualityDegraded:
		return false
	default:
		return code != P2PReasonOKDirect
	}
}

// P2PStatus 直连状态（Wails 事件 "p2p:status" 的载荷，见设计 §10.1）
//
// ⚠️ 新增字段必须**同时**更新 field-lock 测试（`TestP2PStatusJSONFieldLock`）：
// 那条测试用反射断言「字段数 == 名单长度」，漏登记会直接红。
type P2PStatus struct {
	PeerVIP     string `json:"peerVip"`
	State       string `json:"state"`
	ReasonCode  string `json:"reasonCode"`
	ReasonText  string `json:"reasonText"`
	Path        string `json:"path"` // relay | direct
	RTTDirectMs int64  `json:"rttDirectMs"`
	RTTQuicMs   int64  `json:"rttQuicMs"`
	At          int64  `json:"at"`
	Retryable   bool   `json:"retryable"`

	// ⭐ 1b-2A 新增（§10）：让 UI 能显示「谁触发、哪条路径、省了多少」
	Trigger     string `json:"trigger,omitempty"`     // traffic | config | manual | remote
	PathState   string `json:"pathState,omitempty"`   // relay | direct（比 path 更细，path 保留兼容）
	BytesUp     uint64 `json:"bytesUp,omitempty"`     // 该路径已承载的上行字节
	BytesDown   uint64 `json:"bytesDown,omitempty"`   // 该路径已承载的下行字节
	DirectSince int64  `json:"directSince,omitempty"` // 直连建立时刻（Unix ms）
}

// 触发来源（P2PStatus.Trigger；稳定标识，前端可做文案）
const (
	P2PTriggerTraffic = "traffic" // 流量驱动（1b-2A 主路径）
	P2PTriggerConfig  = "config"  // 配置驱动（常用对端）
	P2PTriggerManual  = "manual"  // 用户在面板上手动点击
	P2PTriggerRemote  = "remote"  // 对端发起的邀请（我是响应方）

	// ⚠️ A3a（2026-09-28）**已删除 `P2PTriggerPrePunch = "pre-punch"`**：
	// 预打洞**发起侧**整体删除（`prepunch.go` 桩化）⇒ 不再有任何会话能带上该值。
	// 判决依据：唯一写入点是 `initiator` 路径（本机发起）；而 `responder` 路径
	// **无条件**取 `P2PTriggerRemote` ⇒ 入站邀请永远不会带 `pre-punch`。
	// 🔎 原代码：`A2-干净点快照-2026-09-28\quic\punch.go` 的 `P2PTriggerPrePunch` 常量块（同文件内 `grep P2PTriggerPrePunch` 即得，**不足 20 行**）。
	// 📌 保留 `P2PTriggerRemote`（responder 会话的触发来源，灰度期仍需）。
)

// ---------- 常量（与设计 §3.3/§3.4/§0.4 对应） ----------

const (
	punchAttemptBudget = 40 * time.Second // 硬上限
	punchStageFloor    = 2 * time.Second  // 剩余低于它就不再起新阶段
	punchRetryFloor    = 15 * time.Second // 重试要求的最小余额（打洞窗口+握手必须完整）

	punchQueryTimeout  = 5 * time.Second
	punchQueryRetries  = 1 // 上限 2 次尝试
	punchIntentRetries = 1 // 上限 2 次尝试
	punchReadyWait     = 5 * time.Second

	punchStunTimeout      = 3 * time.Second
	punchPerServerTimeout = 3 * time.Second
	punchInterval         = 100 * time.Millisecond

	punchHandshakeTimeout = 5 * time.Second
	punchProbeTimeout     = 3 * time.Second
	punchProbeRounds      = 3
	punchProbeInterval    = 200 * time.Millisecond

	punchReadyRetries = 3 // 首次 + 最多 2 次重发
	punchReadyGap1    = 1 * time.Second
	punchReadyGap2    = 3 * time.Second

	punchCooldown     = 60 * time.Second // 同一对端失败后的冷却
	punchMaxResponder = 2                // B 侧同时接受的邀请上限（设计 §3.5）
	// ⚠️ 必须与服务端常量 `relayMaxResponderInvites`（vpn-server/quic/punch.go）一致：
	//    客户端是「被动忽略多余邀请」，服务端是「提前拒绝并告知发起方忙」，
	//    两者依据同一个数字才不会出现「服务端说忙但其实空闲」。测试见 TestResponderCapMirror.
	punchSamePeerGuard  = 10 * time.Second // 同一发起方的邀请最小间隔
	punchWindowDefault  = 10000
	punchWindowMin      = 3000
	punchWindowMax      = 15000
	punchPushQueueSize  = 32
	punchDirectCertLife = 24 * time.Hour
)

var errFingerprintMismatch = errors.New("直连证书指纹不匹配")

// errPunchCooldown ⭐ 1b-4 第 3 步：**「本地冷却期内的触发」这一类错误的哨兵**。
//
// 用途：`pathManager.attemptFor` 用它区分「打洞没开始」的原因 ——
//
//	errors.Is(err, errPunchCooldown) ⇒ **跳过** `setBackoffTransient`
//
// 原因（范围文档 §3.2 的必要配套，见实施计划 §2.2）：
//
//	punchManager 自己已经算好了冷却（busy/rate 档 30s→60s→120s→5min）。
//	若 pathManager 再无条件写一个**固定 30s** 退避，那么：
//	  - 60s/120s/5min 档**根本不起作用**（30s 后 `handleTrigger` 的退避门就放行了）；
//	  - 且被放行的那次触发会立刻被 punchManager 的冷却拒回、又推进一档 + 再写 30s 退避
//	    ⇒ 退化成「每 30s 空转一次、档位一路虚涨到 5min」，**比不改更差**。
//
// 为什么跳过本地退避也安全（不会造成请求风暴）：
//
//	冷却期内 `punchWithTrigger` 会在**本地**直接返回（零网络请求），
//	`handleTrigger` 的下一次尝试同样被拦 ⇒ 服务端压力不变。
//	对 `rate-limited` 尤其重要：服务端是**滑动窗口 5 次/分钟硬拒**，
//	本地提前重试**不可能**绕过它，只会在第 31 秒白白撞一次拒绝。
var errPunchCooldown = errors.New("对端处于打洞冷却期")

// errPunchDupPath ⭐ B3（2026-09-27）：**已有可用路径**（Up/Trial）时抑制流量驱动打洞的哨兵错误。
//
// ⚠️ 与 `errPunchCooldown` 同理：它**不是失败**，调用方（`pathManager.attemptFor`）必须
//
//	`errors.Is` 识别它并**跳过 `setBackoffTransient`** —— 否则每次流量触发都推一档退避，
//	「越试越难」，比不做抑制**更差**（由 `TestDupPunchSkipDoesNotWriteBackoff` 用对照法钉住）。
var errPunchDupPath = errors.New("已有可用路径")

// punchReadyMagic 是发起方「我已经在监听了」的裸 UDP 通知（见 handshake 里的时序说明）
const punchReadyMagic = "P2SP-RDY1"

// punchDialWait 响应方等这条通知的上限；等不到也会照常拨号（退化成固定延迟）。
//
// ⭐ 这是**优化**（少一次 Initial 重传），不是正确性依赖：等不到就按固定延迟拨号，
// 拨号本身还有一次重试兜底。所以给 500ms 的宽裕窗口而不追求「必然收到」。
//
// 设计值 500ms 见 `P2SP-阶段1b-设计文档.md` §2.6（1b-1 交付说明里写的是 200ms，
// 那是上一阶段的值；本阶段按设计更新为 500ms，行为没变，只是宽裕度变大）。
const punchDialWait = 500 * time.Millisecond

// ---------- 工具 ----------

// newAttemptID 生成 8 字节随机 attemptId（16 hex）
func newAttemptID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("生成 attemptId 失败: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// newPunchSeed 生成 32 字节打洞 seed（hex，放进 metadata 字段）
func newPunchSeed() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("生成打洞 seed 失败: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// punchMetadataFromSeed 由 32 字节 seed 派生 realm 需要的 (nonce 16B, obfs 32B)。
//
// ⭐ 为什么能这么派生（安全性）：线上明文里只有 nonce（= seed 的前 16 字节），
// obfsKey 需要**完整 seed** 才能算出（SHA-256 无 preimage 捷径），
// 所以旁路观察者既解不出也伪造不了打洞包；seed 本身只走已加密且已认证的信令。
func punchMetadataFromSeed(seedHex string) (realm.PunchMetadata, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(seedHex))
	if err != nil {
		return realm.PunchMetadata{}, fmt.Errorf("seed 不是合法 hex: %w", err)
	}
	if len(seed) != 32 {
		return realm.PunchMetadata{}, fmt.Errorf("seed 必须是 32 字节，实际 %d", len(seed))
	}
	nonce := seed[:16]
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte("p2sp-punch-obfs-v1"))
	obfs := h.Sum(nil) // 32 字节
	return realm.PunchMetadata{
		Nonce: hex.EncodeToString(nonce),
		Obfs:  hex.EncodeToString(obfs),
	}, nil
}

// clampPunchWindow 与 admin.ClampPunchWindowMs 保持一致（两 module 无法互相 import）
func clampPunchWindow(v int) int {
	if v <= 0 {
		return punchWindowDefault
	}
	if v < punchWindowMin {
		return punchWindowMin
	}
	if v > punchWindowMax {
		return punchWindowMax
	}
	return v
}

// parsePunchAddr 解析 "ip:port"；空串返回 (零值, true)（允许空，见设计 §2.2）
func parsePunchAddr(s string) (netip.AddrPort, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.AddrPort{}, true
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return ap, true
}

// maxPunchAddrs 客户端侧候选数上限（与服务端 admin.MaxPunchAddrs 一致）。
//
// ⚠️ 跨模块常量无法编译期互引 → 两端各有一条测试钉住这个数字（镜像常量惯例）。
const maxPunchAddrs = 32

// parsePunchAddrs 解析候选列表；跳过非法项（宽容），返回去重后的结果。
//
// ⭐ 1b-3（A1）：对端可能发来一整个列表；旧对端只有 punchAddr。
func parsePunchAddrs(list []string) []netip.AddrPort {
	if len(list) == 0 {
		return nil
	}
	out := make([]netip.AddrPort, 0, len(list))
	seen := make(map[netip.AddrPort]struct{}, len(list))
	for _, s := range list {
		ap, ok := parsePunchAddr(s)
		if !ok || !ap.IsValid() || ap.Port() == 0 {
			continue
		}
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if _, dup := seen[ap]; dup {
			continue
		}
		seen[ap] = struct{}{}
		out = append(out, ap)
	}
	if len(out) == 0 {
		return nil
	}
	return normalizePunchAddrs(out)
}

// punchAddrStrings 把候选列表转成线上字符串（按端口升序，便于两端日志对比）
func punchAddrStrings(addrs []netip.AddrPort) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

// normalizePunchAddrs 归一化候选列表：只留 IPv4、去重、按（IP, 端口）排序、截断到上限。
//
// ⭐ 为什么只留 IPv4：打洞本身按 `realm.AddrFamilyIPv4` 跑（punch.go 的 PunchConfig），
// 混入 IPv6 只会让 realm 的 `punchFamilies` 判据变复杂而没有收益。
func normalizePunchAddrs(addrs []netip.AddrPort) []netip.AddrPort {
	if len(addrs) == 0 {
		return nil
	}
	seen := make(map[netip.AddrPort]struct{}, len(addrs))
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, a := range addrs {
		if !a.IsValid() || a.Port() == 0 {
			continue
		}
		a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
		if !a.Addr().Is4() {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() != out[j].Addr() {
			return out[i].Addr().Less(out[j].Addr())
		}
		return out[i].Port() < out[j].Port()
	})
	if len(out) > maxPunchAddrs {
		out = out[:maxPunchAddrs]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// peerAddrsFor 组装打洞目标列表（⭐1b-3）：候选列表 + 保证单地址一定在内。
//
// 旧对端只发 punchAddr（列表为空）⇒ 结果就是单地址（等价 1b-2B）；
// 新对端发列表时，若两者不一致也以「单地址必须在列表里」为准（不会漏掉主目标）。
func peerAddrsFor(list []netip.AddrPort, single netip.AddrPort) []netip.AddrPort {
	merged := make([]netip.AddrPort, 0, len(list)+1)
	if single.IsValid() && single.Port() != 0 {
		merged = append(merged, single)
	}
	merged = append(merged, list...)
	return normalizePunchAddrs(merged)
}

// peerReady 对端就绪信息（A 侧从 punch-peer 推送收到）。
//
// ⭐ 1b-3：除了单地址 punchAddr（兼容），还带候选列表与对端直连指纹（2.3 双向固定）。
type peerReady struct {
	addr  netip.AddrPort   // punchAddr（单地址，旧对端只有它）
	addrs []netip.AddrPort // punchAddrs（候选列表；空 ⇒ 只用 addr）
	fp    string           // 对端直连指纹（旧对端为空 ⇒ A 只做单向固定）
}

// ---------- 对称 NAT 端口预测（⭐1b-3 / 2.2） ----------

// predictPortWindow 单个观测值时向上补多少个端口（step 未知，按最常见的「连续分配」假设）
//
// ⚠️ 这是一个**赌**：不知道步长时假设 step=1、只往上补一小段。代价是候选变多
//
//	（对端每个候选都要发包），收益是「连续分配」的对称 NAT 有可能被猜中。
const predictPortWindow = 16

// predictExtraPorts 观测到 ≥2 个端口（可估步长）时，在 max(obs)+4 之后**再往上补**多少个
//
// 为什么还要补：端口的真实分配通常「比观测值更靠后」（观测是对 STUN 目的地分配的，
// 对端目的地会再往后分配几个）⇒ 只补到 max+4 往往不够。
const predictExtraPorts = 16

// predictSymmetricCandidates 由「同一 punch socket 的观测值」生成**要广告给对端的候选列表**。
//
// 背景（1b-3 的核心）：对称 NAT（NAT4）对**不同目的地**分配**不同**外部端口，
// 所以观测值 ≠ 对端能到达的端口。但只要该 NAT 的端口分配**有规律**（连续/小步长），
// 就能用观测值 + 步长**猜**出「对端方向」的端口，把猜测一起广告出去；
// 对端向这些候选发包时，正好有一个落在我们真实的对外映射上 ⇒ 打洞成功。
//
// 规则（与设计 §3.2 一致）：
//   - 观测 ≥2 个且同一 IP：step = 相邻差的**最小值**；从 min(obs) 按 step 补到 max(obs)+4，
//     再额外向上补 predictExtraPorts 个；
//   - 观测只有 1 个：step 未知 ⇒ 假设 1，从该端口向上补 predictPortWindow 个；
//   - **观测值必须全部保留**（它们在协议里同时充当「服务端校验的锚」）；
//   - 总上限 maxPunchAddrs(32)（与服务端上限一致）；
//   - `HY2_NO_PORT_PREDICT=1` 时**只广告观测值**（真机 A/B 对比用，也是回退开关）。
func predictSymmetricCandidates(obs []netip.AddrPort) []netip.AddrPort {
	obs = normalizePunchAddrs(obs)
	if len(obs) == 0 {
		return nil
	}
	if noPortPredict() {
		return obs
	}
	// 只对「同一个 IP」做预测：端口序列的规律只在同一 IP 内成立
	ip := obs[0].Addr()
	for _, a := range obs[1:] {
		if a.Addr() != ip {
			return obs
		}
	}

	minPort := uint32(obs[0].Port())
	maxPort := minPort
	step := uint32(1)
	if len(obs) == 1 {
		// 单观测：step 未知 → 假设 1（连续分配最常见）
	} else {
		best := uint32(0)
		for i := 1; i < len(obs); i++ {
			gap := uint32(obs[i].Port()) - uint32(obs[i-1].Port())
			if gap == 0 {
				continue
			}
			if best == 0 || gap < best {
				best = gap
			}
		}
		if best > 0 {
			step = best
		}
		maxPort = uint32(obs[len(obs)-1].Port())
	}

	// ① 覆盖 [min, max+4]（含观测值之间的空洞）
	end := maxPort + 4
	if len(obs) == 1 {
		end = minPort + uint32(predictPortWindow) - 1
	}
	out := make([]netip.AddrPort, 0, maxPunchAddrs)
	seen := make(map[uint16]struct{}, maxPunchAddrs)
	add := func(port uint32) bool {
		if port == 0 || port > 65535 || len(out) >= maxPunchAddrs {
			return false
		}
		p := uint16(port)
		if _, dup := seen[p]; dup {
			return true
		}
		seen[p] = struct{}{}
		out = append(out, netip.AddrPortFrom(ip, p))
		return true
	}
	for p := minPort; p <= end && len(out) < maxPunchAddrs; p += step {
		add(p)
	}
	// ② 再向上补一段（真实分配通常比观测更靠后）
	extraEnd := maxPort + 4 + uint32(predictExtraPorts)
	if len(obs) == 1 {
		extraEnd = minPort + uint32(predictPortWindow) + uint32(predictExtraPorts)
	}
	for p := end + step; p <= extraEnd && len(out) < maxPunchAddrs; p += step {
		add(p)
	}
	// ③ 观测值一个都不能丢（step 与观测不整除时会漏）
	for _, a := range obs {
		add(uint32(a.Port()))
	}

	// 兜底：若 step 过大导致候选太少，按 +1 补齐到上限（提高命中率）
	for p := minPort; len(out) < maxPunchAddrs && p <= minPort+uint32(maxPunchAddrs); p++ {
		add(p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port() < out[j].Port() })
	return out
}

// candidatesForNATType ⭐ 1b-4 第 2 步-A（bug #3 修复）：**按本机 NAT 类型**决定要不要做端口预测。
//
// 为什么需要这道门（bug #3 的实质）：
// 端口预测只在**对称 NAT（NAT4）**下有依据 —— 那种 NAT 对**不同目的地**分配**不同**外部端口，
// 所以「广告更多候选」才能把对端方向的那个端口覆盖进来。
// 而在 **cone NAT（NAT1~NAT3）**下，同一个内部 socket 对任何目的地都复用**同一个**外部映射
// ⇒ 观测值本身就是对端能到达的地址，多广告的 31 个候选**全是噪声**：
//   - 对端会朝这些端口发包（realm 逐候选打），既浪费时间又可能触发对端的限流；
//   - 服务端还要转发/校验这些候选（协议开销）。
//
// 修复前：发起方（`runInitiator`）与响应方（`runResponder`）**都无条件**调用
// `predictSymmetricCandidates`，于是 cone 用户也广告 32 个候选（实测：`NATFullCone` ⇒ 32 个）。
// 修复后：只有对称 NAT 才预测；其余（full-cone / restricted / port-restricted / unknown）
// 一律只广告**观测值**（与「关掉预测」的行为一致）。
//
// ⚠️ 与 `HY2_NO_PORT_PREDICT=1` 的关系：那个开关是**真机 A/B 用的全局禁用**，
// 本门是**按 NAT 类型的产品逻辑**；两者是「或」的关系（任一要求不预测 ⇒ 不预测）。
//
// ⚠️ 两侧必须用同一判据（本函数就是唯一判据）——只改一侧会让「我广告 32 个、对端只广告 1 个」，
// 候选数不对称，打洞成功率下降（这就是 B1' 不可切片点的原因）。
func candidatesForNATType(natType NATType, obs []netip.AddrPort) []netip.AddrPort {
	if natType != NATSymmetric {
		return normalizePunchAddrs(obs) // cone / unknown：观测值即全部可达地址
	}
	if got := predictSymmetricCandidates(obs); len(got) > 0 {
		return got
	}
	// 预测返回空（观测为空等边界）⇒ 退回观测值，绝不让候选列表为空
	return normalizePunchAddrs(obs)
}

// noPortPredict 是否禁用端口预测（`HY2_NO_PORT_PREDICT=1`）。
//
// 与 HY2_NO_PUBLIC_STUN 同性质：**调试 / 排障开关**，用来在真机上做 A/B
// （开/关预测各测一轮，判断 NAT4 成功率是否真的来自预测）。
func noPortPredict() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("HY2_NO_PORT_PREDICT"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ---------- 地址过滤（设计 §8.1） ----------

// sameAddrPort 比较两个地址（⭐ 必须 Unmap 归一化 IPv4-in-IPv6，否则误杀对端包）
func sameAddrPort(a, b netip.AddrPort) bool {
	if a.Port() != b.Port() {
		return false
	}
	return a.Addr().Unmap() == b.Addr().Unmap()
}

// addrPortFromNetAddr 把 net.Addr 转成 netip.AddrPort（同样做 Unmap 归一化）
func addrPortFromNetAddr(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		ap := v.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
	default:
		if a == nil {
			return netip.AddrPort{}, false
		}
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
	}
}

// peerFilterConn 只放行「打洞学到的那个对端地址」的 PacketConn（A 侧 QUIC listener 用）。
//
// 为什么在 ReadFrom 过滤而不是「接受连接后校验 RemoteAddr」：
// 陌生来源的 QUIC Initial 根本进不了 quic-go —— 不占连接表、不起握手 goroutine，
// 也就不会给新开的监听面引入可被滥用的一侧（设计 §8.1）。
type peerFilterConn struct {
	net.PacketConn
	peer netip.AddrPort

	drops     atomic.Int64
	lastLogAt atomic.Int64
}

func newPeerFilterConn(pc net.PacketConn, peer netip.AddrPort) *peerFilterConn {
	return &peerFilterConn{
		PacketConn: pc,
		peer:       netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()),
	}
}

func (c *peerFilterConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		ap, ok := addrPortFromNetAddr(addr)
		if !ok || !sameAddrPort(ap, c.peer) {
			c.noteDrop(ap)
			continue
		}
		return n, addr, nil
	}
}

func (c *peerFilterConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ap, ok := addrPortFromNetAddr(addr)
	if !ok || !sameAddrPort(ap, c.peer) {
		return 0, fmt.Errorf("peerFilterConn: 拒绝写往非对端地址 %v（期望 %v）", addr, c.peer)
	}
	return c.PacketConn.WriteTo(p, addr)
}

// noteDrop 记一次丢弃（限速日志：每 5s 最多一条）
func (c *peerFilterConn) noteDrop(from netip.AddrPort) {
	c.drops.Add(1)
	now := time.Now().UnixNano()
	last := c.lastLogAt.Load()
	if last != 0 && now-last < int64(5*time.Second) {
		return
	}
	if !c.lastLogAt.CompareAndSwap(last, now) {
		return
	}
	log.Printf("🛡️ [HARP] 已丢弃非对端来源的包（来源 %v，期望 %v，累计丢弃 %d）",
		from, c.peer, c.drops.Load())
}

func (c *peerFilterConn) dropCount() int64 { return c.drops.Load() }

// ---------- 直连证书（Q1：客户端实例生命周期内固定） ----------

// ensureDirectCert 懒生成一份自签证书（内存保存，不落盘），返回证书与指纹
func (c *Hysteria2Client) ensureDirectCert() (tls.Certificate, string, error) {
	c.punchMu.Lock()
	defer c.punchMu.Unlock()
	if c.directCert != nil {
		return *c.directCert, c.directFP, nil
	}
	cert, fp, err := generateDirectCert()
	if err != nil {
		return tls.Certificate{}, "", err
	}
	c.directCert = &cert
	c.directFP = fp
	return cert, fp, nil
}

// generateDirectCert 生成直连用的自签证书（ECDSA P-256 / 24h / 仅内存）
func generateDirectCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("生成直连密钥失败: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "p2sp-direct"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(punchDirectCertLife),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("自签直连证书失败: %w", err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}

// pinDirectFingerprint 返回一个固定对端指纹的 VerifyPeerCertificate
func pinDirectFingerprint(want string) func([][]byte, [][]*x509.Certificate) error {
	want = strings.ToLower(strings.TrimSpace(want))
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("%w: 对端没有提供证书", errFingerprintMismatch)
		}
		sum := sha256.Sum256(rawCerts[0])
		got := hex.EncodeToString(sum[:])
		if got != want {
			// 中性 UI 文案 + 完整指纹进日志（设计 §10）
			log.Printf("⚠️ [HARP] 指纹不匹配：期望 %s，实际 %s", want, got)
			return fmt.Errorf("%w: 期望 %s 实际 %s", errFingerprintMismatch, want, got)
		}
		return nil
	}
}

// ---------- 打洞会话 ----------

// punchTuning 可注入的时间参数（生产用默认值；测试里缩小以便快速、确定性地跑）
type punchTuning struct {
	handshake time.Duration
	probe     time.Duration
	stun      time.Duration
	readyWait time.Duration
}

func defaultPunchTuning() punchTuning {
	return punchTuning{
		handshake: punchHandshakeTimeout,
		probe:     punchProbeTimeout,
		stun:      punchStunTimeout,
		readyWait: punchReadyWait,
	}
}

type punchSession struct {
	mgr      *punchManager
	id       string
	peerVIP  string
	role     string // initiator | responder
	windowMs int
	seed     string
	myFP     string // 自己的直连指纹（A 用）
	peerFP   string // 对端的直连指纹（B 用）
	// peerPunchAddr 打洞目标：A 来自 punch-peer 推送，B 来自 punch-invite
	peerPunchAddr netip.AddrPort
	// peerPunchAddrs 对端候选列表（⭐1b-3；空 ⇒ 用 peerPunchAddr 单地址）
	peerPunchAddrs []netip.AddrPort
	// myPunchAddr 自己 punch socket 的公网地址（B 用在 punch-ready 里；A 用在 intent 里）
	myPunchAddr netip.AddrPort
	// myPunchAddrs 自己 punch socket 的**全部**观测（⭐1b-3：不再只留第一个）
	//
	// 为什么重要：realm 的对称 NAT 预测需要「同一 IP 的 ≥2 个相邻端口」才会触发，
	// 只留一个观测值 ⇒ punchAddrs 只剩 1 个 ⇒ 预测逻辑永远不生效。
	myPunchAddrs []netip.AddrPort

	ctx    context.Context
	cancel context.CancelFunc

	sock      net.PacketConn
	transport *quic.Transport
	listener  *quic.Listener
	conn      *quic.Conn
	filter    *peerFilterConn

	// punchActive 打洞期间为 true（handshake 前会断言它已归零：
	// realm.Punch 独占 socket 读，绝不能与 QUIC 的读并存）
	punchActive atomic.Bool
	// rdySentAfterPunch / rdyReceived：给「P2SP-RDY1 时序」测试用的观测点
	//   - A 侧：通知是在打洞返回之后发出的（rdySentAfterPunch）
	//   - B 侧：在创建 QUIC transport **之前**就收到了通知（rdyReceived）
	rdySentAfterPunch atomic.Bool
	rdyReceived       atomic.Bool
	// waitDone：B 侧「已经结束对 socket 的裸读」——拨号前会断言它，
	// 结构性保证「先结束裸读，再把 socket 交给 QUIC」
	waitDone atomic.Bool // tuning 会话级超时（从 mgr 拷贝，避免测试里改动影响别的会话）
	tuning   punchTuning

	state  atomic.Value // string
	reason atomic.Value // string
	// ⭐ 1b-4 第 3 步：本次会话是否**成功**（succeed() 置位）。
	// 用途：收尾时清零 busy/rate streak（「一次成功的直连 ⇒ 对端现在不忙」）。
	// 与 `reason` 的关系：reason 零值为 ""（成功时被显式记为 ok-direct），
	// 单看 reason 也能判，但 succeeded 让「成功」这件事**不依赖原因码表的完整性**。
	succeeded atomic.Bool
	rttDirect atomic.Int64 // ns
	rttQuic   atomic.Int64 // ns
	startedAt time.Time

	// ⭐ 1b-4 第 2 步-A：探针质量度量（写进对端质量表用）
	//   probeGot   收到有效回显的轮数
	//   probeTotal 本轮实际发出的探针轮数（A 侧固定 punchProbeRounds；B 侧是收到的帧数）
	//   两者一起算「探针丢包率」；只在**成功**路径上有意义（失败看 reason 码）
	probeGot   atomic.Int32
	probeTotal atomic.Int32
	// ⭐ 1b-4 第 2 步-A：诊断用的对端信息（写质量表时带上；来自信令/邀请）
	peerNATType atomic.Value // string
	peerAddr    atomic.Value // string

	// ⭐ 1b-2A：触发来源（traffic/config/manual/remote），随状态事件给 UI
	trigger string
	// detached 资源已移交给路径管理器（此后 closeAll 变 no-op）
	detached atomic.Bool

	peerReadyCh chan peerReady // A：punch-peer 到达（⭐1b-3：带候选列表 + 对端指纹）
	doneCh      chan struct{}  // 会话结束
	finishOnce  sync.Once
	sockClose   sync.Once
	mu          sync.Mutex // 保护 conn/listener/transport 的释放

	// ⭐ 第 2 步-B ④：**仅测试**用的「资源真的被释放了」观测钩子（由 `mu` 保护）。
	//
	// 为什么需要：预打洞成功走 `closeAll()`，但 `closeAll()` 在 `detached` 时是 no-op
	// ⇒ 「有没有真的释放」从外部看不见（会话跑完就从 `m.sessions` 删掉了）。
	// 有了它，用例才能**确定性**地断言「预打洞成功也把连接释放了」（而不是靠 goroutine 计数）。
	// 生产路径恒为 nil（从不设置）⇒ 零开销。
	onRelease func()
}

func (s *punchSession) setState(st string) {
	s.state.Store(st)
	s.mgr.emit(s.status(st, ""))
}

func (s *punchSession) status(state, reason string) P2PStatus {
	if state == "" {
		if v, ok := s.state.Load().(string); ok {
			state = v
		}
	}
	if reason == "" {
		if v, ok := s.reason.Load().(string); ok {
			reason = v
		}
	}
	path := "relay"
	if state == P2PStateDirect {
		path = "direct"
	}
	return P2PStatus{
		PeerVIP:     s.peerVIP,
		State:       state,
		ReasonCode:  reason,
		ReasonText:  P2PReasonText(reason),
		Path:        path,
		RTTDirectMs: msAtLeast1(s.rttDirect.Load()),
		RTTQuicMs:   msAtLeast1(s.rttQuic.Load()),
		At:          time.Now().UnixMilli(),
		Retryable:   p2pRetryable(reason),
		Trigger:     s.trigger,
		PathState:   path,
	}
}

// msAtLeast1 把纳秒转成毫秒，但「非零就必须至少报 1ms」。
//
// 理由：loopback / 同城内网直连的真实 RTT 常在 0.2~0.9ms，
// 直接整除会显示成「0ms」，UI 上看起来像没测到；宁可报 1ms 也不要谎报 0。
func msAtLeast1(ns int64) int64 {
	if ns <= 0 {
		return 0
	}
	ms := ns / int64(time.Millisecond)
	if ms == 0 {
		ms = 1
	}
	return ms
}

// fail 结束会话并给出原因码
func (s *punchSession) fail(reason string) {
	log.Printf("❌ [打洞] 会话结束（%s role=%s peer=%s reason=%s）",
		s.id, s.role, s.peerVIP, reason)
	s.reason.Store(reason)
	s.state.Store(P2PStateFailed)
	s.mgr.emit(s.status(P2PStateFailed, reason))
	s.closeAll()
	s.finish()
	// ⭐ 1b-2A：让路径管理器按失败分类安排退避（不重复发事件，状态已在上行发出）
	if pm := s.mgr.pathMgrRef(); pm != nil {
		pm.onPunchFailed(s.peerVIP, reason)
	}
}

// succeed 会话成功：**只在「打洞 + QUIC 握手 + 应用层探针至少一个往返」全部通过后调用**。
//
// ⚠️ 精确语义（review 追问 1 核实）：本函数**不是**「握手成功就调」。
//
//	两个调用点都在握手之后、且都在**探针写出并读到有效回显**之后：
//	  ① A 侧 `runProbe`：3 轮探针走完、`got==true`（至少一轮有效回显）后调用；
//	  ② B 侧 `runProbeEcho`：首个探针帧回显成功后调用。
//	⇒ 「打洞成功但握手失败」走的是 `fail(P2PReasonDirectHandshakeFailed)`，
//	  **不会**调用本函数 ⇒ **不会**错误清零 busy/rate streak。
//	⇒ 交付说明里「打洞+握手+探针通过」的措辞与实现一致（此前注释简短，容易误读，故在此写明）。
func (s *punchSession) succeed() {
	// ⭐ 1b-4 第 3 步：标记「本次会话成功」——收尾时用它**清零 busy/rate streak**
	//    （语义：一次成功的直连说明「对端现在不忙了」，见 noteSessionOutcomeLocked）。
	//    同时记下原因码：`reason` 的**零值原因**就是成功（收尾判据里作兜底）。
	s.succeeded.Store(true)
	s.reason.Store(P2PReasonOKDirect)
	s.state.Store(P2PStateDirect)
	// ⭐ 1b-4 第一步（先验后切）：**有路径管理器时，这里不再发 `direct`**。
	//
	// 打洞+握手成功只说明通道打通了，数据此刻仍走中继；真正的「切到直连」发生在
	// 试用期判定通过之后（`installAfterTrial` 发 direct）。若这里照旧发一条 direct，
	// 事件流会变成「direct → trial → direct」—— 前端会先记一条「已建立直连」成功日志、
	// 再回退到「测试中」，正是方案 A 记账里那条「用户可能感知到细微抖动」的形态。
	// 没有路径管理器时（loopback 单测 / P2P 未生效）保持原样，语义不变。
	if s.mgr.pathMgrRef() == nil {
		s.mgr.emit(s.status(P2PStateDirect, P2PReasonOKDirect))
	}
	// ⭐ 第 2 步-B ④（**岔路 A：预打洞不保留连接**）—— 本分支是本次改动**唯一**新增的逻辑，
	//   下面的既有路径**逐字未动**。
	//
	// 为什么预打洞成功也要释放：预打洞的产物是**信息**（这个对端打得通 / 最近通信过），
	// 不是「一条要用的连接」。若照常 `handoverToPath()`，会：
	//   - 让 pathManager 起一条**没有任何流量**的 trial 路径（白占资源），
	//     并可能把仍在走中继的流量切过去（用户没要求时就切 = 越权）；
	//   - 让「预打洞」在用户可见事件流里表现为「已建立直连」（它其实什么都没承载）。
	// ⇒ 这里 `closeAll()` + `finish()`：关闭打洞期间开的 socket/transport，
	//   会话**始终归 punchManager**（`m.sessions` 看得见）⇒ **不产生 orphan**。
	//
	// ⚠️ 质量表**照写**（不由本分支负责）：本函数末尾的既有路径不变，而写表发生在
	//   调用方（`PunchWithTrigger` 的会话 defer → `notePeerQuality`）⇒ 预打洞的
	//   探针结果照常进表（这正是预打洞的价值）。`reason` 也照常是 ok-direct。
	//
	// ⚠️ 不做的事：**不发** `direct` 事件（上面的既有条件已保证：有 pathManager 时不发）；
	//    **不** `detached.Store(true)`（那会让 `closeAll()` 变成 no-op ⇒ 真的泄漏）。
	// ⚠️ A3a（2026-09-28）**已删除「预打洞成功分支」整块**（原 `if s.trigger == P2PTriggerPrePunch { … }`）：
	// 预打洞发起侧整体删除（`prepunch.go` 桩化、`P2PTriggerPrePunch` 常量删除）⇒ **该分支不可达**。
	// 它做的是「成功也不 handover，只 `closeAll()` + `finish()`」（岔路 A）+ **仅测试**观测钩子。
	// 🔎 原代码：`A2-干净点快照-2026-09-28\quic\punch.go` 里 `grep -n P2PTriggerPrePunch` 的第一处
	//    （`succeed()` 内，`prePunchSuccessHook` 的调用点即在该块内）。
	// 📌 灰度期（对端未升级）仍会**对端发起**预打洞 ⇒ 本侧作为 **responder** 不在此分支，
	//    走下面的正常 `handoverToPath()`；对端"探路收尾"的 CONNECTION_CLOSE 丢包由
	//    `directPath.scoutTearDownHeuristic()` 兜底（**A3b 才删**）。
	// ⭐ 1b-2A（P0 修复）：把成功后的连接**移交**给路径管理器 ——
	//   在此之前这条 conn/socket/transport 无人释放（成功路径不调用 closeAll，
	//   会话又会从 m.sessions 里删掉，mgr.close() 也就看不见它）。
	//   移交后所有权归 pathManager：路径关闭/Close() 时才 releaseAll()。
	s.handoverToPath()
	s.finish()
}

// handoverToPath 把直连连接的所有权交给路径管理器（幂等；没有路径管理器时不动）
//
// ⚠️⚠️ 可观测性契约（2026-09-27 真机 bug 后补）：本函数的**每一条**提前返回都必须留下日志。
//
//	为什么：它返回前若有一条静默 bail，会话就**不会**置 `detached` ⇒ 会话收尾的
//	`closeAll()` 会把这条连接**真的关掉**。真机现象正是「一边有路径、另一边没有，
//	而没路径的那边把连接关了」⇒ 另一边看到 `EOF` / `remote: path closed`。
//	加日志前这条路径**完全静默**（只有 `succeed()` 成功那行），定位时无法区分
//	「交出去了」和「静默放弃了」——这正是本 bug 一开始定不到根因的原因。
//
// 返回 true 表示真的移交给了路径管理器。
func (s *punchSession) handoverToPath() {
	if s.detached.Load() {
		return
	}
	pm := s.mgr.pathMgrRef()
	if pm == nil {
		log.Printf("⚠️ [HARP] %s 打洞成功但**未移交**：路径管理器为空（P2P 未生效？）"+
			"⇒ 会话收尾会关闭这条连接", s.peerVIP)
		return
	}
	myVIP, ok := s.mgr.c.myVIP4()
	if !ok {
		log.Printf("⚠️ [HARP] %s 打洞成功但**未移交**：本机隧道地址未知（DHCP 未完成？）"+
			"⇒ 会话收尾会关闭这条连接", s.peerVIP)
		return
	}
	peer, ok := parseIPv4(s.peerVIP)
	if !ok {
		log.Printf("⚠️ [HARP] %s 打洞成功但**未移交**：对端 VIP 解析失败"+
			"⇒ 会话收尾会关闭这条连接", s.peerVIP)
		return
	}
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		log.Printf("⚠️ [HARP] %s 打洞成功但**未移交**：会话连接为空（已被释放？）"+
			"⇒ 会话收尾会关闭这条连接", s.peerVIP)
		return
	}
	// 标记移交：此后 closeAll() 变成 no-op（资源归路径管理器）
	s.detached.Store(true)

	release := func() error {
		s.releaseAll()
		return nil
	}
	pm.handleEstablished(establishedReq{
		peerVIP:  s.peerVIP,
		peer:     peer,
		role:     s.role,
		conn:     realDirectConn{c: conn},
		closers:  []func() error{release},
		myVIP:    myVIP,
		peerAddr: s.peerPunchAddr.String(),
		// ⭐ 把打洞阶段已测到的 RTT 交给路径：否则路径初始 RTT=0，
		//    「已启用直连」那行日志会显示 0s（真机上就是这样被发现的）。
		rttDirect: time.Duration(s.rttDirect.Load()),
		rttQuic:   time.Duration(s.rttQuic.Load()),
		// ⭐ B1：把「本次打洞邀请里声明的窗口」交给路径 —— 灰度期「响应方探路收尾」
		//    启发式用它推出「对端最后一次回显」的右界（见 scoutTearDownHeuristic）。
		scoutWindowMs: s.windowMs,
	})
}

func (s *punchSession) finish() {
	s.finishOnce.Do(func() { close(s.doneCh) })
}

// closeAll 释放 socket / 传输（幂等；失败路径与 Close 都会走到）
//
// ⭐ 1b-2A：如果资源已经**移交**给路径管理器（打洞成功），这里就什么都不做 ——
// 否则打洞管理器会把一条正在承载业务流量的直连连接关掉（P0 的另一面）。
func (s *punchSession) closeAll() {
	if s.detached.Load() {
		return
	}
	s.releaseAll()
}

// releaseAll 真正释放资源（路径管理器在路径关闭时经由 closers 调用）
func (s *punchSession) releaseAll() {
	s.mu.Lock()
	conn, ln, tr, sock := s.conn, s.listener, s.transport, s.sock
	onRelease := s.onRelease
	s.conn, s.listener, s.transport = nil, nil, nil
	s.mu.Unlock()
	// ⭐ 第 2 步-B ④：**仅测试**用的观测钩子（预打洞成功必须真的走到这里）。
	//    nil 时零开销；生产代码从不设置它。
	if onRelease != nil {
		onRelease()
	}
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
	if ln != nil {
		_ = ln.Close()
	}
	if tr != nil {
		_ = tr.Close()
	}
	s.sockClose.Do(func() {
		if sock != nil {
			_ = sock.Close()
		}
	})
}

// remaining 剩余预算
func (s *punchSession) remaining() time.Duration {
	d := time.Until(deadlineOf(s.ctx))
	if d < 0 {
		return 0
	}
	return d
}

// stageTimeout 阶段超时 = min(阶段值, 剩余预算)（设计 §3.4 规则②）
func (s *punchSession) stageTimeout(d time.Duration) (time.Duration, bool) {
	rem := s.remaining()
	if rem < punchStageFloor {
		return 0, false
	}
	if d > rem {
		d = rem
	}
	return d, true
}

// canRetry 重试门：剩余 ≥ 重试成本 + punchRetryFloor（设计 §3.4 规则③）
func (s *punchSession) canRetry(cost time.Duration) bool {
	return s.remaining() >= cost+punchRetryFloor
}

func deadlineOf(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now()
}

// ---------- punchManager ----------

type punchManager struct {
	c      *Hysteria2Client
	ctx    context.Context
	cancel context.CancelFunc

	pushCh chan signalMessage
	doneCh chan struct{}
	// startOnce / doneOnce 保证：eventLoop 只启动一次、doneCh 只关一次；
	// 且 close() 在「从未 start 过」时也能正常返回（测试常见）。
	startOnce sync.Once
	doneOnce  sync.Once
	// ⚠️ A3a（2026-09-28）**已删除 `prePunchStartOnce sync.Once`**
	//（预打洞调度器只启动一次的幂等门）—— 调度器已整体删除。
	// 🔎 原代码：`A2-干净点快照-2026-09-28\quic\punch.go` 里 `grep -n prePunchStartOnce`。

	mu         sync.Mutex
	sessions   map[string]*punchSession
	byPeer     map[string]*punchSession // peerVIP → 自发起会话（每对端最多 1 个）
	cooldown   map[string]time.Time     // peerVIP → 冷却截止
	responders int
	lastInvite map[string]time.Time // 发起方 VIP → 上次接受邀请时刻
	jobs       sync.WaitGroup

	// ⭐ 第 2 步-B：**预打洞侦察调度器**（岔路 A：不保留连接）。
	//
	// ⚠️ A3a（2026-09-28）**已删除预打洞发起侧的 11 个字段**（原来在此处的整块）：
	//	`prePunchCfg prePunchConfig` / `prePunchSpent []time.Time` / `prePunchDrawn map[string]bool`
	//	/ `prePunchLastTry map[string]time.Time` / `prePunchRounds int` / `prePunchTier string`
	//	/ `prePunchCandN int` / `prePunchDraws []string` / `prePunchBatchSkips int`
	//	/ `onPrePunchSuccess func(*punchSession)`（**仅测试**观测钩子）。
	// ⚠️ 其中 `prePunchCfg` 的**类型** `prePunchConfig` 定义在 `prepunch.go` ⇒ 两者必须同批删除
	//    （否则 `punch.go` 自身编译不过）。`prepunch.go` 同批桩化。
	// 📌 **钩子设计教训（已收割）**：`onPrePunchSuccess` 曾挂在 `newSession` 里 —— 那里**持着 `m.mu`**，
	//    钩子再取 `s.mu` ⇒ 与「分派协程持 `s.mu` 调 `handleInvite` 取 `m.mu`」形成**闭环死锁**
	//    （实测 60s 超时）。纪律「**不得在锁内回调**」对测试钩子同样适用 ⇒ 《工程纪律》§3 第 11 条（四约束）。
	// 🔎 原代码：`A2-干净点快照-2026-09-28\quic\punch.go` 里 `grep -n 'prePunch'`（该块的行号区间）。

	// ⭐ 1b-4 第 3 步：busy / rate-limited 的**独立 streak**（均在 mu 保护下）。
	//
	//   busyPeerStreak —— 连续「对端忙」（pair-busy / pair-cooldown）
	//   rateStreak     —— 连续「服务端限流」（rate-limited）
	//
	// ⚠️ 与 `pathManager.backoffState` 的 step / qualityStep **完全无关**：
	//    「忙」不是失败，**绝不**推进那两条 streak（这是范围文档 §3.2 的硬约束）。
	// ⚠️ 寿命与 `cooldown` 对齐（冷却过期即清，见 pruneBusyLocked）⇒ 不会无限累积。
	busyPeerStreak map[string]int
	rateStreak     map[string]int

	onStatus func(P2PStatus)

	// ⭐ 1b-2A：路径管理器（成功会话的资源移交给它；失败时通知它安排退避）
	//
	// ⚠️ 用 atomic.Pointer 而不是普通字段 + 锁：`handleInvite` 会在**持有 m.mu**
	//    的情况下走到这里（收到邀请要让路），如果这里再取一次 m.mu 就是自死锁
	//    （非重入互斥锁）——踩过一次，构建期测试直接 60s 超时。
	pathMgr atomic.Pointer[pathManager]
	// skippedDupPunch ⭐ B3：因「已有可用路径」而跳过的流量驱动打洞次数（发版后观察项）。
	skippedDupPunch atomic.Int64

	// ⭐ 1b-4 第 2 步-A：对端质量表（**由 Hysteria2Client 拥有并注入**，本管理器只持引用）。
	//
	// ⚠️ 为什么不能在这里 `new`：punchManager 每次连接都会重建（startPunchManager），
	//    在这里 new 会让「重连不清空」这条拍板约束失效（见实施计划 §9.2.1）。
	// ⚠️ 用 atomic.Pointer 与 pathMgr 同理：`handleInvite` 会在**持有 m.mu** 时读它，
	//    普通字段 + 锁会自死锁（1b-2A 踩过，构建期直接 60s 超时）。
	quality atomic.Pointer[peerTable]

	// rdySentSeen / rdyRecvSeen：累计「曾经发过 / 收过 P2SP-RDY1」
	// （会话成功后会从 sessions 移除，测试需要 manager 级的历史标记）
	rdySentSeen atomic.Bool
	rdyRecvSeen atomic.Bool

	// 可注入（测试用；生产用默认实现）
	discoverPunchAddr func(ctx context.Context, sock net.PacketConn) ([]netip.AddrPort, error)
	// noPredict 关闭「对称 NAT 端口预测」（**测试确定性开关**，不是产品开关）。
	//
	// 为什么需要：loopback 用例把发现函数替换成「返回本机 punch socket 地址」，
	// 预测会把这一个地址扩成 32 个候选，于是对端会朝进程内**别的** socket 端口喷包，
	// 破坏这些用例的时序（实测 3 个用例超时）。产品路径默认开启预测。
	noPredict       bool
	openPunchSocket func() (net.PacketConn, error)
	budget          time.Duration
	tuning          punchTuning
	// windowDefault 自发起时的打洞窗口（可调；生产默认 10s）
	windowDefault int
}

func newPunchManager(c *Hysteria2Client) *punchManager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &punchManager{
		c:              c,
		ctx:            ctx,
		cancel:         cancel,
		pushCh:         make(chan signalMessage, punchPushQueueSize),
		doneCh:         make(chan struct{}),
		sessions:       make(map[string]*punchSession),
		byPeer:         make(map[string]*punchSession),
		cooldown:       make(map[string]time.Time),
		lastInvite:     make(map[string]time.Time),
		busyPeerStreak: make(map[string]int),
		rateStreak:     make(map[string]int),
		budget:         punchAttemptBudget,
		tuning:         defaultPunchTuning(),
		windowDefault:  punchWindowDefault,
		// ⚠️ A3a（2026-09-28）**已删除这里的三行预打洞初始化**
		//（`prePunchCfg: defaultPrePunchConfig()` / `prePunchDrawn` / `prePunchLastTry`）
		// ⇒ 字段已删，初始化随之删除。`defaultPrePunchConfig()` 随 `prepunch.go` 一起消失。
		// 🔎 原代码：`A2-干净点快照-2026-09-28\quic\punch.go` 里 `grep -n defaultPrePunchConfig`。
	}
	m.discoverPunchAddr = m.defaultDiscoverPunchAddr
	m.openPunchSocket = func() (net.PacketConn, error) {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	return m
}

// start 启动事件协程（幂等）
//
// ⚠️ A3a（2026-09-28）**已删除「预打洞调度器」的启动块**（及其前的注释块与 `ℹ️ [预打洞] 已暂停` 日志）：
// 预打洞**发起侧**整体永久删除（`prepunch.go` 桩化）⇒ 不存在可启动的调度器。
//
//	⇒ 边界五项第 5 项：**基线 0 → 保持 0**（唯一 goroutine 就是 `eventLoop`；`jobs` 不再有调度器）。
//	⚠️ 表述纪律：**`+1` 是 B1 之前**（调度器还在）的基线；B1 起已回到 0，A3a 再删掉那段被注释的代码。
//
// 🔎 原代码（含被注释的启动块与 `prePunchSchedulerLoop` 调用）：
//
//	`A2-干净点快照-2026-09-28\quic\punch.go` 里 `grep -n prePunchSchedulerLoop`。
//
// 📌 恢复方向已作废：B1 交付说明 §8 那份"预打洞**恢复**清单"**不再适用** ——
// A2 §0.1 已拍板「从追加项**删除**『预打洞恢复』」⇒ 本切片执行的是**删除**（详见 A3a 计划 §8 第 5 项）。
func (m *punchManager) start() {
	m.startOnce.Do(func() { go m.eventLoop() })
}

// close 停止管理器：取消所有会话并等它们退出（幂等；未 start 过也能安全调用）
func (m *punchManager) close() {
	m.cancel()
	// 没启动过事件循环时，自己把 doneCh 标记完成，避免 <-doneCh 永久阻塞
	m.startOnce.Do(func() { m.doneOnce.Do(func() { close(m.doneCh) }) })

	m.mu.Lock()
	sessions := make([]*punchSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		s.closeAll()
		s.finish()
	}
	<-m.doneCh
	m.jobs.Wait()
}

func (m *punchManager) setStatusHandler(fn func(P2PStatus)) {
	m.mu.Lock()
	m.onStatus = fn
	m.mu.Unlock()
}

// setPathManager 绑定路径管理器（由 startPunchManager 调用）
func (m *punchManager) setPathManager(pm *pathManager) {
	m.pathMgr.Store(pm)
}

// pathMgrRef 取路径管理器（可能为 nil：P2P 未生效时）。
// 无锁：`handleInvite` 会在持锁状态下调用它。
func (m *punchManager) pathMgrRef() *pathManager {
	return m.pathMgr.Load()
}

// setQualityTable 绑定对端质量表（由 startPunchManager 注入**同一实例**；只读引用）
func (m *punchManager) setQualityTable(t *peerTable) { m.quality.Store(t) }

// qualityTable 取质量表（可能为 nil：P2P 未生效 / 单测未注入）。
// 无锁：会话结束路径与持锁路径都会调用它。
func (m *punchManager) qualityTable() *peerTable { return m.quality.Load() }

// isPoorQualityLoss 「丢包率 lossPct（0~100）是否应判为质量差」。
//
// ⭐ 判据**由试用期常量推导**（review 追问 4），不另立 10%/90%：
//
//	试用期单样本判据（`trialSampleGood`）：成功率 ≥ trialMinProbeSuccess(0.90) 才算「好」
//	⇒ 质量表的「差」= 它的**补集**：成功率 < 0.90 ⇔ 丢包率 > 10%
//
// 边界语义（与试用期**严格一致**，不是「差不多」）：
//
//	成功率恰好 90%（丢包 10%）⇒ 试用期判「好」；质量表也**不**判「差」（`>` 而非 `>=`）
//
// 注意 lossPct 是整数百分比（截断），因此这里的比较在整数域与
// `float64(success) < trialMinProbeSuccess` 等价到 1% 精度（探针轮数只有 3，
// 1% 的差别不可能落进任何真实取值）。
func isPoorQualityLoss(lossPct int) bool {
	// 成功率阈值 ⇒ 丢包阈值的整数上界：0.90 ⇒ 丢包 > 10% 才算差
	// （用 Ceil 而非直接截断，保证「0.95 ⇒ 丢包 > 5%」这种非整十阈值也正确）
	lossLimit := int(math.Ceil((1 - trialMinProbeSuccess) * 100))
	return lossPct > lossLimit
}

// ---------- ⭐ 1b-4 第 2 步-A：把打洞结果写进对端质量表 ----------

// notePeerQuality 在**会话真正结束**时把结果写进质量表。
//
// ⚠️ **锁上下文与锁序**（review 追问 3）：
//   - 「在 m.mu 之外写表」里的 `m.mu` = **`punchManager.mu`**（本文件里所有 `m.mu.Lock()` 的那个，
//     保护 `sessions`/`byPeer`/`cooldown` 等）。
//   - 本函数**不持有任何 `punchManager` 的锁**：唯一调用点在会话收尾的 defer 里，
//     且紧跟在 `m.mu.Unlock()` **之后**（顺序就是「先解锁、再写表」）。
//   - `peerTable` 自己只有一把 `mu`（`t.Record` 内部取），与 `punchManager.mu` **完全独立**。
//   - ⇒ 两者的锁序：**从不嵌套**。更强的保证：`peerTable` 的任何方法都不持有对
//     `punchManager`/`pathManager` 的引用 ⇒ 结构上不可能出现「持表锁再取管理器锁」的反向链
//     （即「表锁 → 管理器锁」这条边**不可能存在**），所以将来也不会因为新增表方法而产生锁序反转。
//   - ⚠️ 若将来真有地方需要在持 `punchManager.mu` 时写表，**必须先解锁再写**
//     （或把写表挪到这个 defer 的位置），不要图省事在锁内写 —— 那会凭空造出
//     「punchManager.mu → peerTable.mu」这条边，将来任一反向路径都会死锁。
//
// 只写「可写结果」四类（实施计划 §8-1 的裁决）：
//
//	探针成功            ⇒ 好 / 差（按 RTT 与探针丢包率）
//	probe-timeout / direct-lost / quality-poor ⇒ 差
//	nat-symmetric       ⇒ 不可打洞（**长 TTL**）
//	punch-timeout / peer-no-punch-addr        ⇒ 不可打洞（**短 TTL**）
//	其余一律**不写**
//
// ⚠️ 为什么「其余一律不写」——尤其 `peer-unreachable`：
//
//	对端离线**不反映链路质量**；写进去会让「对端下次上线时被误跳过」（用户明确强调过）。
//	同理 `peer-not-ready` / `attempt-timeout` / `local-no-punch-addr`（本机问题）/
//	`peer-busy` / `rate-limited`（对方忙）/ `cancelled`（用户取消）/
//	`fingerprint-mismatch`（安全事件）/ `server-p2p-disabled` / `direct-handshake-failed`
//	（协议/握手层，不是「这条路快不快」）。
func (m *punchManager) notePeerQuality(s *punchSession) {
	tbl := m.qualityTable()
	if tbl == nil {
		return // P2P 未生效 / 单测未注入 ⇒ 不记录（与「表为空」等价）
	}
	peer, ok := parseIPv4(s.peerVIP)
	if !ok {
		return
	}
	reason, _ := s.reason.Load().(string)
	natType, _ := s.peerNATType.Load().(string)
	addr, _ := s.peerAddr.Load().(string)

	switch reason {
	case P2PReasonOKDirect:
		got, total := int(s.probeGot.Load()), int(s.probeTotal.Load())
		loss := 0
		if total > 0 {
			loss = (total - got) * 100 / total
		}
		kind := peerGood
		// 「差」的判据**复用试用期的同一个常量**（review 追问 4）：
		// 试用期是「成功率 ≥ trialMinProbeSuccess(0.90) 才算好」，这里是它的补集
		// ⇒ 丢包率**必须**由同一常量推出来，不能另写一个 10%，否则将来改一边会忘另一边。
		if isPoorQualityLoss(loss) {
			kind = peerPoor
		}
		tbl.Record(peer, peerOutcome{
			Kind: kind, Reason: P2PReasonOKDirect,
			RTTMs: msAtLeast1(s.rttDirect.Load()), LossPct: loss,
			NatType: natType, Addr: addr,
		})
	case P2PReasonProbeTimeout, P2PReasonDirectLost, P2PReasonQualityPoor:
		tbl.Record(peer, peerOutcome{Kind: peerPoor, Reason: reason, LossPct: 100,
			NatType: natType, Addr: addr})
	case P2PReasonNATSymmetric, P2PReasonPunchTimeout, P2PReasonPeerNoPunchAddr:
		tbl.Record(peer, peerOutcome{Kind: peerUnpunchable, Reason: reason,
			NatType: natType, Addr: addr})
	default:
		// 其余原因不写表（见函数注释）
	}
}

func (m *punchManager) emit(st P2PStatus) {
	m.mu.Lock()
	h := m.onStatus
	m.mu.Unlock()
	if h != nil {
		h(st)
	}
}

// onPush 由信令读协程调用：**只投递，不阻塞**（满了就丢并记日志）
func (m *punchManager) onPush(msg signalMessage) {
	select {
	case m.pushCh <- msg:
	default:
		log.Printf("⚠️ [打洞] 推送队列已满，丢弃 %s（attempt=%s）", msg.Type, msg.AttemptID)
	}
}

// eventLoop 消费推送队列（push → 具体会话）
func (m *punchManager) eventLoop() {
	defer m.doneOnce.Do(func() { close(m.doneCh) })
	for {
		select {
		case <-m.ctx.Done():
			return
		case msg := <-m.pushCh:
			m.handlePush(msg)
		}
	}
}

func (m *punchManager) handlePush(msg signalMessage) {
	switch msg.Type {
	case signalMsgTypePunchInvite:
		m.handleInvite(msg)
	case signalMsgTypePunchBusy:
		m.handleBusyPush(msg)
	case signalMsgTypePunchPeer:
		m.mu.Lock()
		s := m.sessions[msg.AttemptID]
		m.mu.Unlock()
		if s == nil {
			log.Printf("ℹ️ [打洞] 收到无对应会话的 punch-peer（attempt=%s），忽略", msg.AttemptID)
			return
		}
		ap, ok := parsePunchAddr(msg.PunchAddr)
		if !ok {
			log.Printf("⚠️ [打洞] punch-peer 里的 punchAddr 非法: %q", msg.PunchAddr)
			return
		}
		// ⭐ 1b-3：候选列表（A1）+ 对端指纹（2.3）
		pr := peerReady{
			addr:  ap,
			addrs: peerAddrsFor(parsePunchAddrs(msg.PunchAddrs), ap),
			fp:    strings.TrimSpace(msg.DirectFingerprint),
		}
		select {
		case s.peerReadyCh <- pr:
		default:
		}
	default:
		log.Printf("ℹ️ [打洞] 忽略未知推送 %q", msg.Type)
	}
}

// handleBusyPush 处理 punch-busy（⭐1b-2B）：对端已满 → **立即**失败该 attempt。
//
// 早于本功能的行为是：服务端仍会推 invite，B 静默忽略，A 一直等到 40s 预算耗尽
// （原因码 `attempt-timeout`）。现在 A 在收到这条推送时立刻收工，原因码 `peer-busy`，
// 并按「忙」的短冷却（30s）而不是失败台阶重试。
//
// ⚠️ 幂等：服务端同时会回 `error: peer-busy`（推送丢失时的兜底），
// 所以本函数可能与「应答失败」竞争；用状态判断避免对同一会话重复 fail（会重复发事件）。
func (m *punchManager) handleBusyPush(msg signalMessage) {
	if msg.AttemptID == "" {
		return
	}
	m.mu.Lock()
	s := m.sessions[msg.AttemptID]
	m.mu.Unlock()
	if s == nil {
		// 不是我们正在等的 attempt（可能已结束）→ 忽略
		return
	}
	// 只处理「我在等它」的会话；已经拿到结果的不再改判
	if st, _ := s.state.Load().(string); st == P2PStateDirect || st == P2PStateFailed {
		return
	}
	log.Printf("ℹ️ [打洞] 对端忙（attempt=%s peer=%s），立即收工并 30s 内不重试",
		msg.AttemptID, s.peerVIP)
	s.fail(P2PReasonPeerBusy)
}

// handleInvite 处理 punch-invite：校验 → 建响应方会话
func (m *punchManager) handleInvite(msg signalMessage) {
	if !m.c.controlledP2PEnabled() {
		return
	}
	initiatorVIP := strings.TrimSpace(msg.PeerVIP)
	if initiatorVIP == "" || msg.AttemptID == "" {
		return
	}
	peerPunchAddr, ok := parsePunchAddr(msg.PunchAddr)
	if !ok || !peerPunchAddr.IsValid() {
		log.Printf("⚠️ [打洞] 邀请里的 punchAddr 非法: %q", msg.PunchAddr)
		return
	}
	meta, err := punchMetadataFromSeed(msg.Metadata)
	if err != nil {
		log.Printf("⚠️ [打洞] 邀请里的 seed 非法: %v", err)
		return
	}
	if msg.DirectFingerprint == "" {
		log.Printf("⚠️ [打洞] 邀请缺少直连指纹，拒绝")
		return
	}

	now := time.Now()
	m.mu.Lock()
	// ⭐ 按 attemptId 去重：服务端在「重复 punch-intent」时会**重推邀请**（幂等语义），
	//    同一条邀请被推两次不能变成两次打洞（会占两条 socket、翻倍发包）。
	if _, dup := m.sessions[msg.AttemptID]; dup {
		m.mu.Unlock()
		log.Printf("ℹ️ [打洞] 收到重复邀请（同一 attemptId=%s），忽略", msg.AttemptID)
		return
	}
	// ⭐ 1b-2A：让路 —— 如果本机正在为这个对端「等对方先发起」，收到邀请立即让路
	if pm := m.pathMgrRef(); pm != nil {
		pm.notifyInboundInvite(initiatorVIP)
	}
	if last, ok := m.lastInvite[initiatorVIP]; ok && now.Sub(last) < punchSamePeerGuard {
		m.mu.Unlock()
		log.Printf("ℹ️ [打洞] %s 的邀请过于频繁，忽略", initiatorVIP)
		return
	}
	if m.responders >= punchMaxResponder {
		m.mu.Unlock()
		log.Printf("ℹ️ [打洞] 作为响应方已达并发上限(%d)，忽略 %s 的邀请", punchMaxResponder, initiatorVIP)
		return
	}
	if existing, ok := m.byPeer[initiatorVIP]; ok && existing.role == "initiator" {
		// 双向同时发起：允许（设计 §3.5 已知浪费场景），但记一条日志
		log.Printf("ℹ️ [打洞] 与 %s 双向同时发起，各自独立进行", initiatorVIP)
	}
	m.responders++
	m.lastInvite[initiatorVIP] = now
	m.mu.Unlock()

	s := m.newSession(msg.AttemptID, initiatorVIP, "responder", msg.WindowMs, msg.Metadata, msg.DirectFingerprint, peerPunchAddr)
	// ⭐ 1b-3（A1）：对端（A）的候选列表；旧对端为空 ⇒ 只有单地址
	s.peerPunchAddrs = peerAddrsFor(parsePunchAddrs(msg.PunchAddrs), peerPunchAddr)
	s.trigger = P2PTriggerRemote
	m.mu.Lock()
	m.sessions[s.id] = s
	m.mu.Unlock()
	m.jobs.Add(1)
	go func() {
		defer m.jobs.Done()
		defer func() {
			m.mu.Lock()
			delete(m.sessions, s.id)
			m.responders--
			m.mu.Unlock()
		}()
		s.runResponder(meta)
	}()
}

func (m *punchManager) newSession(id, peerVIP, role string, windowMs int, seed, peerFP string, peerPunchAddr netip.AddrPort) *punchSession {
	budget := m.budget
	if budget <= 0 {
		budget = punchAttemptBudget
	}
	ctx, cancel := context.WithTimeout(m.ctx, budget)
	s := &punchSession{
		mgr:           m,
		id:            id,
		peerVIP:       peerVIP,
		role:          role,
		windowMs:      clampPunchWindow(windowMs),
		seed:          seed,
		peerFP:        peerFP,
		peerPunchAddr: peerPunchAddr,
		ctx:           ctx,
		cancel:        cancel,
		startedAt:     time.Now(),
		tuning:        m.tuning,
		peerReadyCh:   make(chan peerReady, 1),
		doneCh:        make(chan struct{}),
	}
	s.state.Store(P2PStateQuerying)
	return s
}

// ---------- A 侧（发起方） ----------

// PunchTo 发起一次打洞（异步；返回 attemptId 供 UI/日志关联）。
// 触发来源记为 manual（用户在面板/控制台手动点名）。
func (m *punchManager) PunchTo(peerVIP string) (string, error) {
	return m.PunchWithTrigger(peerVIP, P2PTriggerManual)
}

// PunchWithTrigger 与 PunchTo 相同，但记录**触发来源**（traffic/config/manual）。
//
// ⭐ 1b-2A：流量驱动由 pathManager 调用（trigger=traffic）；
// 手动/配置驱动复用同一条路径，限流、冷却、预算门全部一致。
func (m *punchManager) PunchWithTrigger(peerVIP, trigger string) (string, error) {
	peerVIP = strings.TrimSpace(peerVIP)
	if peerVIP == "" {
		return "", fmt.Errorf("对端 VIP 不能为空")
	}
	// ⭐⭐ B3（2026-09-27）：**重复打洞抑制** —— 已有「可用」路径时，流量驱动不再打洞。
	//
	// 为什么需要（根因）：**试用期路径不占路由槽位、也不承载流量**（数据仍走中继）
	// ⇒ 流量会继续触发打洞；而 `byPeer` 只挡「同一个会话在飞」，打洞成功后会话结束、
	// `byPeer` 清空，可 trial 路径还要跑十几秒 ⇒ 同一对端被反复发起 attempt。
	//
	// 语义（review 拍板）：**只对 `P2PTriggerTraffic` 生效** —— 手动/配置触发是用户点名，
	// 必须照做（否则「用户点直连没反应」）。`HasUsablePath` 的口径见其注释（Up/Trial 算，
	// Standby/Down 不算）。
	//
	// ⚠️ 竞态：查到「有路径」与「路径消失」之间不做 CAS —— 启发式抑制，最多延迟一拍。
	// ⚠️ 锁序：本检查必须在 `m.mu.Lock()` **之前**（避免构造 punchManager.mu → pathManager 锁 的边）。
	// ⚠️ 只记日志、不写任何退避：返回哨兵错误 `errPunchDupPath`，由 `attemptFor` 识别并**跳过退避**
	//    （否则每次流量触发都推一档 ⇒ 越试越难，比不抑制更差）。
	if trigger == P2PTriggerTraffic {
		if dst, ok := parseIPv4(peerVIP); ok {
			if pm := m.pathMgr.Load(); pm != nil {
				if usable, st := pm.HasUsablePath(dst); usable {
					n := m.skippedDupPunch.Add(1)
					log.Printf("ℹ️ [打洞] %s 已有可用路径（state=%s），跳过重复打洞（累计第 %d 次）",
						peerVIP, st, n)
					return "", fmt.Errorf("已有可用路径（state=%s）: %w", st, errPunchDupPath)
				}
			}
		}
	}
	if !m.c.controlledP2PEnabled() {
		return "", fmt.Errorf("P2P 未启用（服务端开关=%v）", m.c.P2PServerEnabled())
	}
	if _, _, ok := m.c.signalSelfInfo(); !ok {
		return "", fmt.Errorf("NAT 探测尚未完成或未取得公网地址，无法发起打洞")
	}

	now := time.Now()
	m.mu.Lock()
	if until, ok := m.cooldown[peerVIP]; ok && now.Before(until) {
		left := time.Until(until).Round(time.Second)
		m.mu.Unlock()
		// ⭐ 1b-4 第 3 步：**必须包装哨兵**。否则 `pathManager.attemptFor` 用 errors.Is
		//    识别不到「冷却期内」，会再写一个固定 30s 退避 ⇒ 长档（60s/120s/5min）被盖住，
		//    且退化成「每 30s 空转 + 档位虚涨」（见 errPunchCooldown 的说明）。
		return "", fmt.Errorf("该对端刚失败过，%v 后可重试: %w", left, errPunchCooldown)
	}
	if _, busy := m.byPeer[peerVIP]; busy {
		m.mu.Unlock()
		return "", fmt.Errorf("已在向该对端发起打洞")
	}
	id, err := newAttemptID()
	if err != nil {
		m.mu.Unlock()
		return "", err
	}
	seed, err := newPunchSeed()
	if err != nil {
		m.mu.Unlock()
		return "", err
	}
	window := m.windowDefault
	if window <= 0 {
		window = punchWindowDefault
	}
	s := m.newSession(id, peerVIP, "initiator", window, seed, "", netip.AddrPort{})
	s.trigger = trigger
	m.sessions[id] = s
	m.byPeer[peerVIP] = s
	m.mu.Unlock()

	m.jobs.Add(1)
	go func() {
		defer m.jobs.Done()
		defer func() {
			m.mu.Lock()
			delete(m.sessions, id)
			delete(m.byPeer, peerVIP)
			// ⭐ 1b-4 第 3 步：冷却与 streak 一起算（都在同一临界区内，保证原子）
			m.cooldown[peerVIP] = time.Now().Add(m.noteSessionOutcomeLocked(s))
			m.mu.Unlock()
			// ⭐ 1b-4 第 2 步-A：把本次打洞的**结果**写进对端质量表。
			//    ⚠️ 必须在 mu 之外（`Record` 内部取表的锁；持 m.mu 调它会形成
			//    「punchManager.mu → peerTable.mu」的锁序，虽当前无人反向取锁，
			//    但保持「锁内只碰本结构」这条既有纪律更安全）。
			m.notePeerQuality(s)
		}()
		s.runInitiator()
	}()
	return id, nil
}

// noteSessionOutcomeLocked 会话收尾时算「本次冷却多长」，并维护 busy/rate 的独立 streak。
//
// ⚠️ 调用方必须已持 m.mu（冷却与 streak 必须原子更新，否则并发收尾会互相覆盖）。
//
// 语义（实施计划 §7.2 + review 追问 3）：
//
//	succeed()（**打洞 + 握手 + 探针至少一个往返成功** ⇒ 直连真的可用）
//	    ⇒ **两条 streak 都清零**，不设冷却（成功会走 handoverToPath，路径由 pathManager 接管）
//	peer-busy     ⇒ busyPeerStreak 按小台阶（30s→60s→120s→5min）
//	rate-limited  ⇒ rateStreak 按**同一条台阶**（但**各自计数**，见 ladderForBusy 注释）
//	其它失败       ⇒ **两条 streak 都清零**，用 punchCooldown(60s)
//
// ⭐ 「成功」的判据为什么是**会话级成功**而不是「稳定 ≥5min」（review 追问 3 的明确答复）：
//
//  1. **语义匹配**：「忙」是**秒级瞬时**状态（台阶从 30s 起）。一次「打洞+握手+探针」
//     全通说明对端**此刻有余力** ⇒ 「它现在不忙」这个结论已经成立；再要求 5 分钟等于
//     把「瞬时状态」当成「长期状态」，反而会让 streak 在多数场景下**永不清零**。
//     （对比：pathManager 的 step/qualityStep 管的是「长期失败历史」，5min 是对它的正确判据。）
//  2. **结构上做不到**：`punchManager` 在**会话结束**时就写冷却，那时路径刚建立、
//     根本不存在任何「已稳定 5 分钟」的事实；跨会话保留 streak 又要引入「路径存活时长」
//     的跨管理器状态（punchManager ↔ pathManager 反向依赖），代价远大于收益。
//  3. **担心的场景已被别的机制兜住**：「成功 ⇒ 清零，3 秒后路径断了 ⇒ 下次又遇同一忙对端」
//     的后果只是「这次从 30s 起算」。而**路径断了本身**会由 pathManager 记退避
//     （`demote` → `scheduleRetry`，走「打洞失败/质量差」台阶）⇒ 不会形成快速重试环。
//  4. ⚠️ 因此这是一条**有意的设计选择**，不是遗漏。若将来发现真机上有「忙/不忙高频交替」
//     的病态对端，正确做法是给 busy 台阶加**最小重试间隔**（或提高封顶），而不是把清零判据
//     换成 5 分钟。
func (m *punchManager) noteSessionOutcomeLocked(s *punchSession) time.Duration {
	reason, _ := s.reason.Load().(string)
	if s.succeeded.Load() {
		// 成功：清零两条 streak（不设冷却——成功会走 handoverToPath，路径由 pathManager 接管）
		m.pruneBusyLocked(time.Now())
		delete(m.busyPeerStreak, s.peerVIP)
		delete(m.rateStreak, s.peerVIP)
		return 0
	}
	return m.bumpBusyStreakLocked(s.peerVIP, reason)
}

func (s *punchSession) runInitiator() {
	defer s.cancel()

	// ① Querying（上限 2 次尝试；预算门在剩余不足时跳过重试）
	peer, err := s.queryWithRetry()
	if err != nil {
		if s.remaining() < punchStageFloor {
			s.fail(P2PReasonAttemptTimeout)
		} else {
			s.fail(P2PReasonPeerUnreachable)
		}
		return
	}
	if !peer.Online {
		s.fail(P2PReasonPeerUnreachable)
		return
	}
	if !peer.SignalReady {
		s.fail(P2PReasonPeerNotReady)
		return
	}

	// ② NAT 预检（⭐1b-3：从「双方都要非对称」放宽为「至多一侧对称」）
	//
	// 背景（1b-3 的核心改动）：1b-1/1b-2B 在这里**直接拒绝**「任一侧是 symmetric」，
	// 于是国内大量 NAT4 用户连试都不试（原因码 nat-symmetric）。
	// 实际机制上，**NAT4 + NAT1-3 是可打的**：对称 NAT 的那一侧向 cone 侧发包会建立
	// 「到 cone 侧」的映射，cone 侧收到后按 realm 的语义**回 Ack 到观测到的源地址**
	// （正是对称侧的真实对外映射）⇒ 对称侧就能收到回包，洞就通了。
	//
	// 仍然**不承诺** NAT4 + NAT4（硬限制，写进文档）：双方端口都在变，
	// 互相只能靠预测，命中率极低 ⇒ 如实回落中继（原因码 nat-symmetric）。
	ownType := string(s.mgr.c.NATType())
	peerType := peer.NATType
	// ⭐ 1b-4 第 2 步-A：记下对端 NAT 类型/地址（写质量表时带上；纯诊断信息）
	s.peerNATType.Store(peerType)
	s.peerAddr.Store(peer.PublicAddr)
	if ownType == string(NATSymmetric) && peerType == string(NATSymmetric) {
		s.fail(P2PReasonNATSymmetric)
		return
	}
	if ownType == "" || ownType == string(NATUnknown) ||
		peerType == "" || peerType == string(NATUnknown) {
		s.fail(P2PReasonNATUnknown)
		return
	}
	if ownType == string(NATSymmetric) || peerType == string(NATSymmetric) {
		// 一侧对称：允许尝试，但要**显式记一条日志**（排障时一眼看出走的是 1b-3 的放宽路径）
		log.Printf("ℹ️ [打洞] 一侧是对称 NAT（本机=%s 对端=%s）：按 1b-3 放宽策略尝试直连"+
			"（成功与否取决于端口预测，NAT4+NAT4 才会直接放弃）", ownType, peerType)
	}

	// ③ Discovering：punch socket + STUN
	if !s.openSocket() {
		return
	}
	addrs, err := s.discover()
	if err != nil || len(addrs) == 0 {
		s.fail(P2PReasonLocalNoPunchAddr)
		return
	}
	// ⭐ 归一化由会话负责（不依赖注入的 discover 实现）：去重/排序/只留 IPv4/截断到上限。
	//    排序后 punchAddr = 端口最小的那个；realm 的对称 NAT 扩展也从最小端口起算。
	observed := normalizePunchAddrs(addrs)
	if len(observed) == 0 {
		s.fail(P2PReasonLocalNoPunchAddr)
		return
	}
	// ⭐ 1b-3（2.2）：由观测值预测「对端方向」的端口（对称 NAT），一起广告出去
	//
	// ⭐ 1b-4 第 2 步-A（bug #3）：**加 NAT 类型门** —— 只有本机是 symmetric 才预测；
	//    cone 只广告观测值（观测值本身就是对端可达地址，多广告的候选纯噪声）。
	//    判据唯一入口 = candidatesForNATType（两侧共用，避免只改一侧）。
	adv := candidatesForNATType(s.mgr.c.NATType(), observed)
	if s.mgr.noPredict {
		adv = observed
	}
	s.myPunchAddrs = adv
	if len(s.myPunchAddrs) == 0 {
		s.myPunchAddrs = observed
	}
	s.myPunchAddr = s.myPunchAddrs[0]
	if len(s.myPunchAddrs) > len(observed) {
		log.Printf("🎯 [打洞] 端口预测：观测 %d 个 → 候选 %d 个（对称 NAT 端口预测；"+
			"观测=%s 候选=%s）", len(observed), len(s.myPunchAddrs),
			strings.Join(punchAddrStrings(observed), " "),
			strings.Join(punchAddrStrings(s.myPunchAddrs), " "))
	}

	// ④ IntentSent
	resp, code, ok := s.sendIntentWithRetry()
	if !ok {
		s.fail(code)
		return
	}
	_ = resp

	// ⑤ 等 punch-peer（按剩余预算截断）
	wait, ok := s.stageTimeout(s.tuning.readyWait)
	if !ok {
		s.fail(P2PReasonAttemptTimeout)
		return
	}
	select {
	case pr := <-s.peerReadyCh:
		if !pr.addr.IsValid() {
			s.fail(P2PReasonPeerNoPunchAddr)
			return
		}
		s.peerPunchAddr = pr.addr
		s.peerPunchAddrs = peerAddrsFor(pr.addrs, pr.addr) // ⭐ 1b-3（A1）：候选列表
		// ⭐ 1b-3（2.3）：拿到 B 的指纹 → 本侧作为 listener 也固定 B（双向固定）。
		//   旧对端不发 ⇒ 保持空 ⇒ 退回单向固定（等价 1b-1），只记一条日志。
		if pr.fp != "" {
			s.mu.Lock()
			s.peerFP = pr.fp
			s.mu.Unlock()
		} else {
			log.Printf("ℹ️ [打洞] 对端未提供直连指纹（旧版本），本次仅单向固定（等价 1b-1）")
		}
	case <-time.After(wait):
		s.fail(P2PReasonAttemptTimeout)
		return
	case <-s.ctx.Done():
		s.fail(P2PReasonCancelled)
		return
	}
	s.runCommonTail(true)
}

// listenerTLSConfig 构造 A 侧（QUIC listener）的 TLS 配置。
//
// ⭐ 1b-3（2.3 双向指纹固定 / Q2）：1b-1 是**单向**固定 —— B 拨号时固定 A 的指纹（Q1），
// 而 A 只要求「出示任意证书」（RequireAnyClientCert），不校验 B 的身份。
// 现在 B 通过 `punch-ready.directFingerprint` 把自己的指纹交给服务端转发给 A（punch-peer），
// A 拿到后就**同时**固定 B；拿不到（旧对端）则保持 1b-1 的单向语义（不是失败，只记日志）。
//
// ⚠️ 时序说明：punch-peer 是推送，理论上可能晚于 A 开始监听 ⇒ 此时 s.peerFP 还是空，
// 本次退回单向固定。这是**如实降级**，不影响连通性（下次尝试或新版本对端即生效）。
func (s *punchSession) listenerTLSConfig(cert tls.Certificate) *tls.Config {
	s.mu.Lock()
	peerFP := s.peerFP
	s.mu.Unlock()
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// 必须先要求对端出示证书：VerifyPeerCertificate 才拿得到 rawCerts
		ClientAuth: tls.RequireAnyClientCert,
		NextProtos: []string{alpnDirect},
	}
	if peerFP != "" {
		conf.VerifyPeerCertificate = pinDirectFingerprint(peerFP)
	}
	return conf
}

// queryWithRetry 查询对端（复用 1a 的 SignalQuery）
func (s *punchSession) queryWithRetry() (SignalPeer, error) {
	s.setState(P2PStateQuerying)
	var lastErr error
	for i := 0; i <= punchQueryRetries; i++ {
		peer, err := s.mgr.c.SignalQuery(s.peerVIP)
		if err == nil {
			return peer, nil
		}
		lastErr = err
		if i == punchQueryRetries {
			break
		}
		backoff := time.Duration(300*(i+1)) * time.Millisecond
		if !s.canRetry(punchQueryTimeout + backoff) {
			log.Printf("ℹ️ [打洞] 剩余预算不足，跳过查询重试（attempt=%s）", s.id)
			break
		}
		select {
		case <-time.After(backoff):
		case <-s.ctx.Done():
			return SignalPeer{}, s.ctx.Err()
		}
	}
	return SignalPeer{}, lastErr
}

// openSocket 开 punch socket
func (s *punchSession) openSocket() bool {
	s.setState(P2PStateDiscovering)
	sock, err := s.mgr.openPunchSocket()
	if err != nil {
		log.Printf("⚠️ [打洞] 创建 punch socket 失败: %v", err)
		s.fail(P2PReasonLocalNoPunchAddr)
		return false
	}
	s.mu.Lock()
	s.sock = sock
	s.mu.Unlock()
	return true
}

// discover 找自己 punch socket 的公网地址（⭐1b-3：返回**全部**观测，不再只留第一个）
func (s *punchSession) discover() ([]netip.AddrPort, error) {
	timeout, ok := s.stageTimeout(s.tuning.stun)
	if !ok {
		return nil, fmt.Errorf("预算不足")
	}
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()
	return s.mgr.discoverPunchAddr(ctx, s.sock)
}

// defaultDiscoverPunchAddr 用 realm.Discover 在这条 socket 上做 STUN。
//
// ⭐ 1b-3（A1）两处改动：
//  1. STUN 列表换成 `stunServerList()` —— **服务端内置端点（3478/3479）优先**、
//     公共 STUN 兜底。国内公共 STUN 经常不可达，而内置端点必然可达；
//  2. **保留全部观测值**（realm.Discover 本来就返回多个），不再只取第一个 ——
//     这是让 realm 的对称 NAT 端口预测真正生效的前提（需要同 IP 的 ≥2 个相邻端口）。
func (m *punchManager) defaultDiscoverPunchAddr(ctx context.Context, sock net.PacketConn) ([]netip.AddrPort, error) {
	servers := m.c.stunServerList()
	if len(servers) == 0 {
		return nil, fmt.Errorf("没有可用的 STUN 端点")
	}
	addrs, err := realm.Discover(ctx, sock, realm.STUNConfig{
		Servers: servers,
		Timeout: punchPerServerTimeout,
		Family:  realm.AddrFamilyIPv4,
	})
	if err != nil {
		return nil, err
	}
	out := normalizePunchAddrs(addrs)
	if len(out) == 0 {
		return nil, fmt.Errorf("STUN 未返回可用的 IPv4 映射（观测到 %d 条）", len(addrs))
	}
	if len(out) > 1 {
		log.Printf("🌐 [打洞] 本机 punch socket 观测到 %d 个映射: %s（全部广告给对端，供对称 NAT 端口预测）",
			len(out), strings.Join(punchAddrStrings(out), " "))
	}
	return out, nil
}

// sendIntentWithRetry 发 punch-intent（上限 2 次尝试）
func (s *punchSession) sendIntentWithRetry() (SignalPeer, string, bool) {
	s.setState(P2PStateIntent)
	cert, fp, err := s.mgr.c.ensureDirectCert()
	if err != nil {
		log.Printf("⚠️ [打洞] 生成直连证书失败: %v", err)
		return SignalPeer{}, P2PReasonDirectHandshakeFailed, false
	}
	s.myFP = fp
	_ = cert

	addr, _, _ := s.mgr.c.signalSelfInfo()
	msg := signalMessage{
		Type:              signalMsgTypePunchIntent,
		AttemptID:         s.id,
		PeerVIP:           s.peerVIP,
		PublicAddr:        addr,
		NATType:           string(s.mgr.c.NATType()),
		Metadata:          s.seed,
		PunchAddr:         s.myPunchAddr.String(),
		PunchAddrs:        punchAddrStrings(s.myPunchAddrs), // ⭐ 1b-3（A1）：全部候选
		DirectFingerprint: fp,
		WindowMs:          s.windowMs,
	}
	var lastErr error
	for i := 0; i <= punchIntentRetries; i++ {
		resp, err := s.mgr.c.signalRoundTrip(msg)
		if err == nil {
			return SignalPeer{
				VIP:         s.peerVIP,
				Online:      resp.PeerOnline,
				PublicAddr:  resp.PeerPublicAddr,
				NATType:     resp.PeerNATType,
				Metadata:    resp.PeerMetadata,
				SignalReady: resp.PeerSignalReady,
			}, "", true
		}
		lastErr = err
		if i == punchIntentRetries {
			break
		}
		backoff := time.Duration(500*(i+1)) * time.Millisecond
		if !s.canRetry(punchQueryTimeout + backoff) {
			log.Printf("ℹ️ [打洞] 剩余预算不足，跳过 intent 重试（attempt=%s）", s.id)
			break
		}
		select {
		case <-time.After(backoff):
		case <-s.ctx.Done():
			return SignalPeer{}, P2PReasonCancelled, false
		}
	}
	code := P2PReasonAttemptTimeout
	if lastErr != nil {
		code = classifyServerRefusal(lastErr.Error())
	}
	return SignalPeer{}, code, false
}

// classifyServerRefusal 把服务端拒绝映射成原因码（设计 §10.2）
func classifyServerRefusal(msg string) string {
	switch {
	case strings.Contains(msg, "rate-limited"):
		return P2PReasonRateLimited
	case strings.Contains(msg, "peer-not-ready"):
		return P2PReasonPeerNotReady
	case strings.Contains(msg, "peer-unreachable"):
		return P2PReasonPeerUnreachable
	case strings.Contains(msg, "pair-busy"), strings.Contains(msg, "pair-cooldown"):
		return P2PReasonPeerBusy
	case strings.Contains(msg, "超时"):
		return P2PReasonAttemptTimeout
	default:
		return P2PReasonPeerNotReady
	}
}

// ---------- B 侧（响应方） ----------

func (s *punchSession) runResponder(meta realm.PunchMetadata) {
	defer s.cancel()

	// ① PreparingSTUN：开 socket + 找自己的 punchAddr（独立超时/失败出口）
	if !s.openSocket() {
		return // fail 已在内部处理（原因码 local-no-punch-addr）
	}
	if addrs, err := s.discover(); err == nil && len(addrs) > 0 {
		// ⭐ 1b-3：归一化 + 端口预测（对称 NAT）都由会话负责
		// ⭐ 1b-4 第 2 步-A（bug #3）：**同一道 NAT 类型门**（响应方这一侧原先也是无条件预测）
		s.myPunchAddrs = candidatesForNATType(s.mgr.c.NATType(), addrs)
		if s.mgr.noPredict {
			s.myPunchAddrs = normalizePunchAddrs(addrs)
		}
		if len(s.myPunchAddrs) > 0 {
			s.myPunchAddr = s.myPunchAddrs[0]
		}
	} else {
		log.Printf("ℹ️ [打洞] 本机 punch 地址发现失败，仍继续打洞（A 侧会立即收工）: %v", err)
	}

	// ⭐ 1b-3（2.3）：响应方也必须把自己的直连指纹准备好 —— punch-ready 会带上它，
	//    服务端转给 A，A 才能在 listener 侧也固定 B（双向固定）。
	//    ⚠️ 必须在**发 punch-ready 之前**拿（下面那个 goroutine 与打洞并发），
	//    否则 punch-ready 里的指纹是空的，A 只会退回单向固定（实测踩到过：日志显示
	//    「对端未提供直连指纹（旧版本）」而两端其实都是新版本）。
	if _, fp, err := s.mgr.c.ensureDirectCert(); err == nil {
		s.myFP = fp
	} else {
		log.Printf("⚠️ [打洞] 生成直连证书失败（本次无法提供指纹）: %v", err)
	}

	// ② 并发发 punch-ready（带重试）——绝不能阻塞打洞
	readyDone := make(chan struct{})
	go func() {
		defer close(readyDone)
		s.sendReadyWithRetry()
	}()

	// ③ 打洞（B 是响应方，目标地址来自 invite）
	s.setState(P2PStatePunching)
	s.runCommonTail(false)

	select {
	case <-readyDone:
	case <-time.After(time.Second):
	}
}

// sendReadyWithRetry 回报 punch-ready（首次 + 最多 2 次重发）；失败不致命
func (s *punchSession) sendReadyWithRetry() {
	addr, _, _ := s.mgr.c.signalSelfInfo()
	gaps := []time.Duration{0, punchReadyGap1, punchReadyGap2}
	for i := 0; i < punchReadyRetries; i++ {
		if i > 0 {
			select {
			case <-time.After(gaps[i]):
			case <-s.ctx.Done():
				return
			}
		}
		_, err := s.mgr.c.signalRoundTrip(signalMessage{
			Type:              signalMsgTypePunchReady,
			AttemptID:         s.id,
			PeerVIP:           s.peerVIP,
			PublicAddr:        addr,
			NATType:           string(s.mgr.c.NATType()),
			PunchAddr:         s.myPunchAddr.String(),
			PunchAddrs:        punchAddrStrings(s.myPunchAddrs), // ⭐ 1b-3（A1）
			DirectFingerprint: s.myFP,                           // ⭐ 1b-3（2.3）：双向固定
		})
		if err == nil {
			return
		}
		log.Printf("⚠️ [打洞] punch-ready 第 %d 次失败: %v", i+1, err)
	}
	log.Printf("ℹ️ [打洞] punch-ready 三次都没送达（B 继续打洞，A 侧可能超时）")
}

// ---------- 共同尾段：打洞 → 握手 → 探针 ----------

func (s *punchSession) runCommonTail(isInitiator bool) {
	// ④ 打洞门（规则④）：绝不能起一个注定完不成的打洞
	handshakeNeed := s.tuning.handshake + time.Second
	rem := s.remaining()
	if rem < time.Duration(s.windowMs)*time.Millisecond+handshakeNeed {
		s.fail(P2PReasonAttemptTimeout)
		return
	}
	s.setState(P2PStatePunching)

	meta, err := punchMetadataFromSeed(s.seed)
	if err != nil {
		s.fail(P2PReasonSessionExpired)
		return
	}
	window := time.Duration(s.windowMs) * time.Millisecond
	if maxWindow := s.remaining() - handshakeNeed; window > maxWindow {
		window = maxWindow
	}
	ctx, cancel := context.WithTimeout(s.ctx, window)
	defer cancel()

	localAddrs := []netip.AddrPort{}
	if len(s.myPunchAddrs) > 0 {
		localAddrs = append(localAddrs, s.myPunchAddrs...) // ⭐ 1b-3：全部观测（供 realm 判定地址族）
	} else if s.myPunchAddr.IsValid() {
		localAddrs = append(localAddrs, s.myPunchAddr)
	}
	// ⭐ 1b-3（A1）：把**对端候选列表**交给 realm —— 它会向每个候选发包，
	//    并在「同一 IP 的 ≥2 个相邻端口（差 ≤4）」时自动扩展预测端口（对称 NAT）。
	peerTargets := s.peerPunchAddrs
	if len(peerTargets) == 0 {
		peerTargets = []netip.AddrPort{s.peerPunchAddr}
	}
	if len(peerTargets) > 1 {
		log.Printf("🎯 [打洞] 目标候选 %d 个: %s（对称 NAT 端口预测会在此之上扩展）",
			len(peerTargets), strings.Join(punchAddrStrings(peerTargets), " "))
	}
	// ⭐ 交接不变量：Punch 期间它独占 socket 读，交付 QUIC 前必须归零
	//    （TestPunchSocketHandoverRace 用并发读探针验证这一点）
	s.punchActive.Store(true)
	res, err := realm.Punch(ctx, s.sock, localAddrs, peerTargets, meta, realm.PunchConfig{
		Timeout:  window,
		Interval: punchInterval,
		Family:   realm.AddrFamilyIPv4,
	})
	s.punchActive.Store(false)
	if err != nil {
		log.Printf("ℹ️ [打洞] 打洞未成功（%s，对端 %v）: %v", s.role, s.peerPunchAddr, err)
		s.fail(P2PReasonPunchTimeout)
		return
	}
	// ⭐ 期望地址用「包实际来自的地址」（比广告地址更可信）
	peerAddr := netip.AddrPortFrom(res.PeerAddr.Addr().Unmap(), res.PeerAddr.Port())
	log.Printf("📡 [打洞] 打洞成功（%s）：对端实测地址 %v", s.role, peerAddr)

	// ⑤ 握手（A 监听 / B 拨号）
	if !s.handshake(peerAddr, isInitiator) {
		return
	}

	// ⑥ 探针
	if isInitiator {
		s.serveProbe()
	} else {
		s.runProbe()
	}
}

// handshake A 侧监听、B 侧拨号（Q1：B 固定 A 的指纹）
func (s *punchSession) handshake(peerAddr netip.AddrPort, isInitiator bool) bool {
	timeout, ok := s.stageTimeout(s.tuning.handshake)
	if !ok {
		s.fail(P2PReasonAttemptTimeout)
		return false
	}
	s.setState(P2PStateHandshaking)

	cert, myFP, err := s.mgr.c.ensureDirectCert()
	if err != nil {
		log.Printf("⚠️ [HARP] 获取直连证书失败: %v", err)
		s.fail(P2PReasonDirectHandshakeFailed)
		return false
	}
	if isInitiator {
		s.myFP = myFP
	}

	filter := newPeerFilterConn(s.sock, peerAddr)
	// ⭐ 交接不变量（BUG-B 类问题）：打洞已结束，socket 现在只属于 QUIC。
	//    真出现「打洞还在读、QUIC 也来读」就成了两个读者，必须直接判失败。
	if s.punchActive.Load() {
		log.Printf("💥 [HARP] 交接顺序错误：打洞仍在读 socket（%s）", s.role)
		s.fail(P2PReasonDirectHandshakeFailed)
		return false
	}
	s.mu.Lock()
	s.filter = filter
	s.mu.Unlock()

	quicCfg := &quic.Config{
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      5 * time.Second,
		HandshakeIdleTimeout: timeout,
		// 4 条入向流上限：直连数据面只用 2 条（数据流 + 控制流），留 2 条余量。
		// ⚠️ 1b-2A 原来想抬到 8（当时计划「每平面一条流」），改成
		//    「1 条数据流 + 每帧平面标签」后不需要了 —— 保持 1b-1 定稿值不动。
		MaxIncomingStreams: 4,
		InitialPacketSize:  1400,
		// ⭐ 1b-2A：不可靠 UDP 平面要在直连上继续「不可靠」（丢包不重排），
		//    所以必须开 datagram 扩展；两端用同一份配置，等价于双方都开。
		EnableDatagrams: true,
	}
	transport := &quic.Transport{Conn: filter}
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()

	if isInitiator {
		// A = QUIC 服务端（只放行打洞学到的对端地址，见 peerFilterConn）
		tlsConf := s.listenerTLSConfig(cert) // ⭐ 1b-3（2.3）：抽出以便单测「双向固定」
		ln, err := transport.Listen(tlsConf, quicCfg)
		if err != nil {
			_ = transport.Close()
			log.Printf("⚠️ [HARP] 监听 punch socket 失败: %v", err)
			s.fail(P2PReasonDirectHandshakeFailed)
			return false
		}
		// ⭐ 时序修复：打洞刚结束时对端可能已经在拨号了，而此刻 QUIC 还没开始读
		//    socket —— 对端的首个 Initial 会被丢掉，只能等 RTO 重传（最坏 1s+）。
		//    所以监听就绪后立刻用裸 UDP 通知对端「我在听了」，对端据此决定何时拨号。
		s.notifyListening(peerAddr)
		// ⭐ Accept 要**循环**等：对端第一次拨号可能赶在我们监听就绪之前，
		//    那个半成品连接随后会被它自己放弃（换新的连接 ID 重拨）——
		//    这时 Accept 会返回一个错误/一条注定失败的连接。
		//    只要预算没到就继续等下一拨，不要因为这种时序问题判整个 attempt 失败。
		var conn *quic.Conn
		var acceptErr error
		for ctx.Err() == nil {
			c, err := ln.Accept(ctx)
			if err == nil {
				conn = c
				break
			}
			acceptErr = err
			if ctx.Err() != nil {
				break
			}
			log.Printf("ℹ️ [HARP] 接受连接失败，继续等待下一拨（%v）", err)
		}
		if conn == nil {
			_ = ln.Close()
			_ = transport.Close()
			log.Printf("⚠️ [HARP] 等待对端握手失败: %v", acceptErr)
			s.fail(P2PReasonDirectHandshakeFailed)
			return false
		}
		// 双保险：接受后再校验一次 RemoteAddr（同样 Unmap 归一化）
		if ap, ok := addrPortFromNetAddr(conn.RemoteAddr()); !ok || !sameAddrPort(ap, peerAddr) {
			_ = conn.CloseWithError(0, "unexpected peer")
			_ = ln.Close()
			_ = transport.Close()
			log.Printf("⚠️ [HARP] 握手来源地址不符：%v（期望 %v）", conn.RemoteAddr(), peerAddr)
			s.fail(P2PReasonDirectHandshakeFailed)
			return false
		}
		s.mu.Lock()
		s.transport, s.listener, s.conn = transport, ln, conn
		s.mu.Unlock()
	} else {
		// B = QUIC 客户端（固定 A 的指纹）
		// ⭐ 先等对方说「我已经在监听了」（等不到就按固定延迟照常拨号）：
		//    否则首个 Initial 可能打在一个还没开始读的 socket 上（见 notifyListening）。
		s.waitListening(peerAddr)
		// 结构性断言：必须「先结束裸读、再把 socket 交给 QUIC」，
		// 否则同一条 socket 会出现两个读者（BUG-B 类问题）。
		if !s.waitDone.Load() {
			log.Printf("💥 [HARP] 交接顺序错误：未等待就绪通知就直接拨号（%s）", s.role)
			_ = transport.Close()
			s.fail(P2PReasonDirectHandshakeFailed)
			return false
		}
		tlsConf := &tls.Config{
			Certificates:          []tls.Certificate{cert},
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: pinDirectFingerprint(s.peerFP),
			NextProtos:            []string{alpnDirect},
		}
		conn, err := transport.Dial(ctx, net.UDPAddrFromAddrPort(peerAddr), tlsConf, quicCfg)
		if err != nil && !isFingerprintErr(err) {
			// ⭐ 拨号重试一次：打洞刚结束时对端的 QUIC listener 可能还没就绪，
			//    首个 Initial 会石沉大海（虽然可用监听就绪通知缓解，但通知本身也可能
			//    比 `punchDialWait`(500ms) 的上限晚到 —— 设计 §2.6 定这个 500ms；
			//    1b-1 曾是 200ms）。这里再等一小会儿重拨，覆盖这个时间窗。
			log.Printf("ℹ️ [HARP] 首次拨号失败，稍后重试一次: %v", err)
			select {
			case <-time.After(300 * time.Millisecond):
			case <-ctx.Done():
			}
			if ctx.Err() == nil {
				conn, err = transport.Dial(ctx, net.UDPAddrFromAddrPort(peerAddr), tlsConf, quicCfg)
			}
		}
		if err != nil {
			_ = transport.Close()
			if isFingerprintErr(err) {
				s.fail(P2PReasonFingerprintMismatch)
			} else {
				log.Printf("⚠️ [HARP] 拨号失败: %v", err)
				s.fail(P2PReasonDirectHandshakeFailed)
			}
			return false
		}
		s.mu.Lock()
		s.transport, s.conn = transport, conn
		s.mu.Unlock()
	}

	// 记录 QUIC 层 RTT（交叉验证；fork 没有 Conn.Ping，只能读 stats）
	s.captureQuicRTT()
	log.Printf("✅ [HARP] QUIC 握手完成（%s）：对端 %v", s.role, peerAddr)
	return true
}

// isFingerprintErr 判断错误是不是「指纹不匹配」（安全事件，不重试）
func isFingerprintErr(err error) bool {
	return errors.Is(err, errFingerprintMismatch) || strings.Contains(err.Error(), "指纹不匹配")
}

// notifyListening 发起方监听就绪后，用裸 UDP 通知对端（幂等、失败只记日志）
//
// ⭐ 走**打洞用的那条 socket**（`s.sock`），不是新开一条。原因：
//   - 对端（B）的 `peerFilterConn` 只放行**打洞学到的那个地址**——新 socket 的
//     源端口不同，这条通知会被 B 当成陌生人包直接丢掉；
//   - 新 socket 还有自己的 NAT 映射问题（要再跑一次 STUN 才能被路由到）。
//
// 时序（与 BUG-B 的交接约束一致）：本函数在 `realm.Punch` **返回之后**、
// `transport.Listen` 就绪时调用；此时打洞已不再读这条 socket（`punchActive` 已归零，
// handshake 里有断言），而 QUIC 只可能在**读**，我们这里是**写**，两者不冲突。
func (s *punchSession) notifyListening(peerAddr netip.AddrPort) {
	s.mu.Lock()
	sock := s.sock
	s.mu.Unlock()
	if sock == nil {
		return
	}
	// 锁住时序：发这条通知时打洞必须已经结束（否则就是「打洞与 QUIC 并存」）
	if s.punchActive.Load() {
		log.Printf("💥 [HARP] 监听就绪通知在打洞仍在进行时发出（%s）", s.role)
		return
	}
	s.rdySentAfterPunch.Store(true)
	s.mgr.rdySentSeen.Store(true)
	if _, err := sock.WriteTo([]byte(punchReadyMagic), net.UDPAddrFromAddrPort(peerAddr)); err != nil {
		log.Printf("ℹ️ [HARP] 发送监听就绪通知失败（不影响正确性）: %v", err)
	} else {
		log.Printf("🔔 [HARP] 已发出监听就绪通知（%s，会话开始后 %v）",
			s.role, time.Since(s.startedAt).Round(time.Millisecond))
	}
}

// isNetTimeout 判断错误是不是「读超时」（窗口到点的正常结束）
func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// waitListening 响应方等发起方的「监听就绪」通知；上限 punchDialWait，
// 等不到也照常返回（等价于固定延迟，避免因丢包而卡死）。
func (s *punchSession) waitListening(peerAddr netip.AddrPort) {
	s.mu.Lock()
	sock := s.sock
	s.mu.Unlock()
	if sock == nil {
		return
	}
	deadline := time.Now().Add(punchDialWait)
	waitStart := time.Now()
	got := false
	var lastErr error
	var sawOther int
	// ⚠️ 缓冲区必须装得下**任何**会到达这条 socket 的包：
	//   - 打洞包：8 字节 salt + 25..1049 = 最大约 1057 字节；
	//   - QUIC 包：最大约 1452 字节。
	// 用过小的缓冲区在 Windows 上会直接返回 WSAEMSGSIZE（不是截断），
	// 踩过一次：64 字节缓冲 → 读到 A 残留的打洞 HELLO 就报错退出，
	// 于是永远等不到就绪通知。
	buf := make([]byte, 1500)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			break
		}
		_ = sock.SetReadDeadline(time.Now().Add(remain))
		n, from, err := sock.ReadFrom(buf)
		if err != nil {
			if isNetTimeout(err) {
				break // 正常结束：窗口到点
			}
			// ⭐ 其它错误**不能中断等待**（WSAEMSGSIZE / ICMP 端口不可达等），
			//    只要预算没到就继续读；加一点退避避免忙等。
			lastErr = err
			time.Sleep(10 * time.Millisecond)
			continue
		}
		ap, ok := addrPortFromNetAddr(from)
		if !ok || !sameAddrPort(ap, peerAddr) {
			sawOther++
			continue
		}
		if string(buf[:n]) == punchReadyMagic {
			// 记下来：E2E 测试据此断言「对端确实在拨号**之前**收到了就绪通知」
			s.rdyReceived.Store(true)
			s.mgr.rdyRecvSeen.Store(true)
			got = true
			break
		}
		sawOther++
	}
	log.Printf("🔔 [HARP] 就绪通知等待结束（%s）：命中=%v 耗时=%v 其它包=%d err=%v",
		s.role, got, time.Since(waitStart).Round(time.Millisecond), sawOther, lastErr)
	// 交还给 QUIC 前必须清掉读截止时间
	_ = sock.SetReadDeadline(time.Time{})
	// ⭐ 结构性时序标记：调用方（handshake 的拨号分支）会断言「先等过、再拨号」，
	//    保证这条 socket 在交给 QUIC 之前已经结束了自己的裸读。
	s.waitDone.Store(true)
}

func (s *punchSession) captureQuicRTT() {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return
	}
	st := conn.ConnectionStats()
	if st.SmoothedRTT > 0 {
		s.rttQuic.Store(int64(st.SmoothedRTT))
	}
}

// serveProbe A 侧：accept 一条流，收到帧就原样回显（首个帧即视为直连可用）
func (s *punchSession) serveProbe() {
	s.setState(P2PStateProbing)
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		log.Printf("⚠️ [HARP] serveProbe 时连接为空（%s）", s.role)
		s.fail(P2PReasonProbeTimeout)
		return
	}
	log.Printf("🔍 [HARP] 等待对端探针流（%s）", s.role)
	timeout, ok := s.stageTimeout(s.tuning.probe)
	if !ok {
		s.fail(P2PReasonAttemptTimeout)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		log.Printf("⚠️ [HARP] 等待探针流失败: %v", err)
		s.fail(P2PReasonProbeTimeout)
		return
	}
	log.Printf("🔍 [HARP] 已收到对端探针流（%s）", s.role)
	buf := make([]byte, maxFrameSize)
	echoed := 0
	for {
		pkt, err := readFrame(stream, buf)
		if err != nil {
			// ⭐ 已经成功回显过至少一帧 = 路径已被验证（对端拿到了往返），
			//    之后的读取失败（对端测完收工/流被关）绝不能反过来把本机判失败。
			if echoed == 0 {
				log.Printf("⚠️ [HARP] 读取探针帧失败: %v", err)
				s.fail(P2PReasonProbeTimeout)
			}
			return
		}
		if len(pkt) == 0 {
			continue
		}
		s.probeTotal.Add(1) // ⭐ 1b-4 第 2 步-A：B 侧分母 = 收到的探针帧数
		// 原样回显
		if err := writeFrameToStream(stream, pkt); err != nil {
			if echoed == 0 {
				log.Printf("⚠️ [HARP] 回显探针帧失败: %v", err)
				s.fail(P2PReasonProbeTimeout)
			}
			return
		}
		echoed++
		s.probeGot.Add(1) // ⭐ 1b-4 第 2 步-A：写质量表用（B 侧的分母在 runProbeEcho 入口累计）
		if echoed == 1 {
			s.captureQuicRTT()
			if s.rttDirect.Load() == 0 {
				s.rttDirect.Store(s.rttQuic.Load())
			}
			s.succeed() // 首个回显 = 直连可用
		}
		if ctx.Err() != nil {
			return // 预算用完：对端已经测到 RTT，本机收工
		}
	}
}

// runProbe B 侧：开流 → 3 轮 echo → 算 RTT
func (s *punchSession) runProbe() {
	s.setState(P2PStateProbing)
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		s.fail(P2PReasonProbeTimeout)
		return
	}
	timeout, ok := s.stageTimeout(s.tuning.probe)
	if !ok {
		s.fail(P2PReasonAttemptTimeout)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	defer cancel()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		log.Printf("⚠️ [HARP] 打开探针流失败: %v", err)
		s.fail(P2PReasonProbeTimeout)
		return
	}
	log.Printf("🔍 [HARP] 开始探针（%s id=%s）", s.role, s.id)
	buf := make([]byte, maxFrameSize)

	var best time.Duration
	got := false
	for i := 0; i < punchProbeRounds; i++ {
		s.probeTotal.Add(1) // ⭐ 每个**尝试过**的轮次都计入分母（丢包率 = 1 - got/total）
		if i > 0 {
			select {
			case <-time.After(punchProbeInterval):
			case <-ctx.Done():
				break
			}
		}
		payload, _ := json.Marshal(directProbe{Seq: i + 1, TS: time.Now().UnixNano()})
		start := time.Now()
		if err := writeFrameToStream(stream, payload); err != nil {
			log.Printf("ℹ️ [HARP] 探针第 %d 轮写入失败: %v", i+1, err)
			continue
		}
		_ = stream.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		pkt, err := readFrame(stream, buf)
		if err != nil {
			log.Printf("ℹ️ [HARP] 探针第 %d 轮未收到回显: %v", i+1, err)
			continue
		}
		var back directProbe
		if err := json.Unmarshal(pkt, &back); err != nil || back.Seq != i+1 {
			log.Printf("ℹ️ [HARP] 探针第 %d 轮回显不匹配: seq=%d err=%v", i+1, back.Seq, err)
			continue
		}
		rtt := time.Since(start)
		// ⚠️ 不能用 best==0 当「没测到」的哨兵：Windows 上单调时钟粒度较粗，
		//    loopback/同城内网的往返**真的可能正好是 0**，那样会把成功的探针
		//    误判成失败（踩过一次）。所以单独用 got 标记。
		if !got || rtt < best {
			best = rtt
			got = true
		}
		// ⭐ 1b-4 第 2 步-A：记「这一轮收到了有效回显」（写质量表用）
		s.probeGot.Add(1)
	}
	_ = stream.SetReadDeadline(time.Time{})

	s.captureQuicRTT()
	if !got {
		log.Printf("⚠️ [HARP] 探针 %d 轮全部无有效回显（id=%s）", punchProbeRounds, s.id)
		s.fail(P2PReasonProbeTimeout)
		return
	}
	if best <= 0 {
		// 测到了、但小到本地时钟分辨不出来（Windows 上真的会出现 0）。
		// 记一个最小正值：让「rttDirect > 0 ⟺ 探针成功」这个不变量成立，
		// 显示层再把它折算成 1ms（绝不显示 0ms）。
		best = time.Nanosecond
	}
	s.rttDirect.Store(int64(best))
	log.Printf("📡 [HARP] 探针成功：RTT=%v（QUIC stats=%v）", best, time.Duration(s.rttQuic.Load()))
	s.succeed()
}

// directProbe 应用层探针载荷
type directProbe struct {
	Seq int   `json:"seq"`
	TS  int64 `json:"ts"`
}
