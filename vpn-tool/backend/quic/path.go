package quic

// vpn-tool/backend/quic/path.go
//
// ⭐ P2SP 阶段 1b-2A：直连路径管理（触发 → 路由 → 切换 → 回切）。
//
// 设计依据：`P2SP-阶段1b-2-设计文档.md`（Q1~Q16 已定稿）。本文件的落点对应关系：
//
//	§1   触发策略（流量驱动 + 信号门）      → Observe / scheduler / gate
//	§2   路径选择与切换（COW 路由表）        → routeTable / sinkFor / writeLoops 里调用
//	§2.2.1 直连写隔离（R1b）                 → directPath.tx + writer goroutine + 写截止
//	§2.6 L1 四条链路 + demote 顺序           → demote()
//	§4   失效检测与回切（L1/L2 + 退避）      → watchdog / probe / backoff
//	§5   风暴防护（单飞/让路/限额）          → triggerSeen / tiebreak / 限额常量
//	§6   多对端调度（并发 2 + 上限 8）       → scheduler semaphore / pathMaxPaths
//
// ⚠️ 与设计文档的一处实现差异（交付说明里会单列）：
//   设计 §3.5 原本写「每条新开的直连流第一帧必须是平面声明帧」（6 条平面流）。
//   实现改为「**1 条数据流 + 每帧 1 字节平面标签**」+ 1 条控制流：
//     - 每路径 goroutine 从 ~12 个降到 4 个（写/读/datagram/看门狗）；
//     - 平面与流顺序的脆弱对应关系彻底消失（自描述）；
//     - 语义仍是「6 个平面 1:1 镜像」（每个平面独立队列、独立标签、独立计数）。
//   兼容性结论不变：不认这套帧的对端 → 写超时 → L1 → 回中继。
//
// 播放路径三原则（本文件的硬约束）：
//   1. 热路径（Observe / sinkFor）**只做原子读 + map 查**，无锁、无分配、不阻塞；
//   2. 路由表**发布后永不修改**（写时复制），软状态（RTT/字节/最后使用）放在 pathEntry 内部用原子量；
//   3. 降级顺序**严格**：先摘路由（Store 新表）→ 再关路径 → 最后排退避（demote() 里顺序固定）。

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
)

// ---------- 限额与时间常量（设计 §1.1.1 / §4.3 / §5.3 / §6.2） ----------

const (
	pathMaxPaths = 8 // 同时存在的直连路径上限（§6.2）
	pathTxQueue  = 256

	triggerQueueLen = 8 // 触发队列（满了丢触发，不丢包）
	pathMaxAttempts = 2 // 并发发起上限（与 B 侧 punchMaxResponder=2 对齐）

	pathSwitchGuard   = 10 * time.Second
	probeWriteTimeout = 2 * time.Second

	gatePositiveTTL  = 120 * time.Second // 正缓存（§1.1.1）
	gateNegativeTTL  = 60 * time.Second
	gateMinInterval  = 10 * time.Second // 同地址最小查询间隔
	gateFailBackoff  = 30 * time.Second
	gateGlobalPerMin = 30 // 全局门查询预算（与串行信令流对齐）
	gateQueueLen     = 8

	backoffBusy = 30 * time.Second

	// pathIdleEvict / pathRecreateDelay 见下方 var 块（测试要能缩短它们）

	triggerSeenTTL       = 15 * time.Second
	triggerPruneInterval = 5 * time.Second

	// pathLocalNotReadyDelay 本机 NAT 还没就绪时的短延迟（不写负缓存）
	pathLocalNotReadyDelay = 5 * time.Second

	// directMaxDatagram 直连 datagram 上限：**与中继的 maxGameDatagramSize 保持一致**，
	// 这样「同一个平面的包在中继/直连上是否被丢」的语义完全相同（不引入 MTU 惊喜）。
	directMaxDatagram = maxGameDatagramSize
)

// backoffLadder 失败退避台阶（设计 §4.3）：60s → 2m → 5m → 10m（封顶）
// 只读、不被测试改写，所以是包级变量（时间参数才需要每实例一份，见上面 const 块）
var backoffLadder = []time.Duration{
	60 * time.Second, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute,
}

// ---------- ⭐ 1b-4 第一步：退避分层（四类） ----------
//
// ⚠️ 权威定义在下面 §退避 的 `pathFailClass` / `classifyPathFail` —— 本篇只是**注释性的分层说明**，
// 不在这里另建一套分类（切片 1 曾短暂存在一套重复类型，已删除：两套并存会让台阶互相打架）。
//
// 分层（范围文档 §1）：
//
//	确定性打洞失败 nat-symmetric / fingerprint-mismatch / server-p2p-disabled   5min → 15min → 30min → 1h
//	临时性打洞失败 punch-timeout / peer-no-punch-addr / nat-unknown              60s → 120s → 300s → 600s
//	质量差失败     quality-poor / probe-timeout / direct-lost                    5min → 15min → 30min → 1h
//	忙             peer-busy / rate-limited                                      30s 固定，**不推进台阶**

// ---------- ⭐ 1b-4 第一步：试用期参数（先验后切） ----------
//
// ⭐⭐ **参数口径表（2026-09-27 随真机修复定稿；改任何一个值前先读这张表）**
//
// | 参数 | 值（生产） | 含义 / 与谁耦合 |
// |---|---|---|
// | `probeInterval` | **5s** | 路径级探针间隔；**同时是样本间隔**（见下） |
// | `checkInterval` | **1s** | 看门狗节拍（`evalTrial` / `evalStandby` / 健康判据都按它跑） |
// | `trialWindowNormal` | **15s** | 正常档窗口 |
// | `trialWindowShort` | **5s**（名义） | 质量表命中时**名义**缩短；**生产被下界抬到 15s**（见 `trialWindow()`） |
// | `trialNeedGoodNormal` | **2** | 正常档「需要几个**好**样本才通过」 |
// | `trialNeedGoodShort` | **2** | 质量表命中档的同项 |
// | 样本**总数** | **没有常量** | 由「窗口 / 样本间隔」决定 ⇒ 实际最多 `窗口 / probeInterval` 个 |
// | 窗口下界 | `need × probeInterval × 1.5` | `trialSampleFloor()`：保证窗口**装得下** need 个样本 |
//
// ⚠️ **口径澄清（review 追问，此前文档自相矛盾）**：
//
//	「3 取 2」描述的是 **正常档**：「窗口内最多 3 个样本、其中 2 个好就通过」。
//	代码里**没有**「样本总数」常量 —— 判据只有 `trialGood >= trialNeedGood`（好样本够即可提前通过），
//	窗口到点时若 `trialGood < trialNeedGood` 就判负（含「样本不足」那一支）。
//	⇒ **`trialNeedGoodShort` 也是 2，并不意味着「2 取 2」更严**：
//	  - 正常档：最多 3 个样本，容错 1（3 取 2）；
//	  - 命中档：**窗口与正常档相同（被下界抬到 15s）**，所以样本上限也相同，
//	    但「需要的票数」仍是 2 ⇒ **两档在生产参数下退化为同一条判据**。
//
//	⇒ ⚠️ **记账**：质量表命中目前**唯一**的实际收益是「`need` 从 3 档语义降到 2」（本就都是 2）
//	  以及**未来**把 `probeInterval` 也缩短的余地；**「5s 缩短档」在生产参数下不存在**。
//	  要真正缩短试用期，必须**同时**缩短 `probeInterval`（另一处行为改动，需单独评审）。
const (
	// trialWindowNormal 正常试用期：15s（探针 5s ⇒ 3 个样本）
	trialWindowNormal = 15 * time.Second
	// ⚠️⚠️ 2026-09-27 真机 bug（Bug 2）：`trialWindowShort = 5s` **已删除**。
	//
	//	原因：5s 窗口 + `probeInterval=5s` ⇒ 窗口内最多 1 个采样点、**实测 0 个**
	//	⇒ `samples < need` ⇒ **必然判负**（日志：`**样本不足** 好样本 0/0`）
	//	⇒ 「质量表命中」这个本该加分的情形，反而让这条路**永远连不上**。
	//	而窗口下界（`trialSampleFloor = need × probeInterval × 1.5` = 15s）会把它抬到 15s
	//	⇒ 它在生产参数下**不可达 = 死代码**（review 拍板：删除，减少未来误用面）。
	//
	//	⭐ **未来若真要缩短试用期**（记账）：必须**同时**缩短 `probeInterval`
	//	（样本间隔就是它），并把窗口下界一起调小；那时**再加回**一个缩短档常量。
	//	只看窗口不看 probeInterval 的「缩短」在数学上不可能采到样本。
	// trialRTTRatio 试用期 RTT 判据：directRtt < relayRtt × trialRTTRatio
	//
	// ⭐ 2026-09-27 真机修复：**0.8 → 1.0**（"直连不比中继差就算好"）。
	//
	// 为什么必须改（真机实测，非推测）：某拓扑下直连 38–39ms、中继 46–48ms
	// ⇒ 比值 **0.80–0.85**，永远达不到「快 20%」⇒ 两侧独立判负、直连**永远过不了试用期**。
	// 这不是个例：两个客户端出口位置接近时（同 ISP / 同城 / 同出口），
	// 直连相对中继本来就只有 15–20% 优势。
	//
	// 更本质的理由：`relayRtt` **不是**真中继 RTT，而是服务端给的**估算值**
	// （`relayRttMs = RTT(查询方↔S) + RTT(S↔对端)`，两个分量各自有误差、且绕行服务器）
	// ⇒ 用带 ±10~20% 误差的粗估量去要求精确的「快 20%」，是**在噪声里判生死**
	// （同一拓扑会时过时不过）。×1.0 是唯一能可靠判定的语义，也与试用期的目的吻合：
	// 试用期要回答「这条直连能不能用」，不是「它比中继快多少」。
	//
	// ⚠️ 已知隐患（**接受并记账**，见范围文档 §1 的「接收项」）：
	//
	//	若中继被**低估**（如实际 45ms 估成 50ms）而直连恰在两者之间（48ms），
	//	则 `48 < 50` 判「好」⇒ 切直连，但实际直连略慢于中继。
	//	兜底：① 试用期本身要求「3 取 2」好样本；② 切到 Up 之后有 **standby 机制**
	//	（进入 `> relay×1.2 且持续 30s`、退出 `≤ relay×1.0` 带死区）⇒ 最坏是
	//	「用户体验 30s 的略慢，然后自动回中继」。
	//	**观察项（发版后）**：统计 standby 触发率；若偏高 ⇒ 说明很多用户在体验这 30s，
	//	届时应考虑把试用期判据换成「绝对 + 相对」的组合（需单独评审）。
	//
	// ⭐⭐ 2026-09-27 第二次真机修复：**1.0 → 1.2**（容忍双侧不对称）。
	//
	// 真机实测（第二次）：B 侧 `直连=48.1/46.1ms，中继=51ms` ⇒ **B 判好并通过**；
	// 但同一条连接 **A 侧判负并关闭** ⇒ B 的路径被对端关掉（`path closed`）。
	// 根因：**两侧的判据输入本来就不对称，这是必然的、不是抖动**：
	//
	//	- `relayRtt(A) = RTT(A↔S) + RTT(S↔B)`，`relayRtt(B) = RTT(B↔S) + RTT(S↔A)`
	//	  ——两个分量取自**两条不同的 ctrl 连接**，且是 `SmoothedRTT`（实时值，
	//	  各连接独立平滑、查询时刻也不同）⇒ 两侧拿到的是**不同的估算值**
	//	  （服务端 `signal.go: relayRttMsFor` / `relayRTTLookup`，都有代码依据）；
	//	- `directRtt` 是**各自测的自环回**（两侧各自探测 + 各自回显）⇒ 网络路径不对称时，
	//	  两侧实测值可以差几毫秒到十几毫秒。
	//
	// ⇒ 在 ×1.0 这种「紧贴」的阈值下，**直连略优于中继的拓扑会随机地一侧过、一侧不过**，
	//   而判负的一侧会**单方面关掉连接**（`tryFailTrial → demote`）⇒ 判好的一侧白忙。
	//   ×1.2 给「两侧各自 ±10% 的估算/实测差」留出余量，让正常拓扑**两侧都判好**。
	//   ⚠️ 这不是「放宽到没判据」：直连比中继慢 20% 以上仍然判负，
	//   且 Up 之后 standby（进入 `>1.2× 且持续 30s`）继续兜住「略慢」的情形。
	//
	// ⚠️ **仍待评审的设计缺陷（本轮不做，见定位记录 §5.4）**：判负侧**单方面关连接**
	//	会摧毁判好侧的成果。根治要么「判负只意味着本侧不装表、不关连接」，
	//	要么两侧走一次「试用期结论」协商（新协议）。×1.2 只是把触发概率压下去。
	trialRTTRatio = 1.2
	// trialMinProbeSuccess 试用期丢包判据：探针成功率 ≥ 90%
	trialMinProbeSuccess = 0.9
	// trialNeedGoodNormal / trialNeedGoodShort 「3 取 2」/「2 取 2」的通过票数
	trialNeedGoodNormal = 2
	trialNeedGoodShort  = 2
)

// qualityTable 取质量表（可能为 nil：单测未注入）
func (m *pathManager) qualityTable() *peerTable { return m.quality.Load() }

// setQualityTable 注入质量表（由 startPunchManager 传入**同一实例**；只读引用）
func (m *pathManager) setQualityTable(t *peerTable) { m.quality.Store(t) }

// ⭐⭐ A1（2026-09-27）：**试用期不再依赖质量表** —— 以下三处已删除：
//
//	`hasGoodQualityRecord()`（试用期唯一的读表点）
//	`trialWindowFor(good)` / `trialNeedFor(good)`（由它分支出来的两档参数）
//	`peerTable.HasGoodQuality()`（唯一生产调用者就是 `hasGoodQualityRecord`）
//
// 为什么删（而不是"保留给未来"）：`trialWindowShort` 删除后，试用期的窗口与票数
// **两档同值** ⇒ 质量表命中**不产生任何行为差异** ⇒ 它是个「看起来在接线、实际没接」的
// 假接口（保留会让下一个人以为"质量表影响试用期"）。**"未来可能用"不是保留理由。**
//
// ⚠️ **质量表的消费者分布在 A3a（2026-09-28）后已变化 —— 勿再据旧叙述改代码**：
//
//	· **仍在生产路径上**：`Record`（写：`punch.go` 的 attempt 收尾）与 `Unpunchable`
//	  （读：`pathManager.offerForcedRetry` 的**流量驱动强制重试提议**，**与预打洞无关**）；
//	· **已无生产消费者**：**`Peek`（按 `LastTouch` 排优先级）** —— 其唯一生产调用者是预打洞的
//	  `prePunchCandidates`，随 A3a 删除预打洞发起侧而消失（见 `peertable.go` 表头总注）。
//
// ⇒ 若将来要重新让质量表影响试用期，正确做法仍是**先缩短 `probeInterval`**
// （否则窗口下界会把缩短档抬回 15s，等于没缩短；见 `trialWindow()` 注释）。

// trialWindow 试用期长度：由 hasGoodQualityRecord() 决定（补充 B 的接口预留）
//
// ⭐ 1b-4 第一步 · 设计 §9 的**例外**：允许注入一个更短的窗口/更少的样本，
// 否则「试用期通过才装表」「15s 窗内不装表」这类集成用例只能真等 15 秒。
//
// ⚠️ 注入口在 **pathManager**（`m.trialWindowOverride` / `m.trialNeedOverride`），
// 不在路径上 —— 见 newPathManager 的「可注入参数」契约：这些值由看门狗 goroutine 读，
// 必须在启动前（`start()` / `run()` 之前）写好，放管理器上与 probeInterval 等同一条契约。
// 生产恒为 0 ⇒ 走真实参数。
//
// ⭐ A1（2026-09-27）：**不再读质量表** —— 窗口由「名称常量 + 采样下界」决定，
// 与质量表无关（`trialWindowFor` 已删除，见上面 A1 说明）。
func (p *directPath) trialWindow() time.Duration {
	if p.mgr.trialWindowOverride > 0 {
		return p.mgr.trialWindowOverride
	}
	// ⭐⭐ 2026-09-27 真机修复（Bug 2）：**窗口必须容得下 need 个样本**。
	//
	//	样本间隔 = `probeInterval`（`trialSampleStep` 的节流口径），所以
	//	「窗口 >= need × probeInterval」是能采到 need 个样本的**必要条件**
	//	（还要留一点余量给回显 RTT 与采样相位，取 1.5×）。
	//
	//	实测故障：质量表命中曾把窗口缩到 5s，而 `probeInterval = 5s`
	//	⇒ 窗口内最多 1 个采样点、**实测 0 个** ⇒ `samples < need` ⇒ **必然判负**
	//	（日志：`**样本不足** 好样本 0/0`）。
	//	⚠️ 缩短档常量已**删除**（生产不可达 = 死代码）；将来若要真正缩短，
	//	  必须**同时**缩短 `probeInterval`，并把这里的下界一起调小。
	//
	//	测试注入的 probeInterval 很小（毫秒级）⇒ 下界也很小 ⇒ 既有用例语义不变。
	if floor := p.trialSampleFloor(); floor > trialWindowNormal {
		return floor
	}
	return trialWindowNormal
}

// trialSampleFloor 「窗口内能采到 trialNeedGood 个样本」所需的最小窗口（见 trialWindow 的说明）
func (p *directPath) trialSampleFloor() time.Duration {
	step := p.mgr.probeInterval
	if step <= 0 {
		step = defaultProbeInterval
	}
	return time.Duration(p.trialNeedGood()) * step * 3 / 2 // need × step × 1.5（留回显与相位余量）
}

// trialNeedGood 试用期需要多少个「质量好」样本（= 「3 取 2」里的 2）
//
// ⭐ A1（2026-09-27）：**不再读质量表** ⇒ 恒为 `trialNeedGoodNormal`（=2）。
// 两档常量（`trialNeedGoodNormal` / `trialNeedGoodShort`）值相同、语义曾分档；
// `trialNeedFor` 已删除，这里直接返回常量，避免"看起来会分支、实际不分"。
func (p *directPath) trialNeedGood() int {
	if p.mgr.trialNeedOverride > 0 {
		return p.mgr.trialNeedOverride
	}
	return trialNeedGoodNormal
}

// trialSampleGood 单个样本是否判定「质量好」：RTT 与丢包**两个都满足**才算好
func trialSampleGood(directRTT, relayRTT time.Duration, probeSuccess float64) bool {
	if relayRTT <= 0 || directRTT <= 0 {
		return false // 任一侧未知 ⇒ 不能判定（宁可继续走中继）
	}
	return directRTT < time.Duration(float64(relayRTT)*trialRTTRatio) &&
		probeSuccess >= trialMinProbeSuccess
}

// trialVerdict 试用期结论：好样本数 ≥ 需要的票数 ⇒ 通过
//
// ⚠️ 生产路径**不直接调用**它：`evalTrial` 用的是等价但更适合「边跑边判」的形式 ——
// 好样本够了就提前通过（`trialGoodEnough`），窗口到点才按「票数够不够」结算。
// 保留它是为了让「3 取 2」这条判据本身可单测（TestTrialVerdictThreeOfTwo）。
func trialVerdict(goodSamples, total, need int) bool {
	return goodSamples >= need
}

// 默认时间参数（**每个 pathManager 一份**，见 newPathManager 里的初始化）
const (
	// defaultTiebreakDelay VIP 较大的一侧让路窗口（设计 §5.2，Q13 = 2s）
	defaultTiebreakDelay = 2 * time.Second
	// defaultIdleEvict 空闲淘汰门槛：多久没有**业务流量**就关闭路径（不是失败冷却）。
	//
	// ⭐ 取值是 UX 与资源之间的折中（review 追问 3）：
	//   - 每次淘汰都要重新打洞，用户会看到「回中继 → 又切直连」的抖动；
	//     正常使用里「暂停 6 分钟再继续」很常见，所以 300s **太短**；
	//   - 资源的真实上限由 pathMaxPaths(8) + LRU 负责，不需要靠短超时省资源。
	//     ⇒ 取 **30 分钟**：能回收长期不用的路径，又不至于把「短暂停」变成抖动。
	//
	// ⚠️ QUIC 的 keepalive（5s，`KeepAlivePeriod`）**不算**活跃：它一直在跑，
	// 算进去就等于永不淘汰（机制变死代码）。判据只有「有没有业务包上下行」。
	defaultIdleEvict = 30 * time.Minute
	// defaultRecreateDelay 被淘汰/超上限后，重新建路径的最短间隔。
	// 只防「淘汰 → 立刻重建」的自激循环；真正的防抖是失败退避阶梯（§4.3）。
	defaultRecreateDelay = 2 * time.Second
	// defaultDataWriteDeadline 直连**数据**流的写截止（10s）。
	//
	// ⚠️ 它不是「隔离」的手段——隔离靠「每流一条队列 + 专属写协程」（§2.2.1）；
	// 它只是给「对端彻底变黑洞」兜一个最后期限，所以给得很**宽松**：
	// 上行饱和时 `Stream.Write` 阻塞是**正常背压**（QUIC 会重传），
	// 卡死它就会变成「慢链路一拥塞 → 判路径死 → 抖动」。
	defaultDataWriteDeadline = 10 * time.Second
	// defaultSilentWarn 有包要发但上行 0 字节的告警门槛（数据面疑似未生效）
	defaultSilentWarn = 10 * time.Second
	// defaultOneWayWarn 只出不进的告警门槛（数据面疑似单向）
	defaultOneWayWarn = 30 * time.Second
	// defaultProbeInterval 探针间隔（两侧各自发探测、各自算 RTT 与判活）
	defaultProbeInterval = 5 * time.Second
	// defaultProbeMissLimit 连续几次无回显判路径失效（配合上面的间隔 ≈10~15s 判定窗）
	defaultProbeMissLimit = 2
	// defaultCheckInterval 看门狗节拍：健康判据（数据面告警）+ standby 判据都按它跑。
	// 1s 是「及时」与「开销」的折中（每次只读几个原子量）。
	defaultCheckInterval = time.Second
	// ⭐ 1b-2B：standby 判据（与需求给定值一致）
	//
	//	直连 RTT > 中继估计 × 1.2 **持续 30s** → standby；standby 期间每 5 分钟复查，
	//	中继 RTT 基准也每 5 分钟刷新一次（超过就判过期，判断前先查一次）。
	//
	// ⚠️ 1.2× 与 relayRttMs 的近似误差（RTT(A↔S)+RTT(S↔B) 假设路径对称，误差约 10~20%）
	//    处于同一量级：误差不会造成误判，但也意味着**阈值不能再小**（比如 1.05× 就会误判）。
	defaultStandbyRatio            = 1.2
	defaultStandbyDegradeFor       = 30 * time.Second
	defaultStandbyEvalInterval     = 5 * time.Minute
	defaultRelayRttRefreshInterval = 5 * time.Minute
	// defaultStandbyExitRatio 退出 standby 的比值阈值（⭐回差/死区，review 追问 1）。
	//
	// 进入用 1.2×、退出用 1.0× → 中间留 0.2× 的**死区**，消掉「阈值附近振荡」：
	// relayRttMs 本身有 10~20% 的估计误差，若进出共用一个阈值，比值恰好在阈值附近
	// 抖动时就会「切回中继 → 下一个复查周期又切回直连」地来回跳。
	//
	// 退出取 1.0×（而不是 1.1×）是**故意保守**：估计误差的方向未知，
	// 只有「直连至少不比中继估计慢」才切回；宁可多等一个 5 分钟周期，也不要反复横跳。
	// 代价明确：直连比中继快 0~20% 时会继续留在中继（省不了那部分中继流量）。
	defaultStandbyExitRatio = 1.0
)

// ---------- 平面 ----------

// 直连角色：与 1b-1 的会话角色字符串保持一致（发起方 = QUIC listener = A）。
const (
	pathRoleInitiator = "initiator"
	pathRoleResponder = "responder"
)

// pathPlaneIndex 平面的线序索引（**稳定**：写入每帧的第 5 个字节，改动即协议变更）
type pathPlaneIndex uint8

const (
	planeTCP     pathPlaneIndex = 1
	planeUDP     pathPlaneIndex = 2
	planeMatch   pathPlaneIndex = 3
	planeGameTCP pathPlaneIndex = 4
	planeICMP    pathPlaneIndex = 5
	planeCount   int            = 6 // datagram 面也在内（它不走标签，但占一个队列）
)

// planeName 用于日志/UI
func planeName(p pathPlaneIndex) string {
	switch p {
	case planeTCP:
		return "tcp"
	case planeUDP:
		return "udp"
	case planeMatch:
		return "match"
	case planeGameTCP:
		return "gametcp"
	case planeICMP:
		return "icmp"
	case 0:
		return "datagram"
	}
	return "unknown"
}

// ---------- 抽象层（便于无 TUN / 无 socket 测试） ----------

// directStream 直连流的窄接口（真实实现是 *quic.Stream 的包装）
type directStream interface {
	Write(p []byte) (int, error)
	Read(p []byte) (int, error)
	SetWriteDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	Close() error
}

// directConn 直连连接的窄接口（真实实现是 *quic.Conn 的包装）
type directConn interface {
	OpenStreamSync(ctx context.Context) (directStream, error)
	AcceptStream(ctx context.Context) (directStream, error)
	SendDatagram(p []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
	Context() context.Context
	CloseWithError(code uint64, msg string) error
}

// realDirectConn 把 *quic.Conn 适配成 directConn。
//
// ⚠️ 只做转发，不加任何逻辑：这样生产路径与测试路径的行为差别只剩「谁实现接口」。
type realDirectConn struct{ c *quic.Conn }

func (r realDirectConn) OpenStreamSync(ctx context.Context) (directStream, error) {
	s, err := r.c.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (r realDirectConn) AcceptStream(ctx context.Context) (directStream, error) {
	s, err := r.c.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (r realDirectConn) SendDatagram(p []byte) error { return r.c.SendDatagram(p) }

func (r realDirectConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return r.c.ReceiveDatagram(ctx)
}

func (r realDirectConn) Context() context.Context { return r.c.Context() }

func (r realDirectConn) CloseWithError(code uint64, msg string) error {
	return r.c.CloseWithError(quic.ApplicationErrorCode(code), msg)
}

// ---------- 主机接口（由 Hysteria2Client 实现；测试注入假实现） ----------

// pathHost pathManager 需要宿主客户端提供的能力（**故意很窄**）。
type pathHost interface {
	// myVIP4 自己的隧道 IP（未连接/未分配时 ok=false）
	myVIP4() (vip [4]byte, ok bool)
	// natProbeReady 本机是否已拿到公网地址（没拿到就打不了洞；只延迟重试，不写负缓存）
	natProbeReady() bool
	// p2pEnabled 服务端 P2P 开关（运行期关掉 → 不再触发新路径）
	p2pEnabled() bool
	// signalQuery 隧道内信令查询（信号门用；会顺带重新登记自己）
	signalQuery(peerVIP string) (SignalPeer, error)
	// punchWithTrigger 发起打洞（trigger 只用于状态事件/日志）
	punchWithTrigger(peerVIP, trigger string) (string, error)
	// refreshNAT 重新探测 NAT 并重新登记（地址变化后用；失败返回错误）
	refreshNAT(ctx context.Context) error
	// notifyNATReprobed 通知宿主「NAT 重探测成功」（⭐1b-4 第 2 条重置：清全部失败记录）
	notifyNATReprobed()
	// deliverToTun 下行投递（复用既有函数）
	deliverToTun(pkt []byte)
	// onPathEvent 路径状态变化 → 事件（可为 nil）
	onPathEvent(st P2PStatus)
}

// ---------- 路由表（写时复制） ----------

// routeTable 一经发布**永不修改**（map 是引用类型，改它就会与并发读冲突）
type routeTable map[[4]byte]*directPath

// ---------- pathManager ----------

type pathManager struct {
	host pathHost

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// routes 热路径唯一读取的东西：原子指针 + 不可变 map（§2.1）
	routes atomic.Pointer[routeTable]
	// routeMu 写侧串行化（只有调度器/看门狗会写，频率是「事件级」）
	routeMu sync.Mutex

	// triggerSeen 触发去重集合（也是 COW；写在「触发」时，读在路由未命中时）
	triggerSeen atomic.Pointer[map[[4]byte]time.Time]
	seenMu      sync.Mutex

	// natStale 地址可能变了（路径死掉后）→ 下次发起前先重探测 NAT（§4.4）
	natStale atomic.Bool

	triggerCh chan [4]byte

	// ---- 以下只在调度器/自身 goroutine 里访问，用 mu 保护 ----
	mu         sync.Mutex
	gate       map[[4]byte]gateEntry
	pending    map[[4]byte]struct{} // 等 NAT 就绪的挂起触发
	tiebreak   map[[4]byte]chan struct{}
	backoff    map[[4]byte]backoffState
	lastSwitch map[[4]byte]time.Time
	evictAfter map[[4]byte]time.Time // 淘汰后的最短重建时间
	gateBudget []time.Time           // 全局门查询滑动窗口

	// ⭐ 1b-4 第一步（Q3）：对端公网地址的**上一次观测**（键 = 对端 VIP）。
	//
	// 为什么需要它：`refreshNAT`（本机）与 `hostRTT`（到服务端）**都观察不到对端 IP**，
	// 只有信令返回值带 `peerPublicAddr` ⇒ 「对端换 IP（4G↔WiFi）」只能靠它做对比缓存。
	// 变化 ⇒ 环境变了 ⇒ 清掉该对端的全部失败记录（5 条重置之一）。
	// 与 backoff 等同锁管理（m.mu）。
	peerAddrSeen map[[4]byte]string

	// ⭐ 1b-4 第一步：**试用中**的路径（键 = 对端 VIP）。
	//
	// 为什么不放进 routes（**根因见下方 §试用中路径的登记**）：路由表一个对端只有一个槽，
	// 两条并发 trial 抢同一个槽会制造「同名两实体」的非法中间态（后到者覆盖先到者）。
	// 本表让 trial 路径不占槽位，同时保证 `Paths()`（面板显示「测试中」）与
	// `close()` / `ClearAll()`（关停一起关）都能看见它们。
	// 访问一律在 routeMu 下（与 routes 同一把锁，避免两把锁的锁序问题）。
	trialPaths map[[4]byte][]*directPath

	attempts chan struct{} // 并发发起信号量（容量 pathMaxAttempts）
	jobs     sync.WaitGroup

	// ⭐ 可注入的时间参数（**每个管理器一份**，不是包级变量）：
	//    包级 var 会被并发测试互相污染，也会与看门狗 goroutine 形成数据竞争
	//    （`-race` 抓过一次）。默认值见 newPathManager。
	//
	// ⚠️⚠️ **时序契约（硬约束）**：本段所有字段（含下面的 trialWindowOverride /
	//    trialNeedOverride）都在 `start()` 启动的调度/清理协程、以及各 directPath 的
	//    看门狗 goroutine 里被**读**。因此它们必须在**启动前**写好：
	//      ① 管理器级：`newPathManager` 之后、`start()` 之前；
	//      ② 路径级：路径交给 `run()` 之前（trial 与看门狗的其它参数同批读入）。
	//    启动后再写 = 数据竞争（`-race` 会在集成用例上直接报），而不是「改了下一次生效」。
	//    生产代码从不改它们；它们只服务测试注入。
	tiebreakDelay     time.Duration // VIP 较大的一侧的让路窗口
	idleEvict         time.Duration // 空闲淘汰门槛
	recreateDelay     time.Duration // 淘汰后重建的最短间隔
	dataWriteDeadline time.Duration // 数据流写截止
	silentWarn        time.Duration // 「有包要发但上行 0」告警门槛
	oneWayWarn        time.Duration // 「只出不进」告警门槛
	probeInterval     time.Duration // 探针间隔（两侧各自发）
	probeMissLimit    int           // 连续几次无回显算断
	checkInterval     time.Duration // 看门狗节拍（健康判据 + standby 判据；默认 1s）
	// ⭐ 1b-4：试用期参数（生产恒 0 ⇒ 用 trialWindowFor / trialNeedFor 的真实值）。
	//    放管理器而不是路径上，就是为了让「必须启动前注入」这条契约只有**一处**。
	//
	// trialRelayRttSeed 中继 RTT 基准的**初始种子**（ns；生产恒 0）。
	//    真实生产里这个值由 `refreshRelayRTT`（信令的 relayRttMs）在运行期填；
	//    测试若想在「第一拍判定」就拿到基准，必须在 `run()` 之前种下 —— 否则
	//    `trialSampleGood` 会因 `relay <= 0` 先把前面几个样本判成「不好」，
	//    用例就变成了「在窗口内抢样本」的竞态（实测会偶发红）。
	trialWindowOverride time.Duration
	trialNeedOverride   int
	trialRelayRttSeed   int64
	// ⭐ 1b-2B：standby 判据参数（每实例一份，测试可注入）
	standbyRatio            float64       // 进入 standby 的直连/中继 RTT 比值阈值（默认 1.2）
	standbyExitRatio        float64       // 退出 standby 的比值阈值（默认 1.0；与上面形成死区）
	standbyDegradeFor       time.Duration // 劣化需持续多久才切（默认 30s）
	standbyEvalInterval     time.Duration // standby 期间的复查间隔（默认 5 分钟）
	relayRttRefreshInterval time.Duration // 中继 RTT 基准的刷新间隔（默认 5 分钟）

	// ⭐ 1b-4 第 2 步-A：对端质量表（**由 Hysteria2Client 拥有并注入**，本管理器只持引用）。
	//
	// ⚠️ 为什么不能在这里 `new`：pathManager 每次连接都会重建（startPunchManager），
	//    在这里 new 会让「重连不清空」这条拍板约束失效（见实施计划 §9.2.1）。
	// 读点只有两处：`hasGoodQualityRecord`（试用期长短）与 `handleTrigger`（不可打洞软跳过）。
	// 用 atomic.Pointer：`hasGoodQualityRecord` 会从看门狗 goroutine 调用，
	// 与调度 goroutine 上的 `handleTrigger` 并发（普通字段会有数据竞争）。
	quality atomic.Pointer[peerTable]

	// hooks 仅测试用：观测 demote() 的三步顺序（生产为 nil）
	hooks *pathHooks

	startOnce sync.Once
	closeOnce sync.Once
	done      chan struct{}
}

type gateEntry struct {
	pass  bool
	until time.Time
}

type backoffState struct {
	step int
	// ⭐ 1b-4 第一步：质量差失败**独立** streak。
	// 与 step 分开计数，否则「打洞失败 2 次 + 质量差失败 1 次」会按共用 streak 跳到第 3 台阶。
	qualityStep int
	until       time.Time
	lastErr     string
}

type pathHooks struct {
	RouteRemoved func(vip string)
	PathClosed   func(vip string)
	BackoffSet   func(vip string, d time.Duration)
	// ⭐ 1b-4 第一步：试用期判定的结果（**仅测试用**，生产为 nil）。
	// 日志格式由 logTrialPass / logTrialFail 逐字保证；这两个钩子让用例不必去解析日志文本
	// 就能断言「判定确实发生过、且结论是哪一种」。
	TrialPassed func(vip string)
	TrialFailed func(vip string, reason string)
}

// newPathManager 建一个路径管理器。
//
// ⚠️ 时序契约（review 追问 3 的落点）：本函数填的是**默认值**，测试可以在
// `newPathManager` 之后、`start()` 之前覆盖它们（既有 standby/probe 用例就是这么做的）；
// 一旦 `start()`（或任何路径 `run()`）跑起来，再改就是数据竞争。
// 这些值全部只服务测试注入，生产代码不改；因此「启动前注入」是唯一合法时机。
func newPathManager(host pathHost) *pathManager {
	ctx, cancel := context.WithCancel(context.Background())
	empty := routeTable{}
	seen := map[[4]byte]time.Time{}
	m := &pathManager{
		host:         host,
		ctx:          ctx,
		cancel:       cancel,
		triggerCh:    make(chan [4]byte, triggerQueueLen),
		gate:         make(map[[4]byte]gateEntry),
		pending:      make(map[[4]byte]struct{}),
		tiebreak:     make(map[[4]byte]chan struct{}),
		backoff:      make(map[[4]byte]backoffState),
		lastSwitch:   make(map[[4]byte]time.Time),
		evictAfter:   make(map[[4]byte]time.Time),
		peerAddrSeen: make(map[[4]byte]string),
		trialPaths:   make(map[[4]byte][]*directPath),
		attempts:     make(chan struct{}, pathMaxAttempts),
		done:         make(chan struct{}),
		// ⭐ 默认时间参数（测试可以改**这个实例**的字段；不再有包级可变量）
		tiebreakDelay:           defaultTiebreakDelay,
		idleEvict:               defaultIdleEvict,
		recreateDelay:           defaultRecreateDelay,
		dataWriteDeadline:       defaultDataWriteDeadline,
		silentWarn:              defaultSilentWarn,
		oneWayWarn:              defaultOneWayWarn,
		probeInterval:           defaultProbeInterval,
		probeMissLimit:          defaultProbeMissLimit,
		checkInterval:           defaultCheckInterval,
		standbyRatio:            defaultStandbyRatio,
		standbyExitRatio:        defaultStandbyExitRatio,
		standbyDegradeFor:       defaultStandbyDegradeFor,
		standbyEvalInterval:     defaultStandbyEvalInterval,
		relayRttRefreshInterval: defaultRelayRttRefreshInterval,
	}
	m.routes.Store(&empty)
	m.triggerSeen.Store(&seen)
	return m
}

// start 启动调度器与清理协程（幂等）
//
// ⚠️ 时序契约：调用本函数之后，管理器上的可注入参数（probeInterval / checkInterval /
// standby* / trialWindowOverride …）就**不能再改** —— 它们会被调度与看门狗 goroutine 读取，
// 启动后写属于数据竞争（见 pathManager 里那段契约的说明）。
func (m *pathManager) start() {
	m.startOnce.Do(func() {
		m.wg.Add(2)
		go func() { defer m.wg.Done(); m.scheduleLoop() }()
		go func() { defer m.wg.Done(); m.pruneLoop() }()
	})
}

// close 停止一切：清空路由、关闭所有路径、等 goroutine 退出（幂等）
func (m *pathManager) close() {
	m.closeOnce.Do(func() {
		m.cancel()
		// ⚠️ 先**取快照**再清路由表：反过来的话 snapshotPaths() 就是空的，
		//    路径一条都不会被关闭（这正是 P0 那类「资源无人释放」的翻版，踩过一次）。
		paths := m.snapshotPaths()
		m.replaceRoutes(nil) // 先摘路由：从这一刻起写协程全部回中继
		for _, p := range paths {
			p.close()
			p.waitTimeoutLogged("管理器关停")
		}
		// ⭐ 1b-4：试用中的路径**不在路由表里** ⇒ 必须单独关掉，否则连接/goroutine 泄漏
		m.closeTrialPaths()
		// 没启动过调度/清理协程时，自己标记完成，避免 <-m.done 永久阻塞（测试常见）
		m.startOnce.Do(func() { close(m.done) })
		<-m.done
		m.wg.Wait()
		m.jobs.Wait()
	})
}

// ---------- 路由表读写 ----------

// sinkFor 热路径（§2.2）：给定目的地址与平面，返回**该平面对应流**的发送队列。
//
// ⭐ Q1：关键小包（ICMP/match/游戏 TCP）拿到的是一条独立流的队列，
// 所以 bulk TCP 把 bulk 流堵住时，它们仍能立刻发出。
//
// ⭐ 1b-2B：**只认 pathStateUp** —— standby 的路径仍在路由表里，但这里返回 nil，
// 于是写协程自动回中继（这就是 standby「只切流量、不关连接」的实现方式）。
//
// 只做：原子指针加载 + map 查 + 一次 switch。无锁、无分配、不阻塞。
func (m *pathManager) sinkFor(dst [4]byte, plane pathPlaneIndex) chan pathPkt {
	snap := m.routes.Load()
	if snap == nil {
		return nil
	}
	p := (*snap)[dst]
	if p == nil {
		return nil
	}
	if p.state.Load() != pathStateUp {
		return nil
	}
	return p.streamTx(planeStream(plane))
}

// routeVIP 该目的地址是否有可用直连（诊断/UI 用）
func (m *pathManager) routeVIP(dst [4]byte) (string, bool) {
	snap := m.routes.Load()
	if snap == nil {
		return "", false
	}
	p := (*snap)[dst]
	if p == nil || p.state.Load() != pathStateUp {
		return "", false
	}
	return p.peerVIP, true
}

// installRoute 发布一条新路由（COW：拷贝旧表 → 改新表 → Store）
func (m *pathManager) installRoute(dst [4]byte, p *directPath) {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	m.installRouteLocked(dst, p)
}

// installRouteLocked 与 installRoute 相同，但**要求调用方已持有 routeMu**。
//
// ⭐ 抽取原因（真机 bug）：仲裁必须「读旧表 → 决策 → 装表」原子完成，
// 否则并发的两次握手移交会双双看到 existing==nil 而双双装表（见 handleEstablished）。
func (m *pathManager) installRouteLocked(dst [4]byte, p *directPath) {
	old := m.routes.Load()
	next := make(routeTable, len(*old)+1)
	for k, v := range *old {
		next[k] = v
	}
	next[dst] = p
	m.routes.Store(&next)
}

// removeRoute 摘掉一条路由；只有「表里还是它」时才摘（避免误摘新连接）
//
// ⭐ 这是 demote() 的**第一步**：从这一刻起，写协程立即回中继。
func (m *pathManager) removeRoute(dst [4]byte, p *directPath) bool {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	old := m.routes.Load()
	if (*old)[dst] != p {
		return false
	}
	next := make(routeTable, len(*old))
	for k, v := range *old {
		if k == dst {
			continue
		}
		next[k] = v
	}
	m.routes.Store(&next)
	return true
}

// replaceRoutes 整体替换（nil → 空表）；用于 Close / P2P 关闭
func (m *pathManager) replaceRoutes(p *directPath) {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	next := routeTable{}
	if p != nil {
		next[p.peer] = p
	}
	m.routes.Store(&next)
}

// ClearAll 清空路由表并关闭所有直连路径（幂等）。
//
// 触发场景：① 本机开关「开→关」（P2PEffective 变 false）；
// ② 服务端运行期关闭 P2P（检测到「signaling disabled」拒绝文本时）。
// 顺序仍然是「先摘路由 → 再关路径」：摘掉路由的那一刻，写协程就全部回中继了。
func (m *pathManager) ClearAll(reason string) {
	paths := m.snapshotPaths()
	m.replaceRoutes(nil)
	for _, p := range paths {
		log.Printf("📴 [HARP] 关闭路径：%s（%s；本路径共承载 ↑%d ↓%d 字节）",
			p.peerVIP, reason, p.bytesUp.Load(), p.bytesDown.Load())
		p.close()
		p.waitTimeoutLogged("ClearAll")
	}
	// ⭐ 1b-4：试用中的路径也一并关掉（它们不在路由表里，但同样是「已在用 P2P」的产物）
	for _, p := range m.trialPathsSnapshot() {
		log.Printf("📴 [HARP] 关闭试用中的路径：%s（%s）", p.peerVIP, reason)
		p.close()
		p.waitTimeoutLogged("ClearAll(试用中)")
	}
	if len(paths) > 0 {
		m.emit(P2PStatus{State: P2PStateFailed, ReasonCode: P2PReasonServerP2PDisabled,
			ReasonText: reason, Path: "relay", At: time.Now().UnixMilli()})
	}
}

// HasUsablePath ⭐ B3（2026-09-27）：该对端是否已有「可用」路径 ⇒ 流量驱动不必再打洞。
//
// 语义（review 拍板）：
//
//	Up      ✅ 算（正在承载流量）
//	Trial   ✅ 算（**本切片的主要收益**：试用期路径不占路由槽、不承载流量 ⇒ 流量会继续触发
//	                打洞，于是同一对端在 15s 试用期内被反复发起 attempt）
//	Standby ❌ 不算（**降级应允许重试** —— 这是 standby 的设计意图）
//	Down    ❌ 不算
//
// ⚠️ A2 落地时扩展（2 行，不是返工）：`Rejected` ❌ 不算（本侧明确不用）、`Reusing` ✅ 算。
//
// ⚠️ 锁契约：路由表走 `atomic.Pointer` 快照读（无锁）；试用登记走 `trialPathsSnapshot()`（自取 m.mu）。
//
//	调用方（`punchManager.PunchWithTrigger`）此刻**不持 punchManager.mu** ⇒ 不构造新的锁序边。
//
// ⚠️ 竞态取向：查到「有路径」与「路径消失」之间**不做 CAS** —— 这是**启发式抑制**，
//
//	最多延迟一拍（下一次流量触发会重新放行），不值得为它引入跨管理器原子操作。
func (m *pathManager) HasUsablePath(dst [4]byte) (bool, string) {
	if rt := m.routes.Load(); rt != nil {
		if p := (*rt)[dst]; p != nil && p.state.Load() == pathStateUp {
			return true, pathStateName(pathStateUp)
		}
	}
	for _, p := range m.trialPathsSnapshot() {
		if p.peer == dst && p.state.Load() == pathStateTrial {
			return true, pathStateName(pathStateTrial)
		}
	}
	return false, ""
}

func (m *pathManager) snapshotPaths() []*directPath {
	snap := m.routes.Load()
	out := make([]*directPath, 0, len(*snap))
	for _, p := range *snap {
		out = append(out, p)
	}
	return out
}

// ---------- ⭐ 1b-4：试用中路径的登记（与路由表分离） ----------
//
// 为什么必须分离（**根因，review 追问 1 的结论**）：
//
// 先说清楚**不是**什么：`removeRoute` 的守卫是「`(*old)[dst] == p` 才摘」，
// 所以「一条失败的 trial 把**另一条**路径的注册摘掉」**不可能发生**（指针不等直接返回 false）。
// 也就是说 demote 的摘路由逻辑本身没有问题，不需要单独修。
//
// 真正的问题是**槽位冲突**：路由表是 `map[dst]*directPath` —— 一个对端**只有一个槽**。
// trial 期间路径若放进路由表，同一对端的两条并发 attempt 就会抢同一个槽：
//   - 后者覆盖前者 ⇒ 前者的「在表里」状态凭空消失，它的 demote 会摘掉**自己那条**注册（守卫放行），
//     槽位因此短暂变空；
//   - 于是「谁先通过试用期」就不再只由 `arbitrationKeeps` 决定，而掺进了「谁先被 setup 失败带走」。
// 实测症状：A 侧先结算 X（X 进表），另一条 Y 的 setup 失败把自己摘掉 ⇒ 槽位空 ⇒ X 的直接
// 连接凭空消失（用例报「A 应保留 X，实际 <无>」）。
//
// 分离后：trial 路径**不占槽位**，槽位只在装表点（`installAfterTrial`）由 VIP 规则一次性决定，
// 就不存在「同名两实体」这种非法中间态。附带满足设计 §9 Q1（trial 不进路由表 ⇒ 不承载流量、
// 不参与仲裁），同时用本表满足「面板要看得见（Paths）」与「关停要关得掉（close/ClearAll）」。
//
// ⚠️ 边界：本表不是「绕开 demote 的补丁」——demote 的守卫本来就对；本表消除的是**非法状态**。

// addTrialPath 登记一条试用中的路径。
//
// ⚠️ **不做「同一对端只留一条」的顶替**：两条并发的 attempt 必须**都跑完试用期**，
// 再由装表点的 `arbitrationKeeps`（VIP 规则）决定留哪条 —— 谁先通过试用期与
// 「谁是合法的物理连接」是两件事，先到先得会把合法的那条提前关掉。
//
// ⚠️ 锁契约：**要求调用方已持有 routeMu**（与 run() 同一临界区，见 handleEstablished，
// 这样「登记 + run()」对 close() 而言是原子的：不会出现「管理器看得见它但 wg.Add 还没发生」）。
func (m *pathManager) addTrialPath(p *directPath) {
	m.trialPaths[p.peer] = append(m.trialPaths[p.peer], p)
}

// detachTrialPath 把路径从试用登记里摘掉（幂等）。
//
// 返回一个**幂等的清理闭包**：路径无论走到哪一步（装表 / 降级 / 关闭 / 被仲裁丢弃），
// 只要调用它就会摘掉自己那条登记（且只摘一次）。由 newDirectPath 存进 p.untrack。
//
// ⚠️ 锁契约：自己加解锁 routeMu，调用方**不得持 routeMu**（避免自死锁）。
func (m *pathManager) detachTrialPath(p *directPath) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			m.routeMu.Lock()
			defer m.routeMu.Unlock()
			list := m.trialPaths[p.peer]
			for i, q := range list {
				if q == p {
					list = append(list[:i], list[i+1:]...)
					break
				}
			}
			if len(list) == 0 {
				delete(m.trialPaths, p.peer)
			} else {
				m.trialPaths[p.peer] = list
			}
		})
	}
}

// trialPathCount 试用中的路径条数（路径上限判定用；自己取 routeMu）
func (m *pathManager) trialPathCount() int {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	n := 0
	for _, list := range m.trialPaths {
		n += len(list)
	}
	return n
}

// trialPathsSnapshot 试用中路径的快照（自己取 routeMu）
func (m *pathManager) trialPathsSnapshot() []*directPath {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	out := make([]*directPath, 0, len(m.trialPaths))
	for _, list := range m.trialPaths {
		out = append(out, list...)
	}
	return out
}

// closeTrialPaths 关闭所有还在试用期的路径（管理器关停 / ClearAll 用）。
//
// 为什么需要：trial 路径**不在路由表里** ⇒ snapshotPaths() 看不见它们，
// 只按路由表关会让这些连接泄漏（P0 那类「资源无人释放」的翻版）。
func (m *pathManager) closeTrialPaths() {
	for _, p := range m.trialPathsSnapshot() {
		p.close()
		p.waitTimeoutLogged("关停(试用中)")
	}
}

// pathCount 当前**存在的直连路径总数** = 路由表 + 试用表（路径上限判定与用例断言都用它）。
func (m *pathManager) pathCount() int { return len(m.snapshotPaths()) + m.trialPathCount() }

// Paths 供 UI 展示的路径快照
type PathInfo struct {
	PeerVIP     string `json:"peerVip"`
	State       string `json:"state"`
	Role        string `json:"role"`
	RTTMs       int64  `json:"rttDirectMs"`
	BytesUp     uint64 `json:"bytesUp"`
	BytesDown   uint64 `json:"bytesDown"`
	DirectSince int64  `json:"directSince"`
	// Warn 数据面健康告警（空串 = 正常）。见 checkDataPlaneHealth：
	// 它把「用户真没用（无流量）」与「数据面坏了（有包待发却 0 字节）」区分开。
	Warn string `json:"warn,omitempty"`
}

func (m *pathManager) Paths() []PathInfo {
	paths := m.snapshotPaths()
	trials := m.trialPathsSnapshot()
	out := make([]PathInfo, 0, len(paths)+len(trials))
	add := func(p *directPath) {
		out = append(out, PathInfo{
			PeerVIP:     p.peerVIP,
			State:       pathStateName(p.state.Load()),
			Role:        p.role,
			RTTMs:       msAtLeast1(p.rtt.Load()),
			BytesUp:     p.bytesUp.Load(),
			BytesDown:   p.bytesDown.Load(),
			DirectSince: p.since.UnixMilli(),
			Warn:        p.healthWarn(),
		})
	}
	for _, p := range paths {
		add(p)
	}
	// ⭐ 1b-4：试用中的路径也必须出现在面板列表里（前端把它显示成「测试中」）。
	// 它们不在路由表里（不进分流、不参与仲裁），但属于「当前直连对端」的一部分。
	seen := make(map[*directPath]bool, len(paths))
	for _, p := range paths {
		seen[p] = true
	}
	for _, p := range trials {
		if seen[p] {
			continue // 理论上不会同时出现在两张表里；防重（面板不该出现重复行）
		}
		// ⭐ A2（方案 A）：`Rejected` / `Reusing` / `RejectedSettling` **不进面板** ——
		//	它们是「本侧明确不用 / 收尾中」的连接，列成直连会让用户以为在走直连。
		//	⚠️ 与 `pathCount()` **取向相反**：那边**仍计入**（这些登记占资源、占 pathMaxPaths 名额）
		//	⇒ 改任一处都不得顺手把另一处改成同款（用例 #16/#17 各钉一边）。
		switch p.state.Load() {
		case pathStateRejected, pathStateReusing, pathStateRejectedSettling:
			continue
		}
		add(p)
	}
	return out
}

// ---------- 触发（热路径入口） ----------

// Observe 由 TUN 读循环调用（**每包**）。只做三件事：查路由是否已直连、查触发去重、非阻塞入队。
//
// ⚠️ 绝不能在这里做：STUN、日志（非 debug）、加锁、写 socket、DNS。见 §1.4。
func (m *pathManager) Observe(dst [4]byte) {
	// 已有直连（或正在建立）→ 什么都不做
	if snap := m.routes.Load(); snap != nil && (*snap)[dst] != nil {
		return
	}
	if m.seenRecently(dst) {
		return
	}
	select {
	case m.triggerCh <- dst:
	default: // 队列满：丢这次触发（流量还在，下一个包会再触发）
	}
}

// seenRecently 查触发去重集合并**顺手登记**（登记是 COW 写，发生频率=触发频率）
func (m *pathManager) seenRecently(dst [4]byte) bool {
	now := time.Now()
	snap := m.triggerSeen.Load()
	if snap != nil {
		if until, ok := (*snap)[dst]; ok && now.Before(until) {
			return true
		}
	}
	m.seenMu.Lock()
	defer m.seenMu.Unlock()
	cur := m.triggerSeen.Load()
	next := make(map[[4]byte]time.Time, len(*cur)+1)
	for k, v := range *cur {
		if now.Before(v) {
			next[k] = v
		}
	}
	next[dst] = now.Add(triggerSeenTTL)
	m.triggerSeen.Store(&next)
	return false
}

func (m *pathManager) pruneLoop() {
	t := time.NewTicker(triggerPruneInterval)
	defer t.Stop()
	for {
		select {
		case <-m.ctx.Done():
			close(m.done)
			return
		case <-t.C:
			m.pruneTriggerSeen()
			m.evictIdle()
			// ⚠️ **顺序影响正确性，不是风格**：`evictIdle()` **先**跑 —— 它触发的
			//	`releaseRejected → close()` 会把状态置 `Down`；兜底**随后**才扫得到它。
			//	颠倒 ⇒ 本轮扫不到、要等下一拍（白多一个 tick 的空转）。
			m.pruneDeadRegistrations()
		}
	}
}

// pruneDeadRegistrations ⭐ A2 兜底：摘除 `trialPaths` 里 **state == Down** 的死登记。
//
// 纯清理：**不** close、**不**排退避、**不**碰状态。
//
// ⚠️ 为什么需要（防御性，不是已知缺陷路径）：
//
//	`p.untrack` 是**一次性闭包**（`sync.Once` 包着「摘一次 + break」），而 `addTrialPath`
//	**不幂等** ⇒ 同一个指针若被登记两次，只能摘掉一条 ⇒ 残留那条**永远留在表里**
//	（`pruneLoop` 每拍都扫到它、白名单又直接 `continue` ⇒ 空转 + 泄漏）。
//	生产当前**不产生**重复登记（`handleEstablished` 每条路径只 `addTrialPath` 一次）
//	⇒ 本函数是**兜底**，不是主路径。
//
// ⚠️ **白名单只有 `Down`**：
//
//	`Rejected` / `Reusing` / `RejectedSettling` / `Trial` / `Up` / `Standby` **一律不动** ——
//	尤其 `RejectedSettling`（收尾中间态，由 `releaseRejected → close → untrack` 负责）
//	与 `Rejected`（TTL 白名单的正主，见 `evictIdle`）。
//	由 `TestPruneDeadRegistrationsOnlyEvictsDown` **七态逐一**钉住。
//
// ⚠️ 锁契约：自己取 `routeMu`（与 `trialPathsSnapshot` 同款）⇒ 调用方**不得持 `routeMu`**。
func (m *pathManager) pruneDeadRegistrations() {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	for peer, list := range m.trialPaths {
		kept := list[:0] // 原地过滤（读下标恒 ≥ 写下标，安全）
		for _, p := range list {
			if p.state.Load() == pathStateDown {
				continue // 摘除：已死但登记还在
			}
			kept = append(kept, p)
		}
		if len(kept) == 0 {
			delete(m.trialPaths, peer)
			continue
		}
		m.trialPaths[peer] = kept
	}
}

func (m *pathManager) pruneTriggerSeen() {
	now := time.Now()
	m.seenMu.Lock()
	cur := m.triggerSeen.Load()
	next := make(map[[4]byte]time.Time, len(*cur))
	for k, v := range *cur {
		if now.Before(v) {
			next[k] = v
		}
	}
	m.triggerSeen.Store(&next)
	m.seenMu.Unlock()
}

// evictIdle 空闲淘汰（§6.2）：超过 idleEvict 没有上下行流量 → 关路径（不打失败冷却）
func (m *pathManager) evictIdle() {
	now := time.Now()
	for _, p := range m.snapshotPaths() {
		if now.Sub(time.UnixMilli(p.lastUse.Load())) < m.idleEvict {
			continue
		}
		log.Printf("📴 [HARP] 路径空闲淘汰：%s（%v 无流量，本次共承载 ↑%d ↓%d 字节）",
			p.peerVIP, m.idleEvict, p.bytesUp.Load(), p.bytesDown.Load())
		p.close()
		p.waitTimeoutLogged("空闲淘汰")
		m.removeRoute(p.peer, p)
		m.mu.Lock()
		m.evictAfter[p.peer] = now.Add(m.recreateDelay)
		m.mu.Unlock()
	}

	// ⭐⭐ A2（方案 A）：**判负保留连接**的 TTL 淘汰。放在**同一个 pruneLoop** 里 ⇒ 零新增 goroutine。
	//
	// ⚠️ 判据是**白名单**（review 2026-09-27 修正）：只有 `Rejected` 且超 `trialRejectedTTL` 才动。
	//	否定式（"非 Up 且非 Standby"）既没定义 `Reusing`/`RejectedSettling` 算不算，
	//	又容易漏掉 `Trial` ⇒ **误杀正在跑试用期的正常路径**（由 TestPruneOnlyEvictsRejectedState 钉住）。
	// ⚠️ 走 `releaseRejected()`（专用清理：不排退避、不共用 terminateOnce）—— 与 demote 不同路径。
	for _, p := range m.trialPathsSnapshot() {
		if p.state.Load() != pathStateRejected {
			continue // Trial / Reusing / RejectedSettling / Up / Standby 一律不动
		}
		at := p.rejectedAt.Load()
		if at == 0 || now.Sub(time.UnixMilli(at)) < trialRejectedTTL {
			continue
		}
		log.Printf("📴 [HARP] 判负保留连接已到期：%s（保留 %v 后释放；本侧期间未承载流量）",
			p.peerVIP, trialRejectedTTL)
		p.releaseRejected()
	}
}

// ---------- 调度器（§1.5 / §5 / §6.1） ----------

func (m *pathManager) scheduleLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case dst := <-m.triggerCh:
			m.handleTrigger(dst)
		}
	}
}

// handleTrigger 对一个触发做门控与配额判断，然后把实际尝试交给 goroutine（受信号量限制）
func (m *pathManager) handleTrigger(dst [4]byte) {
	if !m.host.p2pEnabled() {
		return
	}
	myVIP, ok := m.host.myVIP4()
	if !ok || myVIP == dst {
		return
	}
	// VIP 唯一性 + 广播/组播/全零（与服务端同款判据）
	if isBroadcastOrMulticast4(dst) {
		return
	}
	// 本机还没拿到公网地址：此刻打不了洞。**不写负缓存**（不是对端的问题），
	// 只把该对端延后 pathLocalNotReadyDelay，等 NAT 就绪后由后续流量重新触发。
	// （设计 §5.2.1 案例 1 的「挂起等就绪」在本实现里等价为「短延迟轮询」——见交付说明的差异表）
	if !m.host.natProbeReady() {
		m.delayRetry(dst, pathLocalNotReadyDelay)
		return
	}
	peerVIP := ip4ToString(dst)
	if peerVIP == "" {
		return
	}

	m.mu.Lock()
	if until, ok := m.evictAfter[dst]; ok && time.Now().Before(until) {
		m.mu.Unlock()
		return
	}
	if st, ok := m.backoff[dst]; ok && time.Now().Before(st.until) {
		m.mu.Unlock()
		return
	}
	if _, busy := m.pending[dst]; busy {
		m.mu.Unlock()
		return
	}
	m.pending[dst] = struct{}{}
	m.mu.Unlock()

	// ⭐ 1b-4 第 2 步-A（D3 软跳过）：该对端近期被记为「不可打洞」时不再白打洞。
	//
	//	TTL 内**允许 1 次**「流量驱动强制重试」（用户拍板：不双罚、也不永久跳过）：
	//	  - 第 1 次触发 ⇒ 记 `forcedOffer`，继续走（真正的**消费**发生在 attemptFor 的提交点，
	//	    即过完信号门+让路+额度、即将调 punchWithTrigger 之前 —— 避免「对端离线/冷却/限流」
	//	    时白消费一次，见实施计划 §2.3.1 / W-2）；
	//	  - 用掉之后 ⇒ 直接返回（不排 pending、不发 intent），并打**用户可见日志**。
	forcedOffer, skipReason, skip := m.offerForcedRetry(dst, peerVIP)
	if skip {
		m.mu.Lock()
		delete(m.pending, dst)
		m.mu.Unlock()
		log.Printf("ℹ️ [HARP] 该对端近期记录不可打洞（%s），本次直连已跳过"+
			"（TTL 内已强制重试 1 次，记录过期后自动恢复）", skipReason)
		return
	}

	m.jobs.Add(1)
	go func() {
		defer m.jobs.Done()
		defer func() {
			m.mu.Lock()
			delete(m.pending, dst)
			m.mu.Unlock()
		}()
		m.attemptFor(dst, peerVIP, myVIP, forcedOffer, skipReason)
	}()
}

// offerForcedRetry 判定「本次触发要不要因为『不可打洞』记录而跳过」。
//
// 返回：
//
//	forcedOffer=true  —— 有「不可打洞」记录但**本 TTL 内还没用过**强制重试 ⇒ 放行，
//	                     并把「这是一次强制重试」的提议交给 attemptFor（由它在提交点消费）
//	skipReason        —— 原因码（日志用）
//	skip=true         —— 已用过 ⇒ 本次跳过
//
// ⚠️ 本函数**不消费**（不做写操作）：只读判定。消费在 `attemptFor` 的提交点，
//
//	否则「对端离线 / 冷却 / 限流」挡下时会白消费一次（W-2）。
func (m *pathManager) offerForcedRetry(dst [4]byte, peerVIP string) (forcedOffer bool, skipReason string, skip bool) {
	tbl := m.qualityTable()
	if tbl == nil {
		return false, "", false
	}
	q, ok := tbl.Unpunchable(dst)
	if !ok {
		return false, "", false
	}
	if q.ForcedRetryUsed {
		return false, q.ReasonCode, true
	}
	return true, q.ReasonCode, false
}

// attemptFor 信号门 → 让路 → 发起打洞
//
// ⭐ 1b-4 第 2 步-A：`forcedOffer` 为 true 表示「本次是一次『不可打洞』记录的强制重试」——
// 只在**提交点**（过完信号门 + 让路 + 拿到额度，即将 `punchWithTrigger` 之前）消费那 1 次机会。
func (m *pathManager) attemptFor(dst [4]byte, peerVIP string, myVIP [4]byte, forcedOffer bool, reason string) {
	// ① 信号门（带缓存）：不是在线对端就不打
	pass, err := m.gateCheck(dst, peerVIP)
	if !pass {
		if err != nil {
			log.Printf("ℹ️ [打洞] %s 未通过信号门：%v", peerVIP, err)
		}
		return
	}

	// ② 让路：VIP 较大的一侧等 tiebreakDelay，期间若收到对方邀请就当响应方
	if bytesGreater(myVIP, dst) {
		waitCh := m.registerTiebreak(dst)
		select {
		case <-waitCh: // 收到对方邀请 → 让路成功
			log.Printf("ℹ️ [打洞] 收到 %s 的邀请，放弃本次发起（VIP 决胜让路）", peerVIP)
			return
		case <-time.After(m.tiebreakDelay):
		case <-m.ctx.Done():
			return
		}
		m.clearTiebreak(dst)
	}

	// ③ 信号量：并发发起上限
	select {
	case m.attempts <- struct{}{}:
	case <-m.ctx.Done():
		return
	}
	attemptID := ""
	consumedForced := false
	err = func() error {
		defer func() { <-m.attempts }()
		// 地址可能变了（上一次路径死掉后）：重探测 + 重登记
		if m.takeNATStale() {
			ctx, cancel := context.WithTimeout(m.ctx, punchAttemptBudget)
			defer cancel()
			if err := m.host.refreshNAT(ctx); err != nil {
				log.Printf("ℹ️ [打洞] NAT 重探测失败（%s）：%v", peerVIP, err)
			} else {
				// ⭐ 1b-4 第一步 第 2 条重置（NAT 重探测成功）。
				//    ⚠️ 锁契约：此刻**不持任何锁**（attemptFor 里已全部释放），
				//    host 实现内部只短暂取 punchMu/m.mu，不做 I/O。
				m.host.notifyNATReprobed()
			}
		}
		// ⭐ 1b-4 第 2 步-A（W-1/W-2）：**提交点** —— 这里才真正会发出 punch-intent。
		//    只有走到这一步，那 1 次强制重试机会才值得用掉（原子消费；并发只会赢一次）。
		if forcedOffer {
			if tbl := m.qualityTable(); tbl != nil && !tbl.TryConsumeForcedRetry(dst) {
				return errForcedRetryUsed
			}
			consumedForced = true
		}
		id, perr := m.host.punchWithTrigger(peerVIP, P2PTriggerTraffic)
		attemptID = id
		return perr
	}()
	if err != nil {
		if errors.Is(err, errPunchDupPath) {
			// ⭐ B3：已有可用路径（Up/Trial）⇒ 本次流量驱动被抑制。
			//	**不是失败**：不写任何退避（日志已由 `PunchWithTrigger` 打出，含 state 与累计次数）。
			return
		}
		if err == errForcedRetryUsed {
			// 并发下被别人先消费掉 ⇒ 本次不发（不是失败，不排退避）
			log.Printf("ℹ️ [HARP] 该对端（%s）的强制重试机会已被本次并发触发用掉，本次不发", peerVIP)
			return
		}
		log.Printf("ℹ️ [打洞] 触发 %s 的打洞未开始：%v", peerVIP, err)
		if consumedForced {
			// ⭐ 追问 4 的日志透明：机会用掉了、但 punch-intent 没发出去（多半是内部冷却）
			log.Printf("ℹ️ [HARP] 强制重试已用掉，但打洞未发起：%s（原因：%v）", peerVIP, err)
		}
		// ⭐ 1b-4 第 3 步：**冷却类错误不写本地退避**（否则会盖住 busy/rate 的长档）。
		//
		//	`punchManager` 已经算好了冷却（busy/rate：30s→60s→120s→5min；其它失败 60s），
		//	这里再无条件写一个**固定 30s** 的 `backoff`，会让：
		//	  ① 长档不起作用（30s 后 `handleTrigger` 的退避门就放行了）；
		//	  ② 被放行的那次触发立刻又被 punchManager 拒回、又推进一档 + 再写 30s
		//	     ⇒ 退化成「每 30s 空转一次、档位一路虚涨到 5min」，**比不改更差**。
		//
		//	跳过也安全：冷却期内 `punchWithTrigger` 在**本地**直接返回（零网络请求），
		//	不会造成请求风暴；对 rate-limited 尤其重要（服务端是硬拒，早试也过不去）。
		if errors.Is(err, errPunchCooldown) {
			log.Printf("ℹ️ [HARP] %s 处于打洞冷却期，本地退避交由打洞管理器负责（不重复排退避）", peerVIP)
			return
		}
		// 冷却/忙以外的失败：延迟重试（不推进退避台阶），由调度器下一轮触发接手
		m.setBackoffTransient(dst, err)
		return
	}
	if consumedForced {
		log.Printf("ℹ️ [HARP] 该对端（%s）曾记录不可打洞（%s），本次强制重试 1 次", peerVIP, reason)
	}
	log.Printf("🔗 [HARP] 已触发直连尝试 → %s（attempt=%s，来源=流量）", peerVIP, attemptID)
}

// errForcedRetryUsed 强制重试机会已被并发触发消费（内部哨兵错误，不外传）
var errForcedRetryUsed = errors.New("强制重试机会已被用掉")

// notifyInboundInvite 由 punchManager 在处理 punch-invite 时调用：
// 让路等待立即结束（我不再自己发起）。
func (m *pathManager) notifyInboundInvite(peerVIP string) {
	dst, ok := parseIPv4(peerVIP)
	if !ok {
		return
	}
	m.mu.Lock()
	ch := m.tiebreak[dst]
	delete(m.tiebreak, dst)
	m.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (m *pathManager) registerTiebreak(dst [4]byte) chan struct{} {
	ch := make(chan struct{})
	m.mu.Lock()
	m.tiebreak[dst] = ch
	m.mu.Unlock()
	return ch
}

func (m *pathManager) clearTiebreak(dst [4]byte) {
	m.mu.Lock()
	delete(m.tiebreak, dst)
	m.mu.Unlock()
}

// ---------- 信号门（§1.1.1） ----------

// gateCheck 判断「这个地址是不是一个可打洞的在线对端」，结果带缓存。
//
// 语义依据（1b-1 定稿约束 2）：`peerOnline` = 数据面在线且信令表里有登记；
// `peerSignalReady` = 服务端推得过去。两者都为真才值得打洞。
func (m *pathManager) gateCheck(dst [4]byte, peerVIP string) (bool, error) {
	now := time.Now()
	m.mu.Lock()
	if e, ok := m.gate[dst]; ok && now.Before(e.until) {
		m.mu.Unlock()
		return e.pass, nil
	}
	// 全局预算（滑动窗口 1 分钟）
	kept := m.gateBudget[:0]
	for _, at := range m.gateBudget {
		if now.Sub(at) <= time.Minute {
			kept = append(kept, at)
		}
	}
	if len(kept) >= gateGlobalPerMin {
		m.gateBudget = kept
		m.mu.Unlock()
		return false, fmt.Errorf("信号门查询已达全局预算（%d/分钟）", gateGlobalPerMin)
	}
	m.gateBudget = append(kept, now)
	m.mu.Unlock()

	peer, err := m.host.signalQuery(peerVIP)
	if err != nil {
		m.putGate(dst, false, gateFailBackoff)
		return false, err
	}
	// ⭐ 1b-4 第一步（Q3 · 第 4 条重置）：信令返回值是**唯一**能看到对端公网地址的通道。
	//    ⚠️ 锁契约：此刻不持 m.mu（上面已 Unlock）⇒ notePeerPublicAddr 自己取锁是顺序取锁。
	m.notePeerPublicAddr(dst, peer.PublicAddr)
	if !peer.Online || !peer.SignalReady {
		m.putGate(dst, false, gateNegativeTTL)
		return false, fmt.Errorf("对端不在线或信令未就绪（online=%v signalReady=%v）",
			peer.Online, peer.SignalReady)
	}
	m.putGate(dst, true, gatePositiveTTL)
	return true, nil
}

func (m *pathManager) putGate(dst [4]byte, pass bool, ttl time.Duration) {
	m.mu.Lock()
	m.gate[dst] = gateEntry{pass: pass, until: time.Now().Add(ttl)}
	m.mu.Unlock()
}

// ---------- 退避（§4.3） ----------

// pathFailClass 失败分类：决定退避行为
type pathFailClass int

const (
	failRetryable pathFailClass = iota // 走台阶（临时性打洞失败）
	failBusy                           // 服务端忙/限流：短延迟、不推进台阶
	failPermanent                      // 确定性失败：长得多的台阶（原先固定 10min）
	// ⭐ 1b-4 第一步：打洞成功但**质量差** ⇒ 独立台阶 + **独立 streak**。
	failQuality
	// ⭐ 2026-09-27（Bug 3）：**对端主动关闭**（应用层 CONNECTION_CLOSE）——
	// 不是本机链路质量问题，**不排退避、不推进任何 streak**（见 classifyPathFail）。
	failPeerClosed
)

// backoffLadderDeterministic 确定性失败台阶（5min → 15min → 30min → 1h）
var backoffLadderDeterministic = []time.Duration{
	5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour,
}

// backoffLadderQuality 质量差失败台阶（与确定性同档，但用独立 streak）
var backoffLadderQuality = []time.Duration{
	5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour,
}

func classifyPathFail(reason string) pathFailClass {
	switch reason {
	case P2PReasonRateLimited, P2PReasonPeerBusy:
		return failBusy
	// 确定性失败：重试没有意义（身份不匹配 / 服务端开关 / 双方对称 NAT）
	case P2PReasonNATSymmetric, P2PReasonFingerprintMismatch, P2PReasonServerP2PDisabled:
		return failPermanent
	// ⭐ 质量差：打洞成功过，问题在链路质量
	case P2PReasonQualityPoor, P2PReasonProbeTimeout, P2PReasonDirectLost:
		return failQuality
	// ⭐ 2026-09-27（Bug 3）：对端主动关闭 ⇒ 与本机链路质量无关，**不排退避**
	case P2PReasonPeerClosed:
		return failPeerClosed
	// 临时性（含 nat-unknown：探测抖动，且可重探测）
	default:
		return failRetryable
	}
}

// backoffDelayFor 按类别与当前 streak 算出「本次退避时长」以及是否推进 streak。
//
// ⭐ 权威入口：onPunchFailed（打洞会话失败）与 scheduleRetry（路径死亡）都走这里，
// 避免两处各写一套台阶选择逻辑（那正是「台阶互相打架」的来源）。
func backoffDelayFor(class pathFailClass, st backoffState) (time.Duration, bool) {
	switch class {
	case failBusy:
		return backoffBusy, false // 忙不是失败：固定短延迟、不推进
	case failPermanent:
		return ladderStep(backoffLadderDeterministic, st.step), true
	case failQuality:
		return ladderStep(backoffLadderQuality, st.qualityStep), true
	case failPeerClosed:
		// ⭐ 2026-09-27（Bug 3）：对端主动关闭 ⇒ **不排退避**（0 = 调用方跳过写入）。
		//	道理与「仲裁败者不排退避」一致（1b-2A 定稿精神）：这不是本机链路的问题，
		//	给对端记一笔退避反而会让「对端重启后想重连」被自己挡在门外。
		return 0, false
	default:
		return ladderStep(backoffLadder, st.step), true
	}
}

// ladderStep 取第 step 档（0 基，超长则封顶最后一档）
func ladderStep(ladder []time.Duration, step int) time.Duration {
	if step < 0 {
		step = 0
	}
	if step >= len(ladder) {
		step = len(ladder) - 1
	}
	return ladder[step]
}

// logBackoffDecision 打出「走了哪条台阶」（⭐1b-4 第一步：四条日志逐字按规格）
//
// ⚠️ 必须在**锁外**调用（持锁 I/O 会拖慢热路径）。
func logBackoffDecision(peerVIP, reason string, class pathFailClass, d time.Duration) {
	after := d.Round(time.Second)
	// ⭐ 1b-4（review 追问 1）：指纹不匹配是**安全事件**（对端身份验证失败），
	// 不能混在普通的「打洞失败（确定性）」里 —— 它需要独立前缀，并明确告诉用户
	// 「这不是网络问题」，否则用户会去折腾网络/NAT，而真正该做的是排查对端身份。
	if reason == P2PReasonFingerprintMismatch {
		log.Printf("🚨 [安全] 直连对端身份校验失败（%s）：这不是网络问题 —— "+
			"对端出示的证书指纹与本机记录不一致，已拒绝直连并冷却 %v", peerVIP, after)
		return
	}
	switch class {
	case failBusy:
		log.Printf("⚠️ [HARP] 对端忙（%v 后重试）：%s（%s）", after, reason, peerVIP)
	case failPermanent:
		log.Printf("⚠️ [HARP] 打洞失败（确定性，%v 后重试）：%s（%s）", after, reason, peerVIP)
	case failQuality:
		log.Printf("⚠️ [HARP] 直连质量差（%v 后重试）：%s（%s）", after, reason, peerVIP)
	default:
		log.Printf("⚠️ [HARP] 打洞失败（临时性，%v 后重试）：%s（%s）", after, reason, peerVIP)
	}
}

// onPunchFailed 打洞会话失败时调用（由 punchManager 通知）
func (m *pathManager) onPunchFailed(peerVIP, reason string) {
	dst, ok := parseIPv4(peerVIP)
	if !ok {
		return
	}
	class := classifyPathFail(reason)
	now := time.Now()
	m.mu.Lock()
	st := m.backoff[dst]
	st.lastErr = reason
	// ⭐ 1b-4 第一步：统一按类别选台阶 + 只推进**对应**的 streak（忙不推进）
	d, advance := backoffDelayFor(class, st)
	if advance {
		if class == failQuality {
			st.qualityStep++
		} else {
			st.step++
		}
	}
	st.until = now.Add(d)
	m.backoff[dst] = st
	until := st.until
	m.mu.Unlock() // ⭐ 锁内只做决策与写状态；日志与回调放到锁外

	logBackoffDecision(peerVIP, reason, class, d)
	if m.hooks != nil && m.hooks.BackoffSet != nil {
		m.hooks.BackoffSet(peerVIP, time.Until(until))
	}
	// 注意：**不在这里发状态事件** —— 会话自己的 fail() 已经发过 failed 状态了，
	// 这里只负责记退避（UI 会从那条事件里拿到原因码与文案）。
}

// setBackoffTransient 发起失败（前置条件不满足/忙）：短延迟，不推进台阶
func (m *pathManager) setBackoffTransient(dst [4]byte, err error) {
	m.mu.Lock()
	st := m.backoff[dst]
	st.until = time.Now().Add(backoffBusy)
	if err != nil {
		st.lastErr = err.Error()
	}
	m.backoff[dst] = st
	m.mu.Unlock()
}

// delayRetry 只把该对端延后一小会儿（不推进退避台阶）：用于「本机还没就绪」这类本地原因
func (m *pathManager) delayRetry(dst [4]byte, d time.Duration) {
	m.mu.Lock()
	st := m.backoff[dst]
	if want := time.Now().Add(d); st.until.Before(want) {
		st.until = want
	}
	m.backoff[dst] = st
	m.mu.Unlock()
}

// scheduleRetry demote() 的第三步：安排退避重试（路径死掉按「可重试」台阶走）
// setRejectedCooldown ⭐ A2：本侧判负**保留连接**后的**短冷却**（复用 `backoffBusy` = 30s）。
//
//   - 为什么需要：不排冷却 ⇒ 流量立刻再触发打洞（重试风暴），而旧连接还占着资源；
//   - **语义与日志各自独立**（review 纪律：不与 `failBusy` / `failPeerClosed` 合并分支）：
//     `failBusy` = 本机/服务端额度受限；`failPeerClosed` = **对端**把连接关了；
//     本支 = **本侧判定不通过但保留连接**（下一轮复用会重跑试用期，不是"更坏的失败"）；
//   - **不推进任何 streak**（`step`/`qualityStep` 都不动），**保留历史 `lastErr`**。
func (m *pathManager) setRejectedCooldown(dst [4]byte) {
	now := time.Now()
	m.mu.Lock()
	st := m.backoff[dst]
	st.until = now.Add(backoffBusy)
	// ⚠️ 不覆盖 st.lastErr：排障时更想知道「这条路上次为什么失败」（与 failPeerClosed 同口径）
	m.backoff[dst] = st
	m.lastSwitch[dst] = now
	m.mu.Unlock()
	log.Printf("ℹ️ [HARP] %s 判负但**保留连接**（方案 A）：%v 短冷却（不推进档位）",
		ip4ToString(dst), backoffBusy)
}

func (m *pathManager) scheduleRetry(dst [4]byte, reason string) {
	// 路径死亡 = 网络环境变了 → 标记需要重探测 NAT
	m.setNATStale()

	now := time.Now()
	m.mu.Lock()
	st := m.backoff[dst]
	prevErr := st.lastErr
	st.lastErr = reason
	// ⭐ 1b-4 第一步：路径死亡（demote）也按**原因分类**选台阶 —— 原先无条件走 failRetryable 台阶，
	// 导致 direct-lost / probe-timeout（质量差）与 punch-timeout（临时性）共用同一条越走越长的台阶。
	class := classifyPathFail(reason)
	d, advance := backoffDelayFor(class, st)
	// ⭐ 2026-09-27（Bug 3 补）：**对端主动关闭 ⇒ 只排一个固定短冷却，不推进任何 streak**。
	//
	//	⚠️ 为什么必须**单独一个分支**（review 拍板：不与 `failBusy` 合并）：
	//	  - 触发条件不同：`failBusy` = 「本机/服务端额度受限」；本支 = 「对端把连接关了」；
	//	  - 合并后**调值会互相牵制**（改一个影响另一个），且日志无法区分成因；
	//	  - streak 语义不同：本支**不推进任何 streak**（不是本机链路问题），
	//	    `failBusy` 也不推进但走的是 busy 语义。
	//
	//	⚠️ 为什么不「完全不排」（原实现）：不写 `backoff` ⇒ `handleTrigger` 的**退避门**不再拦
	//	  ⇒ 只要还有流量发往该对端就会**立刻**再触发一次打洞（重试风暴）。
	//	  常量**复用 `backoffBusy`（30s）**，但语义与日志各自独立。
	if class == failPeerClosed {
		st.until = now.Add(backoffBusy)
		// ⚠️ 保留此前的真实原因：`peer-closed` 只说明「对端把连接关了」，
		//	而排障时更想知道「这条路上次为什么失败」⇒ 不覆盖历史原因（与其它档位不同）。
		st.lastErr = prevErr
		m.backoff[dst] = st
		m.lastSwitch[dst] = now
		m.mu.Unlock()
		log.Printf("ℹ️ [HARP] %s 由**对端主动关闭**（%s）：%v 短冷却（不推进档位；非本机链路问题）",
			ip4ToString(dst), P2PReasonText(reason), backoffBusy)
		if m.hooks != nil && m.hooks.BackoffSet != nil {
			m.hooks.BackoffSet(ip4ToString(dst), backoffBusy)
		}
		return
	}
	if advance {
		if class == failQuality {
			st.qualityStep++
		} else {
			st.step++
		}
	}
	st.until = now.Add(d)
	m.backoff[dst] = st
	// 防抖：开关守卫（避免直连/中继横跳）
	m.lastSwitch[dst] = now
	m.mu.Unlock() // ⭐ 锁内只做决策与写状态；日志与回调放到锁外

	logBackoffDecision(fmt.Sprintf("%d.%d.%d.%d", dst[0], dst[1], dst[2], dst[3]), reason, class, d)
	if m.hooks != nil && m.hooks.BackoffSet != nil {
		m.hooks.BackoffSet(ip4ToString(dst), d)
	}
}

// resetBackoffFor 清掉某个对端的**全部**失败记录（两个 streak 一起清）。
//
// ⭐ 1b-4 第一步：5 条重置条件（重连 / NAT 重探测成功 / VIP 变更 / 对端换 IP / 稳定 ≥5min）
// 统一走这里，避免五处各写一遍（那正是「两套逻辑打架」的来源）。
//
// ⚠️ 语义边界（review 提醒）：它**只清退避，不碰在飞的路径** ——
// VIP 变更 / NAT 重探测成功时，正在试用期的路径仍然有效（对端 VIP 没变），
// 让它照常跑完试用期；清退避只影响「下次失败从第 0 档开始」。
func (m *pathManager) resetBackoffFor(dst [4]byte) {
	m.mu.Lock()
	_, existed := m.backoff[dst]
	delete(m.backoff, dst)
	m.mu.Unlock()
	if existed {
		log.Printf("♻️ [HARP] 已清除 %d.%d.%d.%d 的失败记录（环境变化/稳定运行）",
			dst[0], dst[1], dst[2], dst[3])
	}
}

// backoffSnapshot 取某对端当前退避状态的**只读快照**（不存在则零值）。
//
// ⚠️ 锁契约：**自己加解锁 m.mu，调用方不得持 m.mu**。只用于「算日志里那个延迟」
// 这类旁路用途；真正的退避写入仍只发生在 onPunchFailed / scheduleRetry 里。
func (m *pathManager) backoffSnapshot(dst [4]byte) backoffState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.backoff[dst]
}

// resetAllBackoff 清掉**所有**对端的失败记录（NAT 重探测成功 / 本机 VIP 变更时用）。
//
// 为什么是「全部」而不是「某一个」：这两个事件说明**本机这一侧**的网络环境变了
// （公网地址/隧道地址变了），所有对端过去失败的原因都随之失效 ⇒ 逐对端清会漏掉
// 「这次没在打洞队列里的对端」。
//
// ⚠️ 锁契约：自己加解锁 m.mu，调用方不得持 m.mu。它只清退避表，
// **不碰在飞路径、不碰路由表**（与 resetBackoffFor 同一语义边界）。
// 返回清掉的条数（>0 才打日志，避免噪声）。
func (m *pathManager) resetAllBackoff(reason string) int {
	m.mu.Lock()
	n := len(m.backoff)
	m.backoff = make(map[[4]byte]backoffState)
	m.mu.Unlock()
	if n > 0 {
		log.Printf("♻️ [HARP] 已清除全部 %d 条失败记录（%s）", n, reason)
	}
	return n
}

// stableEnoughToClearFailures 该路径是否已「持续」稳定运行 ≥5 分钟。
//
// ⚠️ 必须是持续：stableSince 由 setState 维护，任何离开 Up 的转移都会清零，
// 所以这里比较的是「本次连续 Up 的时长」，不是累计时长。
//
// ⭐ 并发安全（review 确认 1）：`stableSince` 与 `state` 是**两个独立的原子量**，
// setState 的顺序是「先写 state 再写 stableSince」式的两步 ⇒ 理论上读者可能读到
// 「新的 state=Up」+「旧的 stableSince（上一次 Up 的时刻）」，从而把刚进入 Up 的路径
// 误判成「已稳定 5 分钟」（提前清失败记录）。窗口极小且后果轻微，但既然能廉价消除就消除：
// 读完后**重读一次** stableSince，要求两次一致（期间若发生过任何状态转移，值必然变化/清零）。
// 不引入新锁：double-read 已覆盖实际交错，且避免把 p.mu 拉进 setState 造成的锁序风险。
func (p *directPath) stableEnoughToClearFailures(now time.Time) bool {
	since := p.stableSince.Load()
	if since == 0 || p.state.Load() != pathStateUp {
		return false
	}
	if p.stableSince.Load() != since { // 期间发生过状态转移 ⇒ 本次不判定
		return false
	}
	return now.Sub(time.UnixMilli(since)) >= stableClearFailuresAfter
}

// stableClearFailuresAfter 「稳定运行多久后清空该对端失败记录」（⭐1b-4 第一步：5 分钟）
//
// ⚠️ var 而非 const：集成用例要把它压到几百毫秒才测得起（与 m.checkInterval 等可注入参数同理；
// 默认值本身由 TestStableClearFailuresDefaultIsFiveMinutes 钉住）。
var stableClearFailuresAfter = 5 * time.Minute

// onPunchSucceeded 打洞会话成功时调用（由 punchManager 通知）：清退避 = 环境又好使了
func (m *pathManager) onPunchSucceeded(peerVIP string) {
	if dst, ok := parseIPv4(peerVIP); ok {
		m.mu.Lock()
		delete(m.backoff, dst)
		delete(m.evictAfter, dst)
		m.mu.Unlock()
	}
}

func (m *pathManager) backoffStep(peerVIP string) int {
	dst, ok := parseIPv4(peerVIP)
	if !ok {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.backoff[dst].step
}

// ---------- NAT 失效标记（§4.4） ----------

func (m *pathManager) setNATStale() { m.natStale.Store(true) }

// takeNATStale 取走标记（true 表示需要重探测）
func (m *pathManager) takeNATStale() bool { return m.natStale.Swap(false) }

// ---------- ⭐ 1b-4 第一步：5 条「清空失败记录」的重置hook ----------
//
// 统一落点 = resetBackoffFor（单对端，两个 streak 一起清）/ resetAllBackoff（本机侧变化，全部清）。
// 五条条件与各自的接线点（逐点标注见调用处）：
//  1. 重连（Connect）        → `startPunchManager` 每次连接都 newPathManager（退避表天然从空开始）
//  2. NAT 重探测成功         → `resetAllBackoff`（本机公网地址变了 ⇒ 所有对端作废）
//  3. VIP 变更              → `ResetBackoffAll`（本机隧道地址变了 ⇒ 同上）
//  4. 对端换 IP（4G↔WiFi）   → `notePeerPublicAddr`（信令返回的 peerPublicAddr 变化）
//  5. 稳定运行 ≥5 分钟       → `maybeClearFailuresAfterStable`（看门狗每秒判一次）

// notePeerPublicAddr 记录/对比「对端公网地址」（Q3）。
//
// 落点：所有拿到 `SignalPeer.PublicAddr` 的地方（信号门 / 中继 RTT 刷新）——
// 本机的 refreshNAT 与到服务端的 hostRTT 都观察不到对端 IP，只有信令返回值能。
//
// 地址变化 ⇒ 对端换了网络 ⇒ **清空该对端的失败记录**（4G↔WiFi 后原来的 nat-symmetric /
// punch-timeout 结论不再成立，正是「不该让它吃 15 分钟冷却」的场景）。
//
// ⚠️ 锁契约：本函数自己加解锁 m.mu；调用方不得持 m.mu。
// 命中变化时调用 resetBackoffFor —— 那是**顺序**取锁（先放 m.mu 再取），不是嵌套。
func (m *pathManager) notePeerPublicAddr(dst [4]byte, addr string) {
	if addr == "" {
		return // 服务端不知道 / 旧服务端：没有可比对的观测值，不做任何判断
	}
	m.mu.Lock()
	prev, seen := m.peerAddrSeen[dst]
	m.peerAddrSeen[dst] = addr
	m.mu.Unlock()
	if !seen || prev == addr {
		return // 首次观测（建基线）/ 没变 ⇒ 不动退避
	}
	log.Printf("🔄 [HARP] 对端 %s 公网地址已变化（%s → %s）：清除其失败记录（环境变了）",
		ip4ToString(dst), prev, addr)
	m.resetBackoffFor(dst)
}

// ResetBackoffAll 清掉所有对端的失败记录（本机 VIP 变更时由客户端调用）。
//
// ⚠️ 锁契约：只取 m.mu，不做任何 I/O；调用方（客户端）不得持与路径管理器相关的锁。
func (m *pathManager) ResetBackoffAll(reason string) int { return m.resetAllBackoff(reason) }

// maybeClearFailuresAfterStable 第 5 条重置：直连**持续**稳定 ≥5 分钟 ⇒ 清该对端失败记录。
//
// 「持续」由 stableSince 保证（离开 Up 即清零，见 setState）⇒ 累计时长不算数。
//
// ⚠️ 锁契约（设计 §9 的标注要求）：本函数**不持 m.mu 做判定** ——
//   - `stableEnoughToClearFailures` 只读原子量（内部 double-read，见其注释）；
//   - `backoffSnapshot` 自己加解锁；
//   - `resetBackoffFor` 再自己加解锁（顺序取锁，绝不与外层锁嵌套）。
//
// ⚠️ 节流：≥5 分钟的判据没必要每拍都查，按 checkInterval 的整数倍（≈2s）节流一次。
// 看不到退避记录的路径直接短路返回（绝大多数路径处于这种情形）。
func (p *directPath) maybeClearFailuresAfterStable(now time.Time) {
	last := p.lastStableCheck.Load()
	minGap := p.mgr.checkInterval * 2
	if minGap <= 0 {
		minGap = 2 * time.Second
	}
	if last != 0 && now.UnixMilli()-last < minGap.Milliseconds() {
		return
	}
	p.lastStableCheck.Store(now.UnixMilli())
	if !p.stableEnoughToClearFailures(now) {
		return
	}
	if _, ok := p.mgr.hasBackoff(p.peer); !ok {
		return // 没有失败记录 ⇒ 无事可做（省掉一次日志与加锁）
	}
	p.mgr.resetBackoffFor(p.peer)
}

// hasBackoff 该对端当前是否有失败记录（只读快照）
//
// ⚠️ 锁契约：自己加解锁 m.mu，调用方不得持 m.mu。
func (m *pathManager) hasBackoff(dst [4]byte) (backoffState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.backoff[dst]
	return st, ok
}

// ---------- 路径建立与仲裁（§5.2.1 / Q15） ----------

// establishedReq 一次成功打洞移交过来的所有权
type establishedReq struct {
	peerVIP  string
	peer     [4]byte
	role     string // initiator（= 我方是 QUIC listener）| responder
	conn     directConn
	closers  []func() error
	myVIP    [4]byte
	peerAddr string
	// ⭐ 打洞阶段**已经测到**的 RTT（应用层探针 / QUIC stats）。
	// 不 seed 的话路径的 RTT 初始是 0，而「只有响应方在探针」的实现里
	// 发起方会**永远**显示 0（真机上就是这样被发现的）。
	rttDirect time.Duration
	rttQuic   time.Duration
	// scoutWindowMs 邀请里声明的打洞窗口（ms）⇒ 落到 directPath.scoutWindowMs（B1 启发式用）。
	scoutWindowMs int
}

// arbitrationKeeps 仲裁判据（Q15）：这条路径是不是「合法胜者」。
//
// 胜者 = 「**VIP 较小的一方作为 QUIC listener（role=initiator）**」的那条连接。
// 双方各自独立判定，结论必然一致（无需通信）：
//
//	本机 VIP 较小 ⇒ 本机应当是 listener（role=initiator）
//	本机 VIP 较大 ⇒ 本机应当是拨号方（role=responder）
//
// ⚠️ 它同时用于「既有路径」和「新来路径」，所以两侧、两条路径用的都是**同一条规则**；
//
//	真机 bug 的教训见 handleEstablished 的注释（判定与装表必须原子）。
func arbitrationKeeps(peerVIP, myVIP [4]byte, role string) bool {
	wantInitiator := bytesGreater(peerVIP, myVIP) // 我 VIP 较小 ⇒ 应该由我发起（我是 listener）
	return wantInitiator == (role == pathRoleInitiator)
}

// handleEstablished 接管一条成功的直连（P0：所有权从 punchSession 转到 pathManager）。
//
// ⭐ 1b-4 第一步（**先验后切**）：这里**不再装路由表** —— 打洞+握手成功只说明「通道打通了」，
// 不代表「这条路比中继好」。所以本函数把路径置为 `pathStateTrial`、启动数据面、
// 发一条 `trial` 状态事件，然后**立即返回**；装表要等看门狗的试用期判定通过（见 evalTrial）。
//
//	好处：用户感知从「直接切过去然后可能又切回来（抖动）」变成「一直在中继上，验好了才切」。
//	代价：trial 期间该对端**不在路由表里** ⇒ 重连触发（Observe）不会命中，
//	      但也没关系 —— 路径已经在手上了，试用期通过就装表。
//
// 仲裁（Q15）：同一对端只保留「**VIP 较小的一方作为 QUIC listener（发起方）**」的那条连接。
// 双方都能独立判定（我是不是发起方 + 我 VIP 大小），结论一致，无需通信。
//
// ⚠️ 1b-4 起仲裁**只在装表点**发生（trial 期间路径不进路由表 ⇒ `existing` 天然为 nil，
//
//	两条 trial 各跑各的试用期是**故意**的）。仲裁临界区见 `installAfterTrial`。
//
// 真机 bug 的教训（1b-2B）仍然适用：读旧表 → 仲裁 → 装表必须在同一个 routeMu 临界区内完成，
// 否则两个并发调用会双双看到 existing==nil → 双双装表：
//   - 败者既不关闭也不摘除 ⇒ 泄漏一条连接（两条 conn 同时活着）；
//   - 最终路由取决于「谁最后装」⇒ 两侧可能各自指向**不同**的物理连接；
//   - 接着各自把「对方正在用的那条」当败者关掉 ⇒ 两条连接全死、直连中断回退中继
//     （真机日志：`连接已关闭：Application error 0x0 (remote): path closed`）。
func (m *pathManager) handleEstablished(req establishedReq) {
	// 上限与淘汰（§6.2）：放在临界区之前（evictLRU 自己会加 routeMu）。
	//
	// ⭐ 1b-4：试用中的路径也要计入上限 —— 它们虽然不承载流量，但**连接是真的**，
	// 不计数就会「8 条直连 + N 条试用」把 socket/goroutine 顶爆。
	if len(*m.routes.Load())+m.trialPathCount() >= pathMaxPaths {
		m.evictLRU()
	}
	p, err := newDirectPath(m, req)
	if err != nil {
		log.Printf("⚠️ [HARP] 建立直连路径失败（%s）：%v", req.peerVIP, err)
		for _, c := range req.closers {
			_ = c()
		}
		return
	}

	// ---- 临界区：登记为「试用中」+ 启动数据面（原子） ----
	//
	// ⚠️ 这里**不做仲裁、不进路由表**（设计 §9 Q1）：
	//    - `sinkFor` 只认 Up ⇒ trial 期间数据自然走中继；
	//    - 后到的第二条 trial 天然看到 `existing == nil` ⇒ 两条各跑各的试用期（**故意**的）；
	//    - 只有 `Paths()`（面板显示「测试中」）与 `close()`（关停要一起关）看得见它们。
	//
	// ⚠️ `run()` 必须在锁内：否则存在「已登记但还没 run」的窗口，管理器 close() 会拿到
	//    这条**还没 wg.Add 的**路径并 wait() —— 并发 Add/Wait 属于 WaitGroup 误用
	//    （1b-2B 的 -race 实测报过同款）。
	//    📌 **交叉引用**：见 `run()` 头注释的「已知调用点（1 处生产 + 11 处测试）」与
	//    「不得同步取 `routeMu`」两段 —— **不得**把 `run()` 挪到 `Unlock()` 之后。
	m.routeMu.Lock()
	m.addTrialPath(p)
	p.run()
	m.routeMu.Unlock()

	// ⭐ 1b-4：进入试用期 = 两条通道都必须发 `trial`（面板走 pathStateName、事件走这里）
	log.Printf("✅ [HARP] 通道已建立：%s（role=%s，RTT=%s；进入试用期，数据仍走中继）",
		req.peerVIP, p.role, rttText(p.rtt.Load()))
	p.logTrialEnter()
	m.emit(p.status(P2PStateTrial, P2PReasonTrialProbing))
}

// rttText RTT 的显示文案：**绝不显示 0**
//
// ⭐ 1b-1 定稿规则（msAtLeast1）：测到了但小到本地时钟分辨不出（Windows 上真的会出现 0）
// 也要报 1ms；**没测到**时显示「待测」，而不是让人误以为「0ms = 极快」。
func rttText(ns int64) string {
	if ns <= 0 {
		return "待测"
	}
	return fmt.Sprintf("%dms", msAtLeast1(ns))
}

// evictLRU 淘汰最久无上下行流量的一条路径
func (m *pathManager) evictLRU() {
	paths := m.snapshotPaths()
	if len(paths) == 0 {
		return
	}
	victim := paths[0]
	for _, p := range paths[1:] {
		if p.lastUse.Load() < victim.lastUse.Load() {
			victim = p
		}
	}
	log.Printf("📴 [HARP] 路径数达上限(%d)，淘汰最久未使用：%s", pathMaxPaths, victim.peerVIP)
	m.removeRoute(victim.peer, victim)
	victim.close()
	victim.waitTimeoutLogged("上限淘汰")
	m.mu.Lock()
	m.evictAfter[victim.peer] = time.Now().Add(m.recreateDelay)
	m.mu.Unlock()
}

// ---------- 直连路径 ----------

const (
	pathStateUp int32 = iota + 1
	pathStateDown
	// ⭐ 1b-2B：standby —— 连接与探针都保留，**只是不用它承载流量**。
	//
	// 与 relay/backoff 的区别（四个状态互相独立）：
	//   - direct（Up）   ：路由表里有它，写协程按表把流量走直连
	//   - standby        ：路由表里**也有它**，但 sinkFor 只认 Up → 流量自动回中继
	//   - relay          ：路由表里没有它（从未建立 / 已降级 / 已淘汰）
	//   - backoff        ：路由表里没有它 + 退避表里有冷却（失败后等待重试）
	// 关键：standby **不走 L1**（L1 是写错误/读错误/连接关闭 → 关路径），
	// standby 只切流量，连接留着，所以恢复时可以零成本切回。
	pathStateStandby
	// ⭐ 1b-4 第一步：试用期（先验后切）。
	//
	// 与另外四个状态的区别：
	//   - **不进路由表**（安装由试用期通过后单独做）⇒ `sinkFor` 只认 Up ⇒ 数据自动走中继；
	//   - 与 standby 一样属于「还活着」（alive() 为 true）⇒ 探针/读写协程继续跑，
	//     否则试用期拿不到任何样本（L2 也就无从触发）；
	//   - L1/L2 在试用期内**照常生效**：触发即关路径、按自己的原因码走退避，不等满 15s。
	pathStateTrial
	// ⭐⭐ A2（方案 A）：本侧判负但**保留连接**。
	//
	// 与 `pathStateDown` 的关键区别（这是方案 A 的全部意义）：
	//   - **不进路由表**（本侧不主动发数据）⇒ 与 trial 一样不占路由槽位；
	//   - **连接保持可用**：`ctrlLoop` 照旧回显对端探针（否则对端会 probe-timeout、
	//     把它自己那条也判负 ⇒ 变成「两边都关」，正是要修的那个 bug）；
	//   - 纳入 `alive()` ⇒ 探针/读写协程继续跑；
	//   - 有**自己的 TTL**（`trialRejectedTTL`，由已有 `pruneLoop()` 淘汰 ⇒ 零新增 goroutine）。
	pathStateRejected
	// ⭐ A2：复用**已保留**的连接重跑试用期。
	//
	// 与「新建一条路径」的区别：这是**同一个对象的转换** ⇒ `runOnce` / `watchLoop` 都不重启
	// （`watchLoop` 是常驻 for/select，`checkT` 就跑在它里面；`Run` 只允许跑一次）。
	// `reuseCount` 随之自增（路径级、**不重置**），只服务日志与排障。
	pathStateReusing
	// ⭐ A2：`Rejected` 的**收尾中间态**（对端关闭 / 超时后正在关连接）。
	//
	// ⚠️ **不**纳入 `alive()`：此刻已决定不再使用这条连接 ⇒ 不让探针/新样本再产生
	// （否则会与收尾竞争）。存在的意义是把「收尾中」与「已判负待复用」区分开。
	pathStateRejectedSettling
	// pathStateSentinel **不是状态**：它是「已知状态数」的**唯一真相源**（哨兵）。
	//
	// ⭐ A1（2026-09-27）：为什么需要它 —— `pathStateName` 原来有个
	// `default: return "unknown"`，于是**新增状态忘了加 case 时不会红**，只是静默变成
	// "unknown"（面板上多一行看不懂的状态，排障者没有任何信号）。
	//
	//	⇒ 修法：哨兵 + `allPathStates()` 由**区间推导**（不是手工清单，避免 D1-a 那种
	//	  「双清单漂移」）+ 用例遍历断言「每个状态都有名字」：
	//	    · 新状态加在 sentinel **之前**、忘加 case ⇒ 遍历到 ⇒ 得到 "unknown" ⇒ **红**；
	//	    · 新状态误加在 sentinel **之后** ⇒ `TestPathStateSentinelIsLast` ⇒ **红**。
	//
	//	⚠️ 新增状态时**只需做两件事**：在 `pathStateTrial` 与本行之间加常量；
	//	  在 `pathStateName` 加 case。**不需要**同步任何清单。
	//
	//	⚠️⚠️ 位置纪律（**必须**加在 sentinel 之前）：哨兵之后的常量**不在** `allPathStates()`
	//	  的遍历范围内 ⇒ 那条「必须有名字」的守卫**看不到它**。
	//	  这个洞**不能**靠"再维护一份手工清单"来补（实测：那样两份清单会各自漏，双双静默失效）。
	//	  ⇒ 改用**源码级解析**兜底：`TestPathStateConstBlockHasNoStateAfterSentinel`，两条规则：
	//	    · **规则 A（块内位置）**：本块内哨兵**之后**不得再声明任何常量 ——
	//	      判据**只看位置**，对 Go 的 4 种常量写法（显式/省略 × iota/固定值）一视同仁；
	//	    · **规则 B（跨块）**：**别的** const 块里不得出现 `pathState*` 常量 ——
	//	      Go 的 `iota` **每个 const 块独立**（新块从 0 重新计数）⇒ 放错块会落到
	//	      [1, sentinel) 之外或与现有状态**撞值**，同样逃过穷举。
	//	  零工具链依赖、零手工清单。
	pathStateSentinel
)

// ⚠️ **不再有 `maxPathState()`**（A1 复盘，2026-09-27）：
//
//	它曾用于守卫「不得把状态加在哨兵之后」，但实现是遍历一份**手工清单**
//	⇒ 与 `pathStateSentinel` 构成"双清单"（D1-a 踩过同型问题）：
//	「把状态加在哨兵之后 **且** 忘加进那份清单」⇒ 两个守卫**双双静默失效**（实测确认）。
//
//	⇒ 换成**源码级解析**：`TestPathStateConstBlockHasNoStateAfterSentinel` 用 `go/parser`
//	  直接解析本文件，两条规则：**规则 A** 哨兵之后（同块内）不得再有常量（只判位置，
//	  4 种写法一视同仁）；**规则 B** 别的 const 块不得声明 `pathState*`（iota 每块独立）。
//	  零工具链依赖、零手工清单。**请勿重新引入任何"状态清单"**（那是双清单的复发形态）。
//
//	⚠️ 该守卫自身被有牙验证抓到过**两次**洞（都留了合成样本，见 detector 用例）：
//	  ① 第一版只认「显式 `= iota`」⇒ 省略式（继承 iota）**不红**；
//	  ② 第二版改成「按上一条是否自动编值继承判断」⇒ **固定值写法**（③ 显式 `= 7`、
//	     ④ 哨兵是固定值时的省略式）被判成"非自动编值 ⇒ 放过"，**仍然不红**。
//	  ⇒ 最终版**彻底不做 iota 语义分析**，只判位置 ⇒ 结构上不可能再漏。

// allPathStates 所有**合法路径状态**（由区间推导 —— 唯一真相源是 `pathStateSentinel`）
//
// 用途：`TestPathStateNameCoversAllStates` 遍历它，断言每个状态都有名字
// ⇒ 「新增状态忘登记」变成**编译后必红**，而不是静默 "unknown"。
func allPathStates() []int32 {
	out := make([]int32, 0, pathStateSentinel-1)
	for s := int32(1); s < pathStateSentinel; s++ {
		out = append(out, s)
	}
	return out
}

// pathStateName 状态 → 稳定英文标识（面板 `Paths()` 与 `p2p:status` 两条通道共用）。
//
// ⚠️ **必须穷举所有合法状态**（见 `pathStateSentinel` 的说明）：
// 新增状态时在这里加 case，否则 `TestPathStateNameCoversAllStates` 会红。
func pathStateName(s int32) string {
	switch s {
	case pathStateUp:
		return "direct"
	case pathStateTrial:
		return "trial" // ⭐ 1b-4：面板与 p2p:status 两条通道都要能看到试用期
	case pathStateStandby:
		return "standby"
	case pathStateRejected:
		return "rejected" // ⭐ A2：本侧判负、**保留连接**（对端可能仍在用）
	case pathStateReusing:
		return "reusing" // ⭐ A2：复用保留的连接，重跑试用期
	case pathStateRejectedSettling:
		return "rejected-settling" // ⭐ A2：Rejected 收尾中（**不**纳入 alive）
	case pathStateDown:
		return "relay"
	default:
		log.Printf("⚠️ [HARP] 未知路径状态 %d（内部不一致：请检查 pathStateName 是否漏登记）", s)
		return "unknown"
	}
}

type directPath struct {
	mgr     *pathManager
	peer    [4]byte
	peerVIP string
	role    string
	myVIP   [4]byte
	conn    directConn
	closers []func() error
	since   time.Time
	// scoutWindowMs 建立这条路径的那次打洞邀请里，**对端**声明的打洞窗口（毫秒）。
	//
	// ⭐ 2026-09-27（B1）：只服务灰度期的「响应方探路收尾」启发式（见 scoutTearDownHeuristic）。
	// 0 表示对端没传（旧版本 omitempty）⇒ 判据侧按 `punchWindowDefault` 兜底。
	scoutWindowMs int

	state     atomic.Int32
	bytesUp   atomic.Uint64
	bytesDown atomic.Uint64
	lastUse   atomic.Int64
	rtt       atomic.Int64

	// 每**流**一条有界队列（§2.2.1①）：写协程只做非阻塞入队。
	//
	// ⭐ Q1 的分组：关键小包（ICMP/match/游戏 TCP）与批量流量（bulk TCP/可靠 UDP）
	//    分属两条流 + 两条独立队列 → 前者**不会**排在后者后面等流控窗口。
	txBulk chan pathPkt
	txCrit chan pathPkt

	// ⚠️ 三条流必须在 mu 下访问：setup() 在**另一个 goroutine**里赋值，
	//    而 close()（可能由看门狗/管理器/测试触发）会读它们 —— 裸字段是数据竞争。
	mu         sync.Mutex
	bulkStream directStream
	critStream directStream
	ctrlStream directStream
	peerAddr   string

	lastProbe  atomic.Int64 // 发起方：最近一次收到探测的时刻（ms）
	lastEcho   atomic.Int64 // 响应方：最近一次收到回显的时刻（ms）
	probeMiss  atomic.Int32
	probeSeq   atomic.Int64
	echoedOnce atomic.Bool

	// ⭐ 1b-2B：standby 判据用的状态（全部原子量，看门狗每秒读写）
	//
	//	relayRtt   —— 服务端给的中继 RTT 估计（ns；0 = 未知 → 不做 standby 判断）
	//	relayRttTriedAt —— 上次刷新时刻（ms；用于「超过 5 分钟判过期、判断前先查一次」）
	//	degradeSince —— 「直连劣于中继」这一条件**首次成立**的时刻（ms；0 = 当前不成立）
	//	lastStandbyEval —— 上次「standby 复查」的时刻（ms）
	relayRtt        atomic.Int64
	relayRttTriedAt atomic.Int64
	degradeSince    atomic.Int64
	lastStandbyEval atomic.Int64
	// stableSince 进入 Up 的时刻（ms）—— ⭐1b-4：稳定运行 ≥5min 才清失败记录。
	// 由 setState 维护（离开 Up 即清零 ⇒ 持续语义，不是累计语义）。
	//
	// ⚠️⚠️ **读序契约（review 追问：CAS 后这里仍是两步写）**：
	// `state` 与 `stableSince` 是**两个独立原子量**，任何转移都是「先写 state、再写 stableSince」。
	// 因此读侧**必须保证 state 先读、stableSince 后读**；现有读点只有
	// `stableEnoughToClearFailures`（顺序：state →（判 !=Up 即返回）→ stableSince → double-read）
	// 与 `maybeClearFailuresAfterStable`（顺序：stableEnoughToClearFailures → hasBackoff）。
	// **若将来有人把读侧顺序改成「先读 stableSince 再读 state」，必须同时重审这条契约。**
	//
	// 为什么现在的顺序安全（逐种交错核过）：
	//   - **enterStandby**：CAS 把 state 写成 Standby，随后才 Store(0) ⇒ 读侧在窗口内看到
	//     「state=Standby + stableSince=旧值」，但第一条判据 `state != Up` 直接返回 false
	//     （注意：不是「Standby + 旧值被误用」，而是**根本走不到用它的那一步**）；
	//   - **exitStandby**：CAS 把 state 写成 Up，随后才 Store(now) ⇒ 窗口内读到「state=Up + 0」
	//     ⇒ `since == 0 ⇒ false`（保守，不清失败记录）；
	//   - **setState / 其它**：写法与上面同一方向（state 先落地），同理；
	//   - **唯一能让 stableSince「偏新」的方向是 exitStandby(Standby→Up)**：多读只会把时长
	//     算**短** ⇒ 结论是「不清」，属**安全方向**（宁可多等，不可提前清）。
	//   ⇒ 现在这套顺序下不存在「被误判成已稳定 5 分钟」的交错；改成反序就可能出现，故立此契约。
	stableSince atomic.Int64

	// ---- ⭐ 1b-4 第一步：试用期（trial）状态 ----
	//
	// 与 stableSince 同类：**全部原子量** —— 看门狗每秒读写，且要能 double-read 判定，
	// 不引入新锁（把 p.mu 拉进状态机只会制造锁序风险）。
	// trialStartedAt 进入 trial 的时刻（ms）；0 = 从未进入（或已结束）
	trialStartedAt atomic.Int64
	// trialSamples 已统计的样本数（每个 samplesTick 记一个：有回显=好，无回显=坏）
	trialSamples atomic.Int32
	// trialGood 其中「质量好」的样本数（判据见 trialSampleGood）
	trialGood atomic.Int32
	// watchdogTicks 看门狗跑过的拍数（**纯观测，零语义**；B2 2026-09-28 新增）。
	//
	//	⚠️ 存在的理由：用例需要断言"看门狗确实在跑"（否则"没结算"可能只是看门狗没动 ⇒ 假绿）。
	//	B2 之前那个判据是 `trialLastSampleAt` 是否前进；B2 修复后**无回显时不再推进闸门**
	//	（这正是修复点）⇒ 旧判据失效 ⇒ 改用这个计数器。
	//	⚠️ **自增点在 `watchLoop` 的调用处**（不是 `evalTrial` 内部）：用例会直接调用采样函数，
	//	放进内部会让该断言被伪造。
	watchdogTicks atomic.Int64
	// trialLastSampleAt 上一个样本的判定时刻（ms）—— 样本按 probeInterval 节流
	trialLastSampleAt atomic.Int64
	// trialLastEcho 上一个样本判定时看到的 lastEcho（用于判「这个样本窗里有没有回显」）
	//
	// ⚠️ **基线必须在「进入试用期」那一刻写**（见 `newDirectPath` 里紧随 `trialStartedAt` 的那行），
	//	不能拖到第一个采样点才写：
	//	  进试用期 → t=1s 第一采样点（写基线）→ t=5s 第一个探针回显 → t=6s 采样①
	//	若基线写在 t=1s，t∈[0,1s) 的回显被吃掉还好；但**第一个 probeInterval 窗**（t∈[0,5s)）
	//	里到达的回显会**全部**落在基线之前 ⇒ 15s 窗口名义「3 个样本」实际只有 **2 个采样点**
	//	（3 取 2 ⇒ 容错为 0）。真机上任何一次探针抖动都会让试用期失败（2026-09-27 记账）。
	trialLastEcho atomic.Int64
	// trialLastDirectRtt 最近一次测到的直连 RTT（ns）—— 只用于日志
	trialLastDirectRtt atomic.Int64
	// trialEchoInc 「本样本窗内观测到新回显」的样本数（仅测试/诊断）
	// trialRelayRtt 试用期开始时快照的中继 RTT（ns）—— 日志与判据都用它
	trialRelayRtt atomic.Int64
	// trialDone **第二道取消门**：试用期判定只允许结算一次（CAS）。
	// demote() / close() / 被仲裁丢弃 都会置位；已置位 ⇒ 判定直接放弃，杜绝双写。
	trialDone atomic.Bool
	// untrack 把自己从管理器的「试用中」登记里摘掉（幂等；由 newDirectPath 装配）。
	// demote() / close() 都会调用它 ⇒ 路径无论怎么结束，登记都不会留下悬挂指针。
	untrack func()
	// lastStableCheck 「稳定 ≥5min ⇒ 清失败记录」的节流时刻（ms；≈每 2s 查一次）
	lastStableCheck atomic.Int64

	// ⭐ 数据面健康观测（review 追问 3）：
	//   enqueued  = 「有多少包被交给这条路径去发」（出队时计数）
	//   silentWarned / oneWayWarned = 只告警一次
	// 判据设计成**只告警不降级**：告警负责可观测性（让「direct 但不通」在日志/面板可见），
	// 淘汰与降级负责资源与切换；这样既不会把 bug 掩盖成「正常空闲」，也不会误杀正常路径。
	enqueued       atomic.Uint64
	silentWarned   atomic.Bool
	oneWayWarned   atomic.Bool
	datagramWarned atomic.Bool
	setupTimeout   time.Duration // 0 = punchHandshakeTimeout（测试可注入更短的值）

	closeOnce sync.Once
	// terminateOnce（原 `demoteOnce` 改名）**只给 `terminateDown` 独占**。
	//
	// ⚠️ A2 纪律：`releaseRejected`（TTL 到期 / 对端关闭时的专用清理）**绝不能**共用它 ——
	//	共用会让「复用之后连接真断」那一步的 `close()` 被 once 吞掉 ⇒ **连接泄漏 + PATH-LEAK 亮**。
	//	（由 `TestTerminateOnceOnlyForDown` 用 `PathClosed` 钩子计数钉住；设计期已排除共用方案。）
	terminateOnce sync.Once
	runOnce       sync.Once

	// ⭐ A2（方案 A）：**收尾门**，**可重置**（复用 = 新一轮生命周期）。
	//	为什么不是 `sync.Once`：Go 里把 once 的 done 归零会导致**逻辑级 double execution**
	//	（不是"重置一次"那么温和）⇒ 一律用 `atomic.Bool` + CAS。
	settled atomic.Bool
	// reuseCount 路径级复用次数（**不重置**，只服务日志与排障）。
	reuseCount atomic.Int32
	// rejectedAt 进入 `Rejected` 的时刻（ms）—— TTL 淘汰的**唯一判据**（白名单见 evictIdle）。
	rejectedAt atomic.Int64
	wg         sync.WaitGroup
	// leakKey ⭐ 第 3 步-D：测试侧埋点（记录创建栈），仅用于**定位未关闭的路径**；
	// 生产路径同样会赋值，但只在测试的 TestMain 里被读取/统计。
	leakKey string
	// demotedCh 在 demote() 发生时关闭（测试用：精确等待降级完成）
	demotedCh chan struct{}
	// ready 由 setup() 在两条流建好后关闭；5 个数据面 goroutine 都在它之后才真正干活。
	// 这样 `wg.Add` 只在 run() 里发生一次（不会与 close() 的 Wait 竞争）。
	ready     chan struct{}
	readyOnce sync.Once

	// ⭐ 第 3 步-B：带界等待（`waitTimeout`）用 —— 每条路径最多起一个「等 wg」的协程。
	waitDoneOnce sync.Once
	waitDoneCh   chan struct{}
}

func newDirectPath(m *pathManager, req establishedReq) (*directPath, error) {
	p := &directPath{
		mgr:       m,
		peer:      req.peer,
		peerVIP:   req.peerVIP,
		role:      req.role,
		myVIP:     req.myVIP,
		conn:      req.conn,
		closers:   req.closers,
		peerAddr:  req.peerAddr,
		since:     time.Now(),
		ready:     make(chan struct{}),
		demotedCh: make(chan struct{}),
		// ⭐ B1：对端声明的打洞窗口（灰度期「响应方探路收尾」启发式用；0 ⇒ 判据侧兜底）
		scoutWindowMs: req.scoutWindowMs,
	}
	p.txBulk = make(chan pathPkt, pathTxQueue)
	p.txCrit = make(chan pathPkt, pathTxQueue)
	p.lastUse.Store(time.Now().UnixMilli())
	// ⭐ 1b-4 第一步（**先验后切**）：新建路径进 **trial**，不进路由表 —— 数据继续走中继。
	//
	// ⚠️ 这一行与 handleEstablished 的「只登记试用表」+ 看门狗试用期判定是不可分割的整体
	//    （设计 §8.1）：只改这里会让直连再也装不上表。
	// trial 的起点时刻也在这里落：看门狗用「进入 trial 的时刻 + 窗口」判定是否结算。
	p.setState(pathStateTrial)
	p.trialStartedAt.Store(time.Now().UnixMilli())
	// ⭐ 试用期采样基线**在此刻**落（与 trialStartedAt 同一时点）——**不能**拖到第一个采样点：
	//   拖晚会把「第一个 probeInterval 窗内的回显」整段吃掉，使 15s 窗口只剩 2 个采样点
	//   （名义 3 个），3 取 2 的容错归零。详见 `trialLastEcho` 字段注释与
	//   `TestTrialBaselineSampledFromTrialEntry`。
	p.trialLastEcho.Store(p.lastEcho.Load())
	// 中继 RTT 基准的初始种子（测试注入；生产恒 0 ⇒ 等 refreshRelayRTT 填）
	if m.trialRelayRttSeed > 0 {
		p.trialRelayRtt.Store(m.trialRelayRttSeed)
	}
	// 装配「注销试用登记」的幂等闭包（见 directPath.untrack 的说明）
	p.untrack = m.detachTrialPath(p)
	// ⭐ 继承打洞阶段测到的 RTT（见 establishedReq.rttDirect 的说明）
	if req.rttDirect > 0 {
		p.rtt.Store(int64(req.rttDirect))
	} else if req.rttQuic > 0 {
		p.rtt.Store(int64(req.rttQuic))
	}
	// ⭐ 第 3 步-D：测试侧泄漏定位埋点（记录创建栈键；生产无副作用）
	p.leakKey = notePathCreated()
	return p, nil
}

// ---------- ⭐ 1b-4 第一步：试用期（先验后切）判定 ----------
//
// 判定对象：**已经在 trial 里的路径**（打洞 + 握手成功、数据仍走中继）。
// 三条判据（设计 §1）：窗口 15s（质量好记录 ⇒ 5s）、样本间隔 = probeInterval（5s）、
// 「3 取 2」（缩短期「2 取 2」）、单样本 = `directRtt < relayRtt×0.8` **且** 成功率 ≥90%。
//
// ⚠️ 本函数只由看门狗（checkTicker）调用 ⇒ **单飞**，无需再加锁。
//    状态读取一律原子量 + double-read，不碰 p.mu（避免与 demote/close 形成锁序）。

// trialGoodEnough 已收集到足够多的「质量好」样本 ⇒ 可以提前通过（不等满窗）
func (p *directPath) trialGoodEnough() bool {
	return int(p.trialGood.Load()) >= p.trialNeedGood()
}

// ---------- ⭐ 灰度期启发式：响应方「探路收尾」判定（2026-09-27，B1 切片） ----------

// scoutEchoMargin 「对端最后一次回显」允许晚到的余量。
//
// ⚠️ 只覆盖 **RTT + ticker 抖动**（毫秒~百毫秒级）——**不得**放宽到 `probeInterval`：
//
//	那会把误报窗口从 1s 放大到 5s，把「对端活过它自己的探路窗口之后才断线」误判成探路收尾。
//	（回显被**量化到探针拍**：对端只能回显它收到的探针 ⇒ 上界 = 「Δ 之前最后一个探针拍 + RTT」。）
//
// ⚠️ 本值假设 `probeInterval ≤ 5s`：若将来调大 probeInterval，需按「最坏情况下最后一个
//
//	探针拍离窗口末端的距离」重估本值。
const scoutEchoMargin = 1 * time.Second

// scoutHeuristicHits 启发式触发计数（排障用：判断灰度期是否真的在发生；见 B1 交付说明）。
var scoutHeuristicHits atomic.Int64

// scoutEchoBoundMs 「对端最后一次回显」的右界（单位 **ms**，与 `lastEcho`/`trialStartedAt` 一致）。
//
// ⚠️⚠️ 单位纪律：`clampPunchWindow` 返回 **int（毫秒）**，`scoutEchoMargin` 是 `time.Duration`
// ⇒ 必须 `.Milliseconds()`。漏转会得到 +5×10⁹ ms（≈58 天）⇒ 启发式**恒真**，
// 而且**不会编译失败** ⇒ 由 `TestScoutEchoBoundUnits` 用**数值断言**钉住。
func (p *directPath) scoutEchoBoundMs() int64 {
	w := p.scoutWindowMs
	if w <= 0 {
		w = punchWindowDefault // 旧对端不传 windowMs（omitempty）⇒ 用默认探路窗口
	}
	return int64(clampPunchWindow(w)) + scoutEchoMargin.Milliseconds()
}

// scoutBound 「探路收尾」判据的**年龄上界**（次要守卫：防「很久以前的 0 字节僵尸登记」）。
//
// 推导（三部分，全部来自既有常量，不写死数字）：
//
//	对端探路窗口 Δ_max            = clampPunchWindow(windowMs)          （≤ 其打洞窗口）
//	+ 判活宽限 grace              = probeInterval*(probeMissLimit+1)    （path.go 的 L2 判据）
//	+ 判死拍数上界                = probeMissLimit*checkInterval         （L2 需要连续若干拍）
func (p *directPath) scoutBound() time.Duration {
	w := p.scoutWindowMs
	if w <= 0 {
		w = punchWindowDefault
	}
	grace := p.mgr.probeInterval*time.Duration(p.mgr.probeMissLimit+1) +
		time.Duration(p.mgr.probeMissLimit)*p.mgr.checkInterval
	return time.Duration(clampPunchWindow(w))*time.Millisecond + grace
}

// scoutTearDownHeuristic ⭐⭐ 灰度期启发式（2026-09-27，B1；**全网升级后整体删除**）：
//
//	「本机作为**响应方** + 这条路径**从未承载业务流量** + **对端在它自己的探路窗口内就不再回应**」
//	⇒ 极可能是**未升级对端的预打洞探路收尾**，而不是本机链路质量问题 ⇒ 按 `peer-closed` 类处理。
//
// 为什么需要它（残余场景，真机复盘）：
//
//	对端探路成功后 `releaseAll()` 会 `conn.CloseWithError(0,"")`，但**紧接着就关掉
//	transport/socket**⇒ 该 CONNECTION_CLOSE **单包、无重传**。若它丢了：本机既看不到连接关闭，
//	探针也再无回显 ⇒ 试用期 15s 先到 ⇒ `tryFailTrial` 判 `quality-poor` ⇒ **白排 5min**
//	（判活判死要 16-17s，永远轮不到）。这正是灰度期（部分用户未升级）会遇到的那条。
//
// ⚠️ **判据里不含 peer-close 事实**：有事实时 `isPeerInitiatedClose` 已经覆盖，
//
//	再加一遍就是**空操作**（review 2026-09-27 抓到过这条）。
//
// ⚠️ 为什么用「0 字节业务流量」而不是「寿命 < 10s」：
//
//	预打洞的产物是**信息**，不是「一条要用的连接」⇒ **发起方**在成功分支**不 handover**
//	⇒ 双方都不会在这条 conn 上发业务数据，响应方侧 `bytesUp/Down` 恒为 0；
//	而流量驱动打洞是「因为有流量才打」⇒ 立刻会有字节。
//
//	⚠️ A3a（2026-09-28）：**本侧**已删除「预打洞成功不 handover」分支
//	（原 `punch.go` 的 `s.trigger == P2PTriggerPrePunch`）⇒ 该分支现在**只存在于未升级对端侧**，
//	而本启发式的**目标场景正是未升级对端**（灰度期）⇒ **适用前提不变**，只是出处由「本侧分支」
//	改为「对端侧分支」。**不要**据此把它当成"已不适用"而弱化这个判据。
//
// ⚠️ 代价记账：若这真是**本机网络坏**，会被记成 peer-closed（30s 而非 5min）⇒ 对不可达对端的
//
//	重试更频繁（受服务端 60s/1 次限流 + 30s 冷却双重约束）。灰度期可接受；
//	触发次数由 `scoutHeuristicHits` 观测。
func (p *directPath) scoutTearDownHeuristic() bool {
	if p.role != pathRoleResponder {
		return false
	}
	if p.bytesUp.Load() != 0 || p.bytesDown.Load() != 0 {
		return false // 承载过业务流量 ⇒ 是「要用的连接」，不是探路
	}
	if time.Since(p.since) > p.scoutBound() {
		return false // 次要守卫：很久以前的 0 字节登记不算
	}
	started := p.trialStartedAt.Load()
	if started == 0 {
		return false
	}
	last := p.lastEcho.Load()
	if last == 0 {
		return true // 从未回显（已被上面的「响应方 + 0 字节 + 年轻」约束）
	}
	// 主要判据：对端最后一次回应发生在**它自己的探路窗口**之内
	return last <= started+p.scoutEchoBoundMs()
}

// markScoutHeuristicHit 记录一次启发式触发（计数器 + 显式日志；不静默）。
func (p *directPath) markScoutHeuristicHit(where string) {
	n := scoutHeuristicHits.Add(1)
	log.Printf("ℹ️ [HARP] %s 判为**对端探路收尾**（灰度期启发式@%s，累计第 %d 次）："+
		"按 peer-closed 短冷却处理（本机未承载业务流量、对端在探路窗口内即停止回应）", p.peerVIP, where, n)
}

// evalTrial 试用期判定（看门狗 checkTicker 每拍调用一次）。
//
// 两道**取消门**（设计 §9；顺序固定）：
//  1. `state != pathStateTrial` ⇒ 直接返回（demote/close/standby 已经把路径带走）；
//  2. `trialDone.CAS(false,true)` ⇒ 只有赢家能结算（装表/降级各只发生一次）。
//
// ⚠️ CAS 必须放在真正结算的那一刻，不能在函数入口就取走 —— 否则「窗口未到」的正常情形
//
//	会把取消门用掉，试用期永远无法结算（那正是「trial 卡死」的形态）。
//
// ⭐ double-read（与 stableEnoughToClearFailures 同款）：`trialStartedAt` 与 `state` 是两个
// 独立原子量，两步写入之间读者可能看到「新 state=trial + 旧 startedAt」。窗口极小的竞态，
// 但结算动作是**装表/关路径**这种重动作，所以读完后重读一次，要求两次一致才判定。
func (p *directPath) evalTrial(now time.Time) {
	if p.state.Load() != pathStateTrial {
		return // 取消门 ①：已经不是试用期了，什么都不做
	}
	started := p.trialStartedAt.Load()
	if started == 0 {
		return // 起点还没落（极端：newDirectPath 与 run() 之间）—— 下一拍再来
	}
	if p.trialStartedAt.Load() != started {
		return // 期间发生过状态转移（重新进入 trial）⇒ 本拍不判定
	}
	p.trialSampleStep(now)
	if p.trialGoodEnough() {
		p.tryPassTrial()
		return
	}
	if now.Sub(time.UnixMilli(started)) >= p.trialWindow() {
		p.tryFailTrial() // 窗口到点：好样本不够 ⇒ 判负（含「样本不足」这一支，原因码见下）
	}
}

// trialSampleStep 按 probeInterval 采一个样本。
//
// 样本定义（实现口径，交付说明里单列）：**每个 probeInterval 记一个样本**，
// 「这一窗内有没有收到回显」决定成败 ⇒ 成功率 = 好样本数 / 已收样本数。
// 之所以不按「每次探针一发一回」精确配对：控制流是字节流，多发的探测与回显无法一一对应，
// 而判定只需要「丢包率 ≤10%」这个量级（3 个样本里最多允许 1 个丢）。
func (p *directPath) trialSampleStep(now time.Time) {
	started := p.trialStartedAt.Load()
	if started == 0 {
		return
	}
	win := p.trialWindow()
	step := p.mgr.probeInterval
	if step <= 0 {
		step = defaultProbeInterval
	}
	if step > win {
		step = win // 窗口比探针间隔还短（测试注入）⇒ 至少也要判一次
	}
	last := p.trialLastSampleAt.Load()
	if last == 0 {
		last = started
		p.trialLastSampleAt.Store(started)
		// ⚠️⚠️ **这里绝不能再写 `trialLastEcho`**（2026-09-27 真机记账 1 的修复点）。
		//
		//	基线已由 `newDirectPath` 在**进入试用期那一刻**写好。若在这里再写一次
		//	（= 第一个采样点的当前值），就会把 t∈[进入试用期, 第一个采样点] 之间**已经到达的
		//	回显**整段扔掉 ⇒ 第一个 probeInterval 窗白丢 ⇒ 15s 名义「3 个样本」实际只剩
		//	**2 个采样点**，而「3 取 2」需要 2 个好样本 ⇒ **容错为 0**：
		//	真机上任何一次探针抖动（回显晚于采样点）都会让试用期失败。
		//	⇒ 保留进入试用期时的基线，第一个采样点就能正确把「窗内有没有回显」算进去。
	}
	if now.Sub(time.UnixMilli(last)) < step {
		return // 还没到下一个采样点
	}
	// ⭐ 2026-09-27 修复（记账 2）：**只在本样本窗内「已经有回显」时才落样本**。
	//
	//	原来的判据是「距上次采样 ≥ step 就落一个样本，窗内没回显就记坏」。
	//	问题：`probeT` 与 `checkT` 同刻创建 ⇒ `checkInterval` 整除 `probeInterval` 时，
	//	采样点会频繁落在「刚发出探针、回显还没回来」的那一毫秒 ⇒ 白吃一个采样点
	//	（真机日志：`📤 发出探针 seq=1` 与 `🧪 采样 0/1：回显增量=false` 同一毫秒）。
	//
	//	改成：没回显就**不落样本**，把采样点顺延到下一拍（回显通常几十 ms 后即到）。
	//	代价：样本数 = 「有回显的窗数」（无回显的窗不再计入分母）⇒ 判据更接近
	//	「在真的测到东西的那些窗里，质量够不够好」，也不再因为「探针刚发出」白吃样本。
	//	⚠️ 真正的「一直没回显」由 L2（`probeMissLimit` × `probeInterval`）负责判死，
	//	   不依赖试用期样本 —— 所以这里不落样本不会让坏路径漏网。
	//
	//	⚠️ 为什么不用「距上次发探针 ≥ step/2 才采」那种时间相位判据：实测它会
	//	   把采样点**全部**推掉（生产比例 check=probe/4 下，每拍都落在这个窗口内）
	//	   ⇒ 试用期一个样本都拿不到。判据必须基于**事实（有没有回显）**，不是时间相位。
	//
	// ⭐ 2026-09-28（B2 修复；真机：15s 窗口只采到 1 个样本 ⇒ 判负 ⇒ 半双工）：
	//	**跳过时不得推进 `trialLastSampleAt`。**
	//
	//	原实现在"无新回显"分支里写 `trialLastSampleAt.Store(now)`，注释写"顺延到下一拍"——
	//	**但它实际顺延了一整个 `probeInterval`**：上面的闸门是 `now - trialLastSampleAt >= step`
	//	（`step = probeInterval` = 5s）⇒ **跳过点之后会出现 5s 盲区**，期间每拍都被闸门挡回，
	//	落在盲区里的回显**永远不被采**。
	//
	//	真机形态：首个采样点（T+5s）恰撞「探针刚发出、回显未到」⇒ 跳过并把闸门推到 T+5s
	//	⇒ T+5.5s 到达的回显要等到 T+10s 才被采（迟 4.5s），更晚到达的回显则**整个丢失**
	//	⇒ 15s 窗口内只剩 1 个样本 < `need`(2) ⇒ 判负（对端装表、本侧不装表 ⇒ 下行 0 字节）。
	//
	//	改法：**只在"落样本"时推进闸门**。跳过时闸门不动 ⇒ 下一拍（`checkInterval`=1s）立刻重试，
	//	T+6s 就能把 T+5.5s 的回显采掉 ⇒ 窗口内 T+6s / T+11s 两个样本 = `need` ⇒ 通过。
	//	⇒ 语义：**每个采样机会都必须被真正用掉**（要么落样本、要么下一拍立即重试），
	//	  不允许因为"这一拍恰好没回显"就丢掉一整个 `probeInterval` 的机会。
	//	⚠️ 不会重复计数：`trialLastEcho` 在**落样本**处推进（见下方 `Store(echo)`）⇒
	//	  重试看到的一定是"更新的回显"；而回显节奏由探针间隔保证（1 探针 = 1 回显）。
	//	守卫：`TestTrialSampleGateRetriesOnNextTick`（下一拍必须能落样本）
	//	      + `TestTrialSampleGateDoesNotPhaseLock`（回显到达后最迟一次机会内必须落样本）。
	if p.lastEcho.Load() <= p.trialLastEcho.Load() {
		// ⚠️ **B2 修复点：这里不要写 `trialLastSampleAt.Store(now)`**
		//	（那会推走一个 `probeInterval` 并制造 5s 盲区 = 真机 bug 的根因）。
		return
	}
	p.trialLastSampleAt.Store(now.UnixMilli())

	echo := p.lastEcho.Load()
	relay := time.Duration(p.trialRelayRtt.Load())
	direct := p.rttValue()
	// ⚠️ 先取上一个样本的基线，再更新 —— 日志要报「本样本窗内有没有新回显」，
	//    若在 Store 之后再比，比较的是自己 ⇒ 恒 false（写这行日志时踩过）。
	prevEcho := p.trialLastEcho.Load()
	success := 0.0
	if echo > prevEcho {
		success = 1.0
		if direct > 0 {
			p.trialLastDirectRtt.Store(int64(direct))
		}
	}
	p.trialLastEcho.Store(echo)
	p.trialSamples.Add(1)
	if trialSampleGood(direct, relay, success) {
		p.trialGood.Add(1)
	}
	// ⚠️ 可观测性（2026-09-27 真机 bug 后补）：**每个样本落定时**打一行，
	//	直接暴露「样本数不涨 / 好样本为 0」这件事（真机上正是这个形态）。
	//	打开方式见 `probeTraceEnabled`。
	if probeTraceEnabled() {
		log.Printf("🧪 [HARP] 试用期采样（%s）：好样本 %d/%d（本样本 回显增量=%v 直连=%v 中继=%v 成功率=%.0f%%）",
			p.peerVIP, p.trialGood.Load(), p.trialSamples.Load(),
			echo > prevEcho, direct, relay, success*100)
	}
}

// trialMetrics 试用期日志用的度量文案（百分数按 0~100 取整）
func (p *directPath) trialMetrics() (directMs, relayMs int64, pct int) {
	direct := time.Duration(p.trialLastDirectRtt.Load())
	if direct <= 0 {
		direct = p.rttValue() // 还没测到 ⇒ 用种子/实时值（rttText 会显示「待测」）
	}
	samples := int(p.trialSamples.Load())
	good := int(p.trialGood.Load())
	if samples <= 0 {
		return msAtLeast1(int64(direct)), msAtLeast1(p.trialRelayRtt.Load()), 0
	}
	return msAtLeast1(int64(direct)), msAtLeast1(p.trialRelayRtt.Load()), good * 100 / samples
}

// logTrialEnter 试用期开始的日志（⭐ 设计 §9 Q4 逐字格式）
func (p *directPath) logTrialEnter() {
	log.Printf("🧪 [HARP] 进入试用期：%s（数据仍走中继，%v 内按 %d 个样本判定）",
		p.peerVIP, p.trialWindow(), p.trialNeedGood())
}

// logTrialPass 试用期通过的日志（⭐ 设计 §9 Q4 逐字格式）
func (p *directPath) logTrialPass() {
	direct, relay, pct := p.trialMetrics()
	log.Printf("✅ [HARP] 试用期通过，已切换到直连：%s（直连 RTT=%s / 中继=%s，成功率=%d%%）",
		p.peerVIP, rttText(int64(direct)*int64(time.Millisecond)),
		rttText(int64(relay)*int64(time.Millisecond)), pct)
}

// logTrialFail 试用期未通过的日志（⭐ 设计 §9 Q4 逐字格式 + 2026-09-27「样本不足」分支）
//
// ⚠️ 「样本不足」必须**显式说出来**：2026-09-27 的采样修复让「本窗内无回显」的采样点
// 不再落样本 ⇒ 15s 窗口内可能只有 1 个样本（甚至 0 个）。此时「好样本 0/1」这类输出
// 容易被误读成「质量差」，而实际原因是「根本没测到几次」——两者的排查方向完全不同。
func (p *directPath) logTrialFail(reason string, delay time.Duration) {
	direct, relay, pct := p.trialMetrics()
	samples, good, need := int(p.trialSamples.Load()), int(p.trialGood.Load()), p.trialNeedGood()
	if samples < need {
		log.Printf("⚠️ [HARP] 试用期未通过（%s，%v 后重试）：%s（**样本不足** 好样本 %d/%d，"+
			"窗口内只采到 %d 个样本、判定需要 %d 个；直连 RTT=%s / 中继=%s）",
			reason, delay.Round(time.Second), p.peerVIP, good, samples, samples, need,
			rttText(int64(direct)*int64(time.Millisecond)),
			rttText(int64(relay)*int64(time.Millisecond)))
		return
	}
	log.Printf("⚠️ [HARP] 试用期未通过（%s，%v 后重试）：%s（好样本 %d/%d；直连 RTT=%s / 中继=%s / 成功率=%d%%）",
		reason, delay.Round(time.Second), p.peerVIP,
		good, samples,
		rttText(int64(direct)*int64(time.Millisecond)),
		rttText(int64(relay)*int64(time.Millisecond)), pct)
}

// tryPassTrial 试用期通过 ⇒ 装表点仲裁 → 装表 → 转 Up（取消门 ② 的赢家才能走到这里）
func (p *directPath) tryPassTrial() {
	if p.state.Load() != pathStateTrial {
		return // 取消门 ①（同 evalTrial）：已经被顶替/降级/关闭 ⇒ 绝不再装表
	}
	if !p.trialDone.CompareAndSwap(false, true) {
		return // 取消门 ②：已经有人结算/取消了 ⇒ 绝不二次装表
	}
	p.logTrialPass()
	if h := p.mgr.hooks; h != nil && h.TrialPassed != nil {
		h.TrialPassed(p.peerVIP)
	}
	p.mgr.installAfterTrial(p)
}

// tryFailTrial 试用期未通过 ⇒ **A2 判负**（`rejectTrialSettled`：保留连接 + 30s 短冷却；
// 若命中 B1 灰度期启发式则真死）—— 与「通过」共享同一道取消门 `trialDone`。
//
// 两条判负路径（**结果相同、日志不同**，便于排查）：
//
//	① **样本足够但不够好** ⇒ 真·质量不达标；
//	② **样本不足**（`trialSamples < trialNeedGood`）⇒ **保守判负**（review 拍板 A）：
//	   窗口内没测到足够样本就没法证明这条直连可用，「证明不了」不能当「通过」。
//	   2026-09-27 的采样修复（无回显不落样本）之后，这一支**变得可能**：
//	   15s 窗口里也许只有 1 个样本（0好0坏 / 1好0坏 / 1坏0好）⇒ 都不到「3 取 2」的门槛。
//
// ⚠️ 原因码仍用 `P2PReasonQualityPoor`：不新增信令/协议面取值（用户能看到的原因文案
//
//	由「样本不足」这句日志承担）。若将来前端希望区分两者，再单独评审加 reason code。
func (p *directPath) tryFailTrial() {
	if p.state.Load() != pathStateTrial {
		return
	}
	if !p.trialDone.CompareAndSwap(false, true) {
		return
	}
	// ⭐ A2（方案 A）：判负后的出路只有两种，**都排 30s 短冷却**
	//	（peer-closed ⇒ `failPeerClosed` 支 30s；本侧判负保留连接 ⇒ `setRejectedCooldown` 30s）
	//	⇒ 日志里的延迟直接用 `backoffBusy`（原来的质量差 5min 档已不再适用）。
	delay := backoffBusy
	p.logTrialFail(P2PReasonQualityPoor, delay)
	if h := p.mgr.hooks; h != nil && h.TrialFailed != nil {
		h.TrialFailed(p.peerVIP, P2PReasonQualityPoor)
	}
	// demote 是**唯一**的关闭/退避入口（顺序：摘路由 → 关路径 → 排退避），
	// 它自己也会置 trialDone（幂等），所以这里不重复做任何清理。
	//
	// ⭐ 2026-09-27（B1）：**灰度期启发式** —— 若这条路径是「响应方 + 0 字节 + 对端在
	// 自己的探路窗口内就不再回应」，则判负很可能只是**对端探路收尾**（其 CONNECTION_CLOSE
	// 单包无重传、丢了就看不到），把它记成 peer-closed（30s 短冷却）而不是 quality-poor（5min）。
	if p.scoutTearDownHeuristic() {
		p.markScoutHeuristicHit("trial-verdict")
		// 对端**已经走了**（探路收尾）⇒ 真死，不保留
		p.demote(P2PReasonPeerClosed)
		return
	}
	// ⭐⭐ A2（方案 A）的核心：判负**不再关连接** —— 保留它（对端可能仍在用），
	//	只标记「本侧不用」，并排一个 30s 短冷却防止流量立刻重触发。
	//
	// ⚠️ 「为什么判负」由**上面**的启发式负责（判定阶段）；`rejectTrial` 只管「判负后如何保留连接」
	//	⇒ 两个语义分开，避免把 peer-closed 修正塞进保留逻辑里（review 追问 1 拍板 A）。
	// ⚠️ 必须调 **`rejectTrialSettled`**（**不是** `rejectTrial`）：本函数**已经**在上面
	//	`trialDone.CAS(false,true)` 赢走了判定门 ⇒ 再调自带门的 `rejectTrial` 会因 CAS 失败
	//	**直接 return = 判负空操作**（2026-09-28 实测揪出，见 `rejectTrial` 头的修复留档）。
	p.rejectTrialSettled()
}

// noteTrialRelayRtt 在用信令刷新中继 RTT 时，**在试用期内**留一份快照给判定与日志用。
//
// 为什么不在 trial 开始时取一次：试用期常常在服务端还没算出 relayRtt 时就开始了
// （对端刚连上）——那时快照是 0，判据 `relay <= 0 ⇒ 不好` 会让试用期必然失败。
// 持续跟随既有基准（它本身有 5 分钟刷新节流）才是正确口径。
func (p *directPath) noteTrialRelayRtt(v int64) {
	if p.state.Load() == pathStateTrial {
		p.trialRelayRtt.Store(v)
	}
}

// installAfterTrial 装表点的**仲裁临界区**（设计 §9 Q1）。
//
// 为什么必须原子：trial 期间的路径**不在路由表里**（既不参与分流、也不参与仲裁），
// 所以真正的竞争点是**装表点** —— 两条 trial 可能先后通过，必须
// 「读 existing → 仲裁 → 装表」在同一临界区完成，否则就是 1b-2B 那个真机 bug 的同款形态
// （双双装表 ⇒ 各自关掉对方保留的那条）。
//
// ⭐ 取消门 ① 的**第二道检查必须在临界区内**（review 追问 1 复核时发现，真缺陷）：
// `tryPassTrial`/`passTrialForTest` 入口那次 `state != trial` 检查与这里的装表之间，
// 并发到达的 `demote` 可以把路径判死（它先 `trialDone.Store` + `setState(Down)`，再取 routeMu）——
// 于是「已判死」的路径又被装进路由表并 `setState(Up)`：状态说直连、实际连接已关
// （正是最坏的「面板显示直连但不通」）。把 state 检查挪进 routeMu 之后，它与
// demote 的 `removeRoute`（同锁）互斥 ⇒ 两者只能有一个赢：
//   - demote 先拿到锁 ⇒ 这里读到 Down ⇒ 直接放弃装表（本函数返回 false）；
//   - 这里先拿到锁 ⇒ 装表 + 转 Up；随后 demote 拿锁时按「表里还是它」把它摘掉（守卫放行）。
//
// 两种交错都收敛到「Down 且不在表里」，不会留下「Up 但连接已关」。
//
// 两种情形：
//  1. `existing == nil`（无在用直连）⇒ 直接装表 + 转 Up；
//  2. `existing` 是 Up/Standby（已有在用直连）⇒ 走既有 `arbitrationKeeps`：
//     既有胜 ⇒ 自己**直接关路径、不排退避**（仲裁失败 ≠ 质量失败，不该吃 5min 冷却）；
//     自己胜 ⇒ 装自己 + 转 Up，解锁后在**锁外** close/wait 既有
//     （持锁等待会死锁：旧路径的数据面协程可能正卡在 demote → removeRoute 等 routeMu）。
//
// 返回 true 表示「本次调用真的把 p 装进了路由表」。
func (m *pathManager) installAfterTrial(p *directPath) bool {
	// 先摘掉自己的「试用中」登记（无论输赢都不再是试用态）——自己取锁，必须在 routeMu 之前
	p.untrack()

	m.routeMu.Lock()
	// ⭐ 取消门 ①（临界区内版）：已被 demote/close 判死的路径绝不装表
	if p.state.Load() != pathStateTrial {
		m.routeMu.Unlock()
		log.Printf("ℹ️ [HARP] 试用期结算时路径已不在试用中（%s，状态=%s），放弃装表",
			p.peerVIP, pathStateName(p.state.Load()))
		return false
	}
	old := m.routes.Load()
	existing := (*old)[p.peer]
	if existing != nil && existing != p &&
		arbitrationKeeps(existing.peer, existing.myVIP, existing.role) {
		existingWins := true
		newWins := arbitrationKeeps(p.peer, p.myVIP, p.role)
		m.routeMu.Unlock()
		log.Printf("ℹ️ [HARP] 试用期已通过但同一对端已有直连（保留 %s），丢弃本次（role=%s；existingWins=%v newWins=%v）",
			existing.role, p.role, existingWins, newWins)
		p.close()
		p.waitTimeoutLogged("仲裁(已存在胜)")
		return false
	}
	m.installRouteLocked(p.peer, p)
	p.setState(pathStateUp)
	m.routeMu.Unlock()

	if existing != nil && existing != p {
		log.Printf("ℹ️ [HARP] 同一对端两条直连，保留「小 VIP 发起」的那条（丢弃 role=%s）", existing.role)
	}
	log.Printf("🧭 [HARP] 试用期通过 → 路径已加入路由表：%s → 后续发往该 VIP 的流量走直连"+
		"（写协程逐包查表分流；面板「当前直连对端」的字节数应立即开始增长）", p.peerVIP)
	m.onPunchSucceeded(p.peerVIP)
	m.emit(p.status(P2PStateDirect, P2PReasonOKDirect))

	if existing != nil && existing != p {
		// ⚠️ 锁外关闭/等待旧路径（理由见函数注释）
		existing.close()
		existing.waitTimeoutLogged("仲裁(替换旧路径)")
	}
	return true
}

// passTrialForTest 立刻把一条 pathStateTrial 的路径按「通过」结算掉（**仅测试助手调用**）。
//
// 用途：绝大多数既有用例只关心「有一条 Up 的路径」，不该被迫等 15 秒试用期。
// 它走的是与生产**完全相同**的两道取消门 + 同一个仲裁临界区，只是把判定换成「直接通过」。
func (p *directPath) passTrialForTest() {
	if p.state.Load() != pathStateTrial {
		return // 与 tryPassTrial 同一道门：已关闭/被顶替的路径不得装表
	}
	if !p.trialDone.CompareAndSwap(false, true) {
		return
	}
	p.mgr.installAfterTrial(p)
}

// run 启动数据面 goroutine（幂等）。
//
// ⚠️⚠️ **锁内契约（生产）**：本函数**必须**在 `routeMu` 临界区内调用 —— 否则会出现
// 「已登记但 `wg.Add` 未发生」的窗口，`close()` 会拿到这条路径并 `wait()`，与 `wg.Add`
// 并发 = **WaitGroup 误用**。**已知生产调用点：仅 `handleEstablished`**（见该处注释，与之互引）。
//
// ⚠️ **不得在本函数内同步获取 `routeMu`/`m.mu`**：本函数正被锁内调用 ⇒ 会立即**自死锁**。
// 要读路由表请放进 `setup()`（它在独立协程里跑，且不等 `ready`）。
//
// ⚠️ **已知调用点（1 处生产 + 11 处测试）**：
//
//	· **1 处锁内**：`trial_integration_test.go:145` —— 安全理由：**锁挡住并发 `close()`**；
//	· **10 处锁外**：全部属于「**未在 `run()` 之前 `addTrialPath`**」——安全理由：**路径不在
//	  `trialPaths` ⇒ `close()` 拿不到它**。⚠️ **这不是"锁外也行"，新夹具不要复制这个形态**；
//	· a2/b3 的 `addTrialPath`（不在上面的 `run()` 清单里，`run()` 经 `newTestPathOwned`
//	  先发生）：属于「**先 `run()` 后 `addTrialPath`**」的安全形态（`wg.Add` 已完成）。
//
// ⚠️ **测试夹具的豁免是历史既成事实，不是设计意图**：当前 10 处锁外夹具不挂，依赖
// 「用例体内不触发 `close()`」这个隐含约束（`t.Cleanup` 是 LIFO、在用例体返回后才跑）。
// **新夹具一律抄 `newTestPathNoPass`**（锁内 `addTrialPath` + `run()`）。
//
// ⚠️ **`-race` 与 Go 内建的 WaitGroup 运行期检查都只在"交错真的发生"时触发** ⇒ 不能证明
// "不存在误用"；`go vet` **无**此检查。验证锁内契约只能靠**逐条静态通读调用点**。
//
// ⚠️ **不能同步建流**：本函数由 punchManager 在「探针成功」的回调里调用，
// 而探针协程此刻可能正在回显探测包（发起方）。同步建流（最多 5s）会把回显卡住，
// 对端就会因为收不到回显而误判路径失效。所以：先起 goroutine，建好流再放行数据面。
func (p *directPath) run() {
	p.runOnce.Do(func() {
		// 一次性加满：setup + 7 个数据面协程
		// （bulk 写/读、crit 写/读、控制流、datagram、看门狗）
		// 之后不再 Add，避免与 close() 的 Wait 竞争。
		p.wg.Add(8)
		go func() { defer p.wg.Done(); p.setup() }()
		for _, fn := range []func(){
			p.bulkWriteLoop, p.critWriteLoop,
			p.bulkReadLoop, p.critReadLoop,
			p.datagramLoop, p.ctrlLoop, p.watchLoop,
		} {
			f := fn
			go func() {
				defer p.wg.Done()
				<-p.ready // setup 完成（或路径已关）后才开始
				// setup 失败 / 路径已关闭时直接退出：此时两条流可能还没建好，
				// 直接跑数据面会拿到 nil 流（踩过：close() 会主动放行这些 goroutine）。
				//
				// ⭐ 1b-4：判据必须是 **alive()** 而不是 `state == pathStateUp` ——
				// 「先验后切」下新建路径在 **trial**，用 Up 判定会让**看门狗直接退出**，
				// 于是试用期永远没人判定（路径卡死在 trial / 或者永远装不上表）。
				// 这正是本切片最危险的一处「只改一半」形态，集成用例已覆盖。
				if !p.alive() {
					return
				}
				f()
			}()
		}
	})
}

// ---------- 流分组（Q1：关键小包与批量流量分开） ----------

// streamKind 一条直连流的用途（**线格式的一部分**：作为每条流的首帧声明）
type streamKind string

const (
	streamBulk streamKind = "bulk" // 批量：bulk TCP + 可靠 UDP
	streamCrit streamKind = "crit" // 关键小包：ICMP + match + 游戏 TCP（独立流 → 不被 bulk 的流控窗口拖住）
	streamCtrl streamKind = "ctrl" // 控制/探针
)

// streamDecl 每条流的**第一帧**：声明这条流的用途。
//
// ⚠️ 为什么必须显式声明：`AcceptStream` **没有**「第几条」的语义（QUIC 流之间无序），
// 只能靠流内容自描述。顺序猜是不可靠的（1b-1 的测试夹具就踩过同类问题）。
type streamDecl struct {
	Type string     `json:"t"` // 固定 "stream"
	Kind streamKind `json:"k"`
}

// planeStream 平面 → 流分组（Q1 的答案：关键小包与批量流量分属两条流）
func planeStream(plane pathPlaneIndex) streamKind {
	switch plane {
	case planeTCP, planeUDP:
		return streamBulk
	case planeICMP, planeMatch, planeGameTCP:
		return streamCrit
	}
	return streamBulk
}

// streamTx 取该流对应的发送队列
func (p *directPath) streamTx(kind streamKind) chan pathPkt {
	if kind == streamCrit {
		return p.txCrit
	}
	return p.txBulk
}

// ---------- 写侧（§2.2.1） ----------

// setStreams / streams 在锁下访问三条流（setup 在另一个 goroutine 里赋值）
func (p *directPath) setStreams(bulk, crit, ctrl directStream) {
	p.mu.Lock()
	p.bulkStream, p.critStream, p.ctrlStream = bulk, crit, ctrl
	p.mu.Unlock()
}

func (p *directPath) streams() (bulk, crit, ctrl directStream) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.bulkStream, p.critStream, p.ctrlStream
}

// streamFor 取某条流的句柄
func (p *directPath) streamFor(kind streamKind) (directStream, error) {
	bulk, crit, ctrl := p.streams()
	switch kind {
	case streamBulk:
		if bulk == nil {
			return nil, fmt.Errorf("bulk 流未建立")
		}
		return bulk, nil
	case streamCrit:
		if crit == nil {
			return nil, fmt.Errorf("crit 流未建立")
		}
		return crit, nil
	default:
		if ctrl == nil {
			return nil, fmt.Errorf("控制流未建立")
		}
		return ctrl, nil
	}
}

// setup 建立三条流（**发起方开、响应方收**）并握手；失败则降级（L1）
//
// ⭐ 角色约定修正了一个真错：只有发起方 `OpenStreamSync`，响应方 `AcceptStream`，
// 之后双方在**同一组双向流**上收发。早期实现让双方各自开流、各自读自己那条，
// 结果是「A 写进自己开的流、B 从没读过它」——真实两端之间数据面根本不通
// （单元测试用的是同一条假流，所以没暴露）。
func (p *directPath) setup() {
	ctx, cancel := context.WithTimeout(p.mgr.ctx, p.setupTimeoutValue())
	defer cancel()

	var bulk, crit, ctrl directStream
	var err error
	if p.role == pathRoleInitiator {
		bulk, crit, ctrl, err = p.openStreams(ctx)
	} else {
		bulk, crit, ctrl, err = p.acceptStreams(ctx)
	}
	if err != nil {
		log.Printf("⚠️ [HARP] 建立数据面流失败（%s role=%s）：%v", p.peerVIP, p.role, err)
		p.readyOnce.Do(func() { close(p.ready) })
		p.demote(P2PReasonDirectHandshakeFailed)
		return
	}
	p.setStreams(bulk, crit, ctrl)

	if err := p.writeCtrl(pathCtrlMsg{
		Type: ctrlHello, Role: p.role, VIP: ip4ToString(p.myVIP), Datagram: true,
	}); err != nil {
		log.Printf("⚠️ [HARP] 控制流握手失败：%v", err)
		p.readyOnce.Do(func() { close(p.ready) })
		p.demote(P2PReasonDirectHandshakeFailed)
		return
	}
	p.readyOnce.Do(func() { close(p.ready) })
}

// openStreams 发起方：按 streamKinds() 开流并各自声明用途（响应方 accept 后按声明归类）
func (p *directPath) openStreams(ctx context.Context) (bulk, crit, ctrl directStream, err error) {
	for _, kind := range streamKinds() {
		s, oerr := p.conn.OpenStreamSync(ctx)
		if oerr != nil {
			return nil, nil, nil, fmt.Errorf("打开 %s 流失败: %w", kind, oerr)
		}
		if werr := writeJSONFrame(s, streamDecl{Type: "stream", Kind: kind}); werr != nil {
			_ = s.Close()
			return nil, nil, nil, fmt.Errorf("声明 %s 流失败: %w", kind, werr)
		}
		switch kind {
		case streamBulk:
			bulk = s
		case streamCrit:
			crit = s
		default:
			ctrl = s
		}
	}
	return bulk, crit, ctrl, nil
}

// streamKinds 数据面必须存在的三条流（**唯一权威清单**：发起方按它开、响应方按它收，
// 数量与种类都从这里派生，避免两处写死而漂移）
func streamKinds() []streamKind {
	return []streamKind{streamBulk, streamCrit, streamCtrl}
}

// acceptStreams 响应方：收**恰好 len(streamKinds()) 条**流，按首帧声明归类。
//
// 契约（review 追问 1 的答复）：
//   - **数量固定 3 条**（bulk/crit/ctrl），没有「动态等」——数量就是 streamKinds() 的长度；
//   - 每条流都要求**恰好一次**声明：未知种类、重复声明 → 立即关流并判失败（fail-closed）；
//   - 两个超时都是**有限**的：`AcceptStream` 用 setup ctx（`p.setupTimeout`，默认 5s），
//     声明读取用流读截止（同一个超时）。发起方少开一条流 → 第 3 次 Accept 到点失败 → 降级；
//     发起方开了流但不写声明 → 声明读超时失败 → 降级。**不存在无限等**。
func (p *directPath) acceptStreams(ctx context.Context) (bulk, crit, ctrl directStream, err error) {
	buf := make([]byte, 512)
	want := len(streamKinds())
	deadline := time.Now().Add(p.setupTimeoutValue())
	for i := 0; i < want; i++ {
		s, aerr := p.conn.AcceptStream(ctx)
		if aerr != nil {
			return nil, nil, nil, fmt.Errorf("接受第 %d/%d 条流失败: %w", i+1, want, aerr)
		}
		// ⚠️ 声明读必须有截止时间：否则对端「开流但不写声明」会让 setup 永久卡住，
		//    路径既不 ready 也不降级 = 「direct 但流量不通」且没有回落（最坏的一种 limbo）。
		_ = s.SetReadDeadline(deadline)
		pkt, rerr := readFrame(s, buf)
		if rerr != nil {
			_ = s.Close()
			return nil, nil, nil, fmt.Errorf("读取第 %d/%d 条流的声明失败: %w", i+1, want, rerr)
		}
		var d streamDecl
		if json.Unmarshal(pkt, &d) != nil || d.Type != "stream" {
			_ = s.Close()
			return nil, nil, nil, fmt.Errorf("第 %d/%d 条流的声明非法", i+1, want)
		}
		switch d.Kind {
		case streamBulk:
			if bulk != nil {
				_ = s.Close()
				return nil, nil, nil, fmt.Errorf("bulk 流重复声明")
			}
			bulk = s
		case streamCrit:
			if crit != nil {
				_ = s.Close()
				return nil, nil, nil, fmt.Errorf("crit 流重复声明")
			}
			crit = s
		case streamCtrl:
			if ctrl != nil {
				_ = s.Close()
				return nil, nil, nil, fmt.Errorf("ctrl 流重复声明")
			}
			ctrl = s
		default:
			_ = s.Close()
			return nil, nil, nil, fmt.Errorf("未知的流声明 %q", d.Kind)
		}
	}
	// 清掉声明读的截止时间：之后这两条流是长期承载数据的，不能被它误伤
	for _, s := range []directStream{bulk, crit, ctrl} {
		if s != nil {
			_ = s.SetReadDeadline(time.Time{})
		}
	}
	if bulk == nil || crit == nil || ctrl == nil {
		return nil, nil, nil, fmt.Errorf("缺少必需的流（bulk=%v crit=%v ctrl=%v）",
			bulk != nil, crit != nil, ctrl != nil)
	}
	return bulk, crit, ctrl, nil
}

// setupTimeoutValue setup 的整体超时（默认 punchHandshakeTimeout；测试可注入更短的值）
func (p *directPath) setupTimeoutValue() time.Duration {
	if p.setupTimeout > 0 {
		return p.setupTimeout
	}
	return punchHandshakeTimeout
}

// writeJSONFrame 写一个 JSON 帧（用于流的用途声明）
func writeJSONFrame(s directStream, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_ = s.SetWriteDeadline(time.Now().Add(probeWriteTimeout))
	defer func() { _ = s.SetWriteDeadline(time.Time{}) }()
	return writeFrameToStream(s, data)
}

// ---------- 写侧（§2.2.1 + Q1：关键与批量分属两条流） ----------

// bulkWriteLoop 独占 bulk 流（bulk TCP + 可靠 UDP）。
//
// ⭐ 隔离有两层：
//  1. 与中继写协程隔离（R1b）：它卡住只会让 bulk 队列积压/丢弃；
//  2. **与关键小包隔离（Q1）**：crit 流有自己的写协程与流控窗口，
//     bulk 被大批量数据堵住时，ICMP/match/游戏 TCP 照常发出。
func (p *directPath) bulkWriteLoop() { p.writeLoopFor(streamBulk) }

// critWriteLoop 独占 crit 流（ICMP + match + 游戏 TCP）
func (p *directPath) critWriteLoop() { p.writeLoopFor(streamCrit) }

func (p *directPath) writeLoopFor(kind streamKind) {
	ch := p.streamTx(kind)
	for {
		select {
		case <-p.mgr.ctx.Done():
			return
		// ⭐ 第 3 步-B 根治：路径被判死 / 连接已关时**立即**退出。
		//
		// ⚠️ 为什么必须有这两条：本循环在**队列空转**时只靠
		//    `case <-time.After(200ms)` 轮询 `alive()` —— 那是「间接、最慢一拍」的退出方式，
		//    而它是 7 个数据面协程里**唯一**不监听「路径关闭」事件的（其余都听
		//    `conn.Context()` 或自己的流）。实测（隔离用例 `-count=20`）：某条路径被关闭后
		//    本协程不退出 ⇒ `p.wait()` 永久阻塞 ⇒ 装表点/淘汰/关停全部串行卡住。
		case <-p.demotedCh:
			return
		case <-p.conn.Context().Done():
			return
		case pkt := <-ch:
			p.enqueued.Add(1) // 数据面健康观测用（见 checkDataPlaneHealth）
			if err := p.writeData(kind, pkt.plane, pkt.data); err != nil {
				if errors.Is(err, errWriteTimeout) {
					log.Printf("⚠️ [HARP] %s 流写超时（%s），判定路径失效", kind, p.peerVIP)
				} else {
					log.Printf("⚠️ [HARP] %s 流写失败（%s）：%v", kind, p.peerVIP, err)
				}
				p.demoteErr(err) // L1-a / L1-b（对端主动结束的判定已收在 demoteWith）
				return
			}
		case <-time.After(200 * time.Millisecond):
			if !p.alive() { // ⭐ 1b-2B：standby 期间写协程要留着（恢复时立刻可用）
				return
			}
		}
	}
}

// writeData 写一帧数据到指定流（4 字节长度 + 1 字节平面标签 + 原始 IP 包），带写截止
func (p *directPath) writeData(kind streamKind, plane pathPlaneIndex, pkt []byte) error {
	s, err := p.streamFor(kind)
	if err != nil {
		return err
	}
	buf := make([]byte, 4+1+len(pkt))
	binary.BigEndian.PutUint32(buf[:4], uint32(1+len(pkt))) // ⚠️ 长度前缀必须写！漏了它帧长恒为 0，对端会当成空帧丢掉
	buf[4] = byte(plane)
	copy(buf[5:], pkt)
	if err := s.SetWriteDeadline(time.Now().Add(p.mgr.dataWriteDeadline)); err != nil {
		return err
	}
	if _, err := s.Write(buf); err != nil {
		if isNetTimeout(err) {
			return errWriteTimeout
		}
		return err
	}
	p.bytesUp.Add(uint64(len(pkt)))
	p.touch()
	return nil
}

// pathPkt 队列元素：**平面标签随包一起走**（不能靠事后推断：
// 同一个包里推不出「它属于哪个平面」的元信息）
type pathPkt struct {
	plane pathPlaneIndex
	data  []byte
}

// nextTx 与旧的单流 writeData 已随「每流一条队列」的重构移除（Q1 的隔离点）

// ---------- 读侧 ----------
var errWriteTimeout = errors.New("直连写超时")

// ---------- 读侧 ----------

// alive 路径是否**还活着**（Up 或 Standby）。
//
// ⭐ 1b-2B：standby 只是「不用它承载流量」，连接、两条流、探针、读写协程都必须继续跑：
//   - 探针继续跑 → 才能评估质量是否恢复（周期重评估的基础）
//   - 读协程继续跑 → 恢复时不需要重建任何东西
//   - 写协程保留（队列空转）→ 切回 direct 时立刻可用
//
// 判定「要不要承载流量」的地方（sinkFor）则**只认 Up**。
func (p *directPath) alive() bool {
	s := p.state.Load()
	// ⭐ 1b-4：试用期的路径也「活着」—— 探针/读写协程必须继续跑，否则试用期永远拿不到样本
	// ⭐ A2：`Rejected`（判负但**保留连接**）与 `Reusing`（复用重跑试用期）同样必须活着
	//	—— 否则 `ctrlLoop` 不再回显对端探针 ⇒ 对端 probe-timeout 后也判负 = 双侧都关。
	// ⚠️ `RejectedSettling`（收尾中间态）**不**纳入：此刻已决定不再使用这条连接。
	return s == pathStateUp || s == pathStateStandby || s == pathStateTrial ||
		s == pathStateRejected || s == pathStateReusing
}

// setState **一般状态转移**的唯一写入点。
//
// ⭐ 1b-4 第一步：在这里维护 `stableSince` —— 「成功稳定运行 ≥5 分钟才清失败记录」的判据。
// 置位规则：进入 Up 时记时刻；**任何离开 Up 的转移都清零** ⇒ 保证是「持续成功」而非「累计成功」。
//
// ⚠️ 契约（review 追问 2 后的修订）：
//   - **一般转移**必须走本函数（不要直接 `state.Store`）——否则 `stableSince` 会失效；
//   - **例外（只有一处）**：`enterStandby` / `exitStandby` 用 **CAS 直接写 state**
//     （`CompareAndSwap(Up,Standby)` / `CompareAndSwap(Standby,Up)`），因为它们是「判定与动作之间
//     夹了一次同步信令往返」的竞态点，必须把「检查 + 转移」合成一个原子动作（见两函数注释）。
//     CAS 比 setState **更严格**（带期望旧状态），且 CAS 成功后仍按同样的顺序补写 `stableSince`
//     （Up ⇒ now / 其它 ⇒ 0）⇒ 读侧契约不受影响（见 `stableSince` 字段上的读序契约）。
func (p *directPath) setState(s int32) {
	p.state.Store(s)
	if s == pathStateUp {
		p.stableSince.Store(time.Now().UnixMilli())
	} else {
		p.stableSince.Store(0)
	}
}

// dataReadLoop 读一条数据流（bulk 或 crit）：按平面标签投递到 TUN。
//
// ⭐ 两条流各有自己的读协程 → 一条流的乱序/缺口不会挡住另一条流的投递（Q1 的读侧隔离）。
func (p *directPath) bulkReadLoop() { p.dataReadLoop(streamBulk) }
func (p *directPath) critReadLoop() { p.dataReadLoop(streamCrit) }

func (p *directPath) dataReadLoop(kind streamKind) {
	s, err := p.streamFor(kind)
	if err != nil {
		return
	}
	p.readStreamLoop(kind, s)
}

func (p *directPath) readStreamLoop(kind streamKind, s directStream) {
	buf := make([]byte, maxFrameSize)
	for {
		pkt, err := readFrame(s, buf)
		if err != nil {
			if p.mgr.ctx.Err() != nil || !p.alive() {
				return
			}
			log.Printf("⚠️ [HARP] %s 流读失败（%s）：%v", kind, p.peerVIP, err)
			p.demoteErr(err) // L1-d（对端 FIN 时 err=io.EOF ⇒ 判 peer-closed，见 isPeerInitiatedClose ④）
			return
		}
		if len(pkt) < 2 {
			continue
		}
		plane := pathPlaneIndex(pkt[0])
		payload := pkt[1:]
		if plane < planeTCP || plane > planeICMP {
			continue // 未知平面：丢弃（fail-closed，不猜）
		}
		p.bytesDown.Add(uint64(len(payload)))
		p.touch()
		p.mgr.host.deliverToTun(payload)
	}
}

// datagramLoop 不可靠 UDP 平面（语义必须与中继一致：丢了就丢了，不重排）
func (p *directPath) datagramLoop() {
	// 退出条件必须同时覆盖「管理器关闭」与「这条连接关闭」：
	// 否则 conn 关了而 ReceiveDatagram 仍在阻塞，close() 的 wg.Wait() 会永久等待。
	ctx, cancel := context.WithCancel(p.mgr.ctx)
	defer cancel()
	stop := context.AfterFunc(p.conn.Context(), cancel)
	defer stop()

	for {
		pkt, err := p.conn.ReceiveDatagram(ctx)
		if err != nil {
			if p.mgr.ctx.Err() == nil && p.state.Load() == pathStateUp {
				// 对端可能没开 datagram：这不是致命错误，记一次就安静退出
				log.Printf("ℹ️ [HARP] datagram 接收结束（%s）：%v", p.peerVIP, err)
			}
			return
		}
		if len(pkt) == 0 {
			continue
		}
		p.bytesDown.Add(uint64(len(pkt)))
		p.touch()
		p.mgr.host.deliverToTun(pkt)
	}
}

// writeDatagram 发送一个不可靠 UDP 包（由中继写协程在直连命中时调用）
//
// ⚠️ 降级链路（review 追问 2）：datagram **没有**写截止、没有 ACK、没有重传，
// 所以「网络黑洞」不会从 `SendDatagram` 返回错误 —— 它只会在**本地原因**下报错
// （包过大 / 对端未协商 datagram / 本地队列满）。因此 datagram 平面的降级是**继承**来的：
//   - L1-c：`conn.Context().Done()`（idle timeout / CONNECTION_CLOSE）
//   - L2：控制流的探针（有 ACK）连续无回显 ≤12s → 整条路径降级
//
// 也就是说：datagram 坏了但控制流还活着的「单平面黑洞」检测不到（同一 5 元组，
// 实际极罕见），这属于**已知且接受**的边界，写在这里以免被当成遗漏。
func (p *directPath) writeDatagram(pkt []byte) {
	if len(pkt) > directMaxDatagram {
		// 与中继完全一致的行为：超限丢弃（不截断、不改语义）
		if isDebugMode() {
			log.Printf("⚠️ [HARP] datagram 过大 %d，丢弃", len(pkt))
		}
		return
	}
	if err := p.conn.SendDatagram(pkt); err != nil {
		// ⚠️ 不用 debug 门控：datagram 报错通常是「对端没开 datagram」这种**持续性问题**，
		//    对端日志里看不到就会变成「不可靠 UDP 平面静默失效」。每条路径只报一次。
		if p.datagramWarned.CompareAndSwap(false, true) {
			log.Printf("⚠️ [HARP] datagram 发送失败（%s）：%v —— 该路径的不可靠 UDP 平面将不可用（可靠流量不受影响）",
				p.peerVIP, err)
		}
		return
	}
	p.bytesUp.Add(uint64(len(pkt)))
	p.touch()
}

// ---------- 控制流与健康（§4.1） ----------

type ctrlType string

const (
	ctrlHello     ctrlType = "hello"
	ctrlProbe     ctrlType = "probe"
	ctrlProbeEcho ctrlType = "echo"
)

type pathCtrlMsg struct {
	Type     ctrlType `json:"t"`
	Role     string   `json:"role,omitempty"`
	VIP      string   `json:"vip,omitempty"`
	Datagram bool     `json:"dgram,omitempty"`
	Seq      int64    `json:"seq,omitempty"`
	TS       int64    `json:"ts,omitempty"`
	RTTMs    int64    `json:"rttMs,omitempty"`
}

func (p *directPath) writeCtrl(msg pathCtrlMsg) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, _, cs := p.streams()
	if cs == nil {
		return fmt.Errorf("控制流未建立")
	}
	_ = cs.SetWriteDeadline(time.Now().Add(probeWriteTimeout))
	defer func() { _ = cs.SetWriteDeadline(time.Time{}) }()
	return writeFrameToStream(cs, data)
}

// ctrlLoop 控制流的读侧（在 watchLoop 里以 goroutine 形式启动）
func (p *directPath) ctrlLoop() {
	buf := make([]byte, maxFrameSize)
	for {
		// ⚠️ 必须走 `streams()`（锁下读），**不能直读 `p.ctrlStream`**：
		//   - `setup()` 在**另一个 goroutine** 里用 `setStreams()` 加锁赋值 ⇒ 直读是数据竞争；
		//   - `run()` 的启动门只查 `alive()`，而 1b-4 让 **trial** 也算 alive，且
		//     `setup()` 失败时是「先 `close(ready)`、再 `demote()`」⇒ 存在一个真实窗口：
		//     本 goroutine 醒来时 state 仍是 trial（alive=true）但三条流都还是 nil
		//     ⇒ 直读会把 nil 交给 `readFrame` 直接 panic（`-race -count=20` 实测踩到，
		//     栈顶 `io.ReadAtLeast({0x0,0x0},...)` ← `readFrame` ← `ctrlLoop`）。
		// 流还没建好（setup 失败 / 路径正在关停）⇒ 本循环直接退出：
		// 此时路径已在降级流程里，由 `demote()` 负责收尾，这里没有可读的控制流。
		_, _, ctrl := p.streams()
		if ctrl == nil {
			return
		}
		pkt, err := readFrame(ctrl, buf)
		if err != nil {
			if p.mgr.ctx.Err() == nil && p.alive() {
				log.Printf("⚠️ [HARP] 控制流读失败（%s）：%v", p.peerVIP, err)
				p.demoteErr(err)
			}
			return
		}
		var msg pathCtrlMsg
		if err := json.Unmarshal(pkt, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case ctrlHello:
			if isDebugMode() {
				log.Printf("🔗 [HARP] 控制流握手：%s role=%s dgram=%v", p.peerVIP, msg.Role, msg.Datagram)
			}
			p.echoedOnce.Store(false)
			p.lastProbe.Store(time.Now().UnixMilli())
		case ctrlProbe:
			// 收到对方的探测：把它的时间戳原样回显（对方据此算 RTT）
			p.lastProbe.Store(time.Now().UnixMilli())
			if err := p.writeCtrl(pathCtrlMsg{Type: ctrlProbeEcho, Seq: msg.Seq, TS: msg.TS}); err != nil {
				log.Printf("⚠️ [HARP] 探测回显失败（%s）：%v", p.peerVIP, err)
				p.demoteErr(err)
				return
			}
		case ctrlProbeEcho:
			// ⭐ 收到**自己那发探测**的回显 → 算 RTT + 清失败计数。
			//    现在两侧都发探测、都算 RTT（见 watchLoop 的说明）：
			//    只让响应方探针的话，发起方的 RTT 会永远停在 0（真机上踩过）。
			p.lastEcho.Store(time.Now().UnixMilli())
			p.probeMiss.Store(0)
			if msg.TS > 0 {
				rtt := time.Since(time.Unix(0, msg.TS))
				if rtt > 0 {
					p.rtt.Store(int64(rtt))
				}
			}
			// ⚠️ 可观测性（2026-09-27 真机 bug 后补）：试用期判定的**燃料**就是这条回显
			//	（`trialSampleStep` 看 `lastEcho` 是否增长），而它此前**完全静默**
			//	⇒ 真机上「15s 内采不到样本」无法区分
			//	「探针没发出去」/「对端没回显」/「回显到了但采样点错过」。
			//	打开方式见 `probeTraceEnabled`（环境变量，不必改代码）。
			if probeTraceEnabled() {
				log.Printf("🔁 [HARP] 探针回显（%s）：RTT=%v seq=%d（试用期样本燃料）",
					p.peerVIP, time.Since(time.Unix(0, msg.TS)).Round(time.Millisecond), msg.Seq)
			}
		}
	}
}

// watchLoop 看门狗：
//   - L1-c：conn.Context().Done()（QUIC 自己关了：idle timeout / CONNECTION_CLOSE）
//   - L2：**两侧各自**发探测并按「自己的回显」判活（对称探测）
//
// ⚠️ 为什么改成对称探测（1b-2A 真机 RTT 恒 0 的根因）：
// 早期沿用 1b-1「响应方探针、发起方回显」的方向，结果是**只有响应方**在算 RTT，
// 发起方永远拿不到值（路径 RTT 恒 0）。对称探测后：
//   - 两侧都能显示实时 RTT；
//   - 两侧都能独立通过「自己的回显缺失」判定路径失效（不再需要「发起方靠收不到探测来猜」）；
//   - 单向黑洞（只出不进 / 只进不出）在任一侧都能被发现。
func (p *directPath) watchLoop() {
	probeT := time.NewTicker(p.mgr.probeInterval)
	defer probeT.Stop()
	checkT := time.NewTicker(p.mgr.checkInterval)
	defer checkT.Stop()

	for {
		select {
		case <-p.mgr.ctx.Done():
			return
		case <-p.conn.Context().Done():
			// L1-c：零轮询、零延迟
			if p.alive() {
				// ⭐ 2026-09-27（Bug 3）：**分清「对端主动关闭」与「本机链路质量差」**。
				//
				//	对端主动关（应用层 CONNECTION_CLOSE）在真机上表现为
				//	`Application error 0x0 (remote): path closed` + 三条流 EOF。
				//	根因多半是**对端自己的判据判负**（或仲裁/收尾）——与本机链路质量无关。
				//	若当成 `direct-lost` ⇒ 走 `failQuality` 台阶 ⇒ 排 5m/30m 退避 + 档位虚涨
				//	（实测：`07:06:41 …（30m0s 后重试）：probe-timeout` 紧接着
				//	 `07:07:37 …（5m0s 后重试）：direct-lost`），
				//	既误导诊断，又给对端记一笔它不该背的退避。
				//	⇒ 判为 `P2PReasonPeerClosed`：**不排退避、不推进任何 streak**。
				//
				// ⚠️ 2026-09-27（Bug 3 覆盖修复）：判定已**收敛到唯一入口** `demoteWith`
				//	（`demoteErr` 收 err、`demote` 也按连接事实升级）⇒ 这里不再自己算 reason，
				//	避免「5 个分支各判一次 ⇒ 先到先赢」的竞态。
				log.Printf("⚠️ [HARP] 连接已关闭（%s）：%v", p.peerVIP, context.Cause(p.conn.Context()))
				p.demoteErr(context.Cause(p.conn.Context()))
			}
			return
		case <-probeT.C:
			// ⭐ 1b-2B：standby 期间**探针继续跑**（周期重评估的基础）
			if !p.alive() {
				continue
			}
			seq := p.probeSeq.Add(1)
			if err := p.writeCtrl(pathCtrlMsg{Type: ctrlProbe, Seq: seq, TS: time.Now().UnixNano()}); err != nil {
				log.Printf("⚠️ [HARP] 探测发送失败（%s）：%v", p.peerVIP, err)
				p.demoteErr(err)
				return
			}
			// ⚠️ 与「探针回显」配对使用：两行一起看就能区分
			//	「探针没发出去」/「发出去了但对端没回」/「回了但采样点错过」。
			//	打开方式见 `probeTraceEnabled`。本行的缺失 = watchLoop 没跑到（路径没起来）。
			if probeTraceEnabled() {
				log.Printf("📤 [HARP] 发出探针（%s）：seq=%d state=%s（等待回显）",
					p.peerVIP, seq, pathStateName(p.state.Load()))
			}
		case <-checkT.C:
			if !p.alive() {
				return
			}
			now := time.Now()
			p.checkDataPlaneHealth()
			// ⭐ 1b-2B：standby 判据 + 周期重评估（每秒一次判据、按门槛节流切换）
			p.evalStandby()
			// ⭐ 1b-4 第一步：试用期判定（先验后切）。
			//    只在 pathStateTrial 里生效；evalStandby 的 switch 不认 trial ⇒ 两者互不干扰。
			p.evalTrial(now)
			// ⭐ B2（2026-09-28）：**看门狗跑过的拍数**（纯观测，零语义）。
			//	用途：用例要断言「看门狗确实在跑」，而**不能**再用 `trialLastSampleAt` 是否前进
			//	—— B2 修复后"无回显时**不**推进闸门"（那正是修复点），所以它已不再能证明"在跑"。
			//	⚠️ **必须在这里（调用点）自增**，不能放进 `evalTrial` 内部：用例会**直接调用**
			//	   `evalTrial` 以外的采样函数，放进内部会让"看门狗在跑"的断言被伪造 ⇒ 假绿。
			//	守卫：`TestTrialNoEarlySettlementInsideWindow`（窗口未到 + 无回显 ⇒ 不结算，但此计数必须增长）。
			p.watchdogTicks.Add(1)
			// ⭐ 1b-4 第一步（第 5 条重置）：直连**持续**稳定 ≥5min ⇒ 清该对端失败记录。
			//    只在 Up 里成立（stableSince 离开 Up 即清零）⇒ trial/standby 期间自然不触发。
			p.maybeClearFailuresAfterStable(now)
			// ⭐ 对称探测的判活：看「自己那发探测的回显」。
			//    lastEcho == 0 表示「刚刚建立、还没测过」——用一个宽限期
			//    （probeInterval*(missLimit+1)）覆盖首轮，避免刚建立就误判。
			since := now.Sub(time.UnixMilli(p.lastEcho.Load()))
			if p.lastEcho.Load() == 0 {
				since = time.Since(p.since)
			}
			if since > p.mgr.probeInterval*time.Duration(p.mgr.probeMissLimit+1) {
				if p.probeMiss.Add(1) >= int32(p.mgr.probeMissLimit) {
					log.Printf("⚠️ [HARP] 探测连续无回显（%s，已 %v 无回显），判定路径失效",
						p.peerVIP, since.Round(time.Second))
					// ⚠️ 无错误对象（纯超时）⇒ `demoteErr(nil)`：仍会按**连接事实**升级，
					//    并交给「响应方探路收尾」启发式（灰度期）。
					p.demoteErr(nil)
					return
				}
			}
		}
	}
}

// ---------- 1b-2B：standby（质量降级）+ 周期重评估 ----------

// refreshRelayRTT 向服务端要一次「中继 RTT 估计」（RTT(本机↔S) + RTT(S↔对端)）。
//
// 复用既有的隧道内信令（一次 register+查询，轻量；信令流常驻）。
// 失败只记 debug 日志：拿不到就保持旧值/0，**绝不影响**业务。
func (p *directPath) refreshRelayRTT() {
	// ⭐ 先记「尝试时刻」：**无论这次有没有拿到值**都要记。
	//
	// 否则会出现「每拍打一次信令」：服务端不知道中继 RTT 时（旧服务端、或对端
	// 刚连上还没有统计）会一直返回 relayRttMs=0，而判据是「relay==0 就刷新」，
	// 于是每个路径每秒都做一次完整的信令往返（signalQuery 是同步 request/response，
	// 还会重新 register）。8 条直连就是 8 次/秒 —— 纯浪费，且会给服务端添无谓负载。
	p.relayRttTriedAt.Store(time.Now().UnixMilli())
	peer, err := p.mgr.host.signalQuery(p.peerVIP)
	if err != nil {
		if isDebugMode() {
			log.Printf("ℹ️ [HARP] 中继 RTT 刷新失败（%s）：%v", p.peerVIP, err)
		}
		return
	}
	// ⭐ 1b-4 第一步（Q3 · 第 4 条重置）：同一个信令查询顺带做「对端公网地址」对比缓存。
	//    为什么这里也要接：信号门的结果有正缓存（gatePositiveTTL=120s），只靠它会让
	//    「对端换 IP」最多晚 2 分钟才被发现；中继 RTT 刷新每 5 分钟必跑一次，覆盖更稳。
	//    ⚠️ 锁契约：调用方（refreshRelayRTT）不持任何锁。
	if dst, ok := parseIPv4(p.peerVIP); ok {
		p.mgr.notePeerPublicAddr(dst, peer.PublicAddr)
	}
	if peer.RelayRTTMs > 0 {
		p.relayRtt.Store(int64(peer.RelayRTTMs) * int64(time.Millisecond))
		// ⭐ 1b-4：试用期判定与日志要用它（见 noteTrialRelayRtt 的说明）
		p.noteTrialRelayRtt(p.relayRtt.Load())
	}
}

// evalStandby 每秒被看门狗调一次：判「直连是否明显劣于中继」，并做周期重评估。
//
// 规则（与需求逐条对应）：
//   - directRtt > relayRtt × standbyRatio（1.2×）**持续** standbyDegradeFor（30s）→ 进入 standby
//     （流量回中继，**连接与探针保留**）；
//   - standby 期间每 standbyEvalInterval（5 分钟）复查一次；directRtt ≤ relay×standbyExitRatio
//     （1.0×）才切回 direct —— 进/出两个阈值之间是**死区**，防阈值附近振荡（review 追问 1）；
//   - relayRtt 为 0（服务端不知道 / 旧服务端）→ **不做任何判断**（等价 1b-2A）；
//   - relayRtt 超过 relayRttRefreshInterval 未**尝试**刷新 → 判断前先查一次。
func (p *directPath) evalStandby() {
	now := time.Now()
	state := p.state.Load()
	if !p.alive() {
		return
	}

	relay := p.relayRtt.Load()
	triedAt := p.relayRttTriedAt.Load()

	// 基准过期（或从没查过）→ 先刷新一次。
	//
	// ⚠️ 节流看的是「上次**尝试**时刻」，不是「上次拿到值的时刻」：服务端不知道中继
	//    RTT 时会一直返回 0，若按「值为 0 就刷新」判，就会每拍（1s）每路径打一次信令。
	if triedAt == 0 || now.UnixMilli()-triedAt >= p.mgr.relayRttRefreshInterval.Milliseconds() {
		p.refreshRelayRTT()
		relay = p.relayRtt.Load()
	}
	if relay <= 0 {
		return // 服务端不知道中继 RTT → 不判断（兼容旧服务端）
	}

	direct := p.rtt.Load()
	if direct <= 0 {
		return // 直连 RTT 还没测到 → 不判断
	}

	switch state {
	case pathStateUp:
		// 进入判据：direct > relay × standbyRatio（默认 1.2×）
		threshold := time.Duration(float64(relay) * p.mgr.standbyRatio)
		if time.Duration(direct) <= threshold {
			p.degradeSince.Store(0)
			return
		}
		since := p.degradeSince.Load()
		if since == 0 {
			p.degradeSince.Store(now.UnixMilli())
			return
		}
		if now.UnixMilli()-since >= p.mgr.standbyDegradeFor.Milliseconds() {
			p.enterStandby(direct, relay)
		}
	case pathStateStandby:
		// 周期重评估：每 standbyEvalInterval 复查一次
		last := p.lastStandbyEval.Load()
		if last != 0 && now.UnixMilli()-last < p.mgr.standbyEvalInterval.Milliseconds() {
			return
		}
		p.lastStandbyEval.Store(now.UnixMilli())
		// ⭐ 退出判据用更松的 standbyExitRatio（默认 1.0×）→ 与进入阈值之间形成死区，
		//    消除「阈值附近来回切」（review 追问 1）。
		if time.Duration(direct) <= time.Duration(float64(relay)*p.mgr.standbyExitRatio) {
			p.exitStandby(direct, relay)
		}
	}
}

// enterStandby 进入 standby：**只切流量**（路由表里保留，sinkFor 只认 Up → 自动回中继）
//
// ⭐ 动作前状态复核（review：§4.2.1 的「检查与操作不互斥」修复）。
//
// 为什么必须在本函数里复核，而不是靠 `evalStandby` 开头那次 `state` 读：
// `evalStandby` 在读出 state 之后可能调用 `refreshRelayRTT()` —— 那是**一次同步的隧道内
// 信令往返**（几十 ms 到秒级）。这个窗口里路径完全可能已经结束（`demote`：连接断/L1/L2/
// 被仲裁丢弃），而 `evalStandby` 用的是**陈旧的局部 state 变量** ⇒ 原实现会把
// `Down` 覆写成 `Standby`：`alive()` 对 Standby 返回 true（连接却已关），并 emit 一条
// 假的 `quality-degraded`，把「已失败回退中继」显示成「质量不佳暂时切回」。
//
// 修法：**CAS 把「检查 + 转移」合成一个原子动作**（比「重读一次 state」更强：重读与 setState
// 之间仍有窗口）。`CompareAndSwap(Up, Standby)` 与 `demote`/`close` 的 `setState(Down)`
// 只有一个能赢：
//   - 本函数赢 ⇒ 正常进 standby；
//   - demote 先赢 ⇒ CAS 失败 ⇒ **直接返回**：不写 degradeSince、不打日志、**不 emit**。
//
// ⚠️ 不能用「共用一个 bool」：`enterStandby` 要求当前是 **Up**、`exitStandby` 要求当前是
// **Standby** —— 两者期望的旧状态不同，各自的 CAS 期望值也不同。
//
// 返回 true 表示真的完成了 Up→Standby 转移（false = 已被别的路径带走，什么都没做）。
func (p *directPath) enterStandby(direct, relay int64) bool {
	if !p.state.CompareAndSwap(pathStateUp, pathStateStandby) {
		return false // 已被 demote/close/其他转移带走 ⇒ 绝不覆写、绝不发假事件
	}
	// ⚠️ 两步写（CAS + 下面三行 Store）。**stableSince 必须在这里清 0**：
	//    CAS 只写了 state，若不补这一行，「离开 Up ⇒ stableSince 清零」这条不变量就被破坏
	//    （路径会带着 Up 期间正在跑的计时器停在 Standby；读侧靠 `state != Up` 挡住，
	//     但一旦读序被改就立刻误判）。已完成一轮 review 后补上的缺口。
	//    读侧契约见 stableSince 字段上的说明：本顺序（state 先落地）满足「state 先读」。
	p.stableSince.Store(0)
	p.degradeSince.Store(0)
	p.lastStandbyEval.Store(time.Now().UnixMilli())
	log.Printf("🐢 [HARP] 质量不佳，切回中继（standby）：%s 直连 RTT=%dms > 中继估计=%dms × %.1f"+
		"（连接与探针保留，每 %v 复查一次；≤ %.1f× 时切回）",
		p.peerVIP, msAtLeast1(direct), msAtLeast1(relay), p.mgr.standbyRatio,
		p.mgr.standbyEvalInterval, p.mgr.standbyExitRatio)
	p.mgr.emit(p.status(P2PStateStandby, P2PReasonQualityDegraded))
	return true
}

// exitStandby 复查发现恢复 → 切回 direct（连接一直活着，所以零成本）
//
// ⭐ 动作前状态复核：同 enterStandby（唯一期望的旧状态是 **Standby**）。
// 原实现会在「复查窗口内路径已 demote」时把 `Down` 覆写成 `Up` 并 emit 假 `direct`
// —— 那是比假 standby 更坏的一种：`sinkFor` 只认 Up，会把流量**发给一条已关闭的连接**。
//
// 返回 true 表示真的完成了 Standby→Up 转移。
func (p *directPath) exitStandby(direct, relay int64) bool {
	if !p.state.CompareAndSwap(pathStateStandby, pathStateUp) {
		return false // 已不是 standby（多半是 demote 抢先）⇒ 绝不把死路径推回直连
	}
	// ⚠️ 两步写（CAS + 下面两行 Store）：进入 Up ⇒ `stableSince` 必须记**这一刻**
	//    （与 setState 的规则一致：稳定计时从真正转 Up 开始）。同一窗口内读侧可能看到
	//    「state=Up + stableSince=0」⇒ `since == 0 ⇒ false`（保守，不清失败记录）；
	//    唯一「偏新」的方向是多读到这一刻 ⇒ 时长算短 ⇒ 判不清，属安全方向。
	p.stableSince.Store(time.Now().UnixMilli())
	p.degradeSince.Store(0)
	p.lastStandbyEval.Store(0)
	log.Printf("⚡ [HARP] 质量已恢复，切回直连：%s 直连 RTT=%dms ≤ 中继估计=%dms × %.1f",
		p.peerVIP, msAtLeast1(direct), msAtLeast1(relay), p.mgr.standbyExitRatio)
	p.mgr.emit(p.status(P2PStateDirect, P2PReasonOKDirect))
	return true
}

// ---------- 数据面健康告警（review 追问 3） ----------

// pathSilentWarn / pathOneWayWarn 的门槛见 defaultSilentWarn / defaultOneWayWarn
// 与管理器实例字段（`m.silentWarn` / `m.oneWayWarn`）——**不是包级可变量**。
//
// ⭐ 设计要点：**只告警，不降级**。
//   - 降级/淘汰负责「资源与切换」，它们的判据（探针失败、空闲）**无法区分**
//     「用户真没用」与「数据面坏了」；
//   - 告警负责「可观测性」：用**发送侧的证据**把两者区分开——
//     只有在「我们已经把包交给这条路径去发（enqueued>0）却一个字节都没发出去」，
//     或者「发出了却一个字节都没收到」时才会告警。用户单纯没流量 ⇒ 不告警。

// checkDataPlaneHealth 每秒钟跑一次；命中就给一次告警（每条路径只报一次）。
// 门槛来自管理器实例（`p.mgr.silentWarn` / `p.mgr.oneWayWarn`），不是包级变量。
func (p *directPath) checkDataPlaneHealth() {
	up := time.Since(p.since)
	upBytes, downBytes, queued := p.bytesUp.Load(), p.bytesDown.Load(), p.enqueued.Load()

	// ① 有包要发、却一个字节都没发出去 ⇒ 写路径根本没生效（写协程卡住/流不可用）
	if queued > 0 && upBytes == 0 && up >= p.mgr.silentWarn && p.silentWarned.CompareAndSwap(false, true) {
		// ⚠️ 级别纪律（2026-09-28，B2 切片）：本条的**判据**是"有包要发但上行 0 字节"，
		//	但**成因有多种**（对端判负未装表 / 对端暂不可达 / 对端进程重启 / 防火墙拦截）
		//	⇒ 用 `ℹ️` 而非 `⚠️`：**判据与推测分离**，不把"疑似"写成结论。
		//	⚠️ 不要改这里的**置位条件**（`silentWarned` 的语义与时机都不变 —— 有守卫：
		//	`TestSilentPathWarnsButIsNotDemoted` / `path_test.go` 的阈值断言）。
		log.Printf("ℹ️ [HARP] %s 上行 0 字节（已有 %d 个包要发，%v 内）：本机侧未观测到上行"+
			"（可能：对端试用期判负未装表 / 对端暂不可达 / 防火墙拦截；隧道不受影响，流量仍可走中继）",
			p.peerVIP, queued, up.Round(time.Second))
	}
	// ② 发出了、却始终收不到任何下行 ⇒ **对端**没有在把数据发回来（多种成因，见下）
	if upBytes > 0 && downBytes == 0 && up >= p.mgr.oneWayWarn && p.oneWayWarned.CompareAndSwap(false, true) {
		// ⚠️ 与上一条同款：判据是"下行 0 字节"，**成因不止一个** —— A2（方案 A）之后
		//	「对端判负 ⇒ 不装表、但保留连接」会让本侧**必然**看到"上行有量、下行 0"
		//	⇒ 这是**方案 A 的预期后果**，不是故障（详见 A2/A3a 交付说明的记账）。
		log.Printf("ℹ️ [HARP] %s 下行 0 字节（已上行 %d 字节，%v 内）：可能原因：对端试用期判负未装表"+
			" / 对端暂不可达 / 对端进程重启 · 防火墙拦截（本机侧无上行障碍；此条为提示，不计为故障）",
			p.peerVIP, upBytes, up.Round(time.Second))
	}
}

// healthWarn 供面板显示当前告警（空串 = 正常）
func (p *directPath) healthWarn() string {
	// ⚠️ 措辞与上面的 log 同步（判据在前、成因在后）；**只改文案**，判定顺序与状态位不变。
	switch {
	case p.silentWarned.Load():
		return "数据面：上行 0 字节（有包待发）"
	case p.oneWayWarned.Load():
		return "数据面：下行 0 字节（上行有量）"
	default:
		return ""
	}
}

// ---------- 降级（§2.6-③ / §4.2：顺序不可颠倒） ----------

// demote 路径降级（唯一入口）：**先摘路由 → 再关路径 → 最后排退避**（顺序是本函数的契约）
//
// ⚠️ 语义边界（2026-09-27 Bug 3 覆盖修复）：`reason == P2PReasonDirectLost` 时，本函数会按
//
//	**连接事实**升级为 `P2PReasonPeerClosed`（见 `demoteWith`）。其它原因码——
//	`tryFailTrial` 的 `QualityPoor`、`setup` 的 `DirectHandshakeFailed`——**不受影响**：
//	判负/握手失败各有自己的原因码与退避档，不得被「对端关闭」覆盖（否则判负语义被掩盖）。
func (p *directPath) demote(reason string) { p.demoteWith(nil, reason) }

// demoteErr **触发错误类**失败（默认结论恒为 `DirectLost`；5 条 L1 链路专用）。
//
// 为什么把「对端主动结束」的判定收在这里（而不是 5 个分支各判一次）：
//
//	`demoteOnce` 保证的是「**第一个调用者赢**」，**不是**「peer-closed 赢」⇒ 若各分支
//	自己算原因码再调 demote，先到的本地超时分支会把原因码定成 direct-lost（竞态）。
//	收在唯一入口 ⇒ 谁先进都按**同一个事实**算出同一个码。
func (p *directPath) demoteErr(err error) { p.demoteWith(err, P2PReasonDirectLost) }

// demoteWith 降级实现：先做「对端主动结束」升级，再走一次性的 demoteOnce 体。
func (p *directPath) demoteWith(err error, reason string) {
	if reason == P2PReasonDirectLost {
		// ① 分支自己的错误（ApplicationError{Remote} / StreamError{Remote} / io.EOF）
		// ② 连接事实（`conn.Context()` 的 cancel cause）——两者**互补**：
		//    `connection.go` 里 `ctxCancel` 是 `run()` 的 **defer** ⇒ 存在「流已解锁但
		//    cause 还没写」的窗口；反过来 FIN 场景 err=io.EOF 时 cause 可能已写好。
		// ⚠️ p.conn 可能为 nil（单测夹具的字面量路径）⇒ 必须 nil 守卫。
		if isPeerInitiatedClose(err) ||
			(p.conn != nil && isPeerInitiatedClose(context.Cause(p.conn.Context()))) {
			reason = P2PReasonPeerClosed
		} else if p.scoutTearDownHeuristic() {
			// ⭐ 灰度期启发式（无 peer-close 事实时的补位；见 scoutTearDownHeuristic）
			p.markScoutHeuristicHit("demote")
			reason = P2PReasonPeerClosed
		}
	}
	p.terminateDown(reason)
}

// Done 路径终结（对端关闭 / 管理器关停 / 仲裁丢弃）—— **出口恒为 `terminateDown`**（真死优先）。
//
// ⚠️ A2（review 追问 2）：**不丢 B1 的 peer-closed 识别** —— 这里把连接 cause 交给 `demoteErr`，
//
//	由它统一做 `isPeerInitiatedClose` 判定（类型级 + 文案兜底），再落到 `terminateDown`。
//	即：`Done()` 的**出口唯一**（绝不走「保留连接」那条），但**原因码仍按事实分类**
//	（不会退化成裸 `direct-lost`，否则 Bug 3 的修复会在这条入口上失效）。
func (p *directPath) Done() {
	var cause error
	if p.conn != nil {
		cause = context.Cause(p.conn.Context())
	}
	p.demoteErr(cause)
}

// trialRejectedTTL ⭐ A2：判负**保留连接**的登记存活时长（TTL 淘汰的**唯一判据**；白名单见 evictIdle）。
//
// 60s 的依据：够对端走完它自己的判定/收尾（对端试用期 15s + 余量），又不至于长期占资源。
const trialRejectedTTL = 60 * time.Second

// ---------- ⭐⭐ A2（方案 A）：判负保留连接 / 复用 / 专用清理 ----------

// rejectTrial **本侧判负但保留连接**（方案 A 的核心）。
//
// 与 `terminateDown`/`demote` 的区别（这就是方案 A 的全部意义）：
//
//   - **不关连接**：`ctrlLoop` 照旧回显对端探针（否则对端 probe-timeout 后也判负 ⇒ 双侧都关）；
//   - **不装路由表**：本侧不主动发数据（`sinkFor` 只认 Up）；
//   - 登记**留在** `m.trialPaths`（摘登记交给 pruneLoop 按 TTL 扫 —— 见 `releaseRejected`）；
//   - 排一个**短冷却**（`backoffBusy`=30s，**不推进任何 streak**、保留历史 `lastErr`）
//     —— 否则流量会立刻再触发 ⇒ 重试风暴 + 旧连接白白占资源。
//
// ⚠️ 本函数**不关心「为什么判负」**：原因码修正是**判定阶段**的事（`tryFailTrial` 里的
//
//	B1 灰度期启发式）⇒ 两个语义分开，别把 peer-closed 修正塞进来（review 追问 1 拍板 A）。
//
// ⚠️⚠️ **两条入口的分工（2026-09-28 修复一个真 bug，勿再合并）**：
//
//	`tryPassTrial → installAfterTrial` 是「**判定函数赢门 → 动作函数不再赢门**」；
//	A2 原先把两件事都塞进 `rejectTrial`（自己赢门 + 结算），而 `tryFailTrial` **已经先赢了门**
//	⇒ `rejectTrial` 的 CAS 必然失败并 `return` ⇒ **生产路径上判负是空操作**：
//	路径既不保留（没进 `Rejected`）、也不关闭、不排退避、TTL 也扫不到 —— **永远挂在 `trial`**。
//	实测由三条**集成/端到端**用例揪出（`TestTrialFailStaysQualityPoorOnInitiator` /
//	`TestTrialInsufficientSamplesFailsConservatively` / `TestTrialFailOnPoorQualityRetainsConnection`）；
//	A2 单测**全部绿**是因为它们直接调 `rejectTrial()`（门未消费）⇒ 典型的"单测绿、集成死"。
//
// 📌 纪律固化：`P2SP-工程纪律.md` §3 第 9 条「**判定函数赢门 → 动作函数不再赢门**（但**必须**做
// state 前置）」；本文件的两个参照实现就是 `tryPassTrial → installAfterTrial` 与
// `tryFailTrial → rejectTrialSettled`。
func (p *directPath) rejectTrial() {
	if p.state.Load() != pathStateTrial {
		return
	}
	if !p.trialDone.CompareAndSwap(false, true) {
		return // 判定门：只有赢家能结算（与 tryPassTrial 互斥）
	}
	p.rejectTrialSettled()
}

// rejectTrialSettled 判负的**实际结算**，供**已赢得判定门**的调用方使用
// （`tryFailTrial` 的 `trialDone` CAS；或 `rejectTrial` 自己赢门后转调）。
//
// ⚠️ 本函数**不再判断定门** —— 重复赢门就是空操作（见 `rejectTrial` 头的修复留档）。
func (p *directPath) rejectTrialSettled() {
	// ⚠️ **幂等 / 防覆盖前置**（与 `installAfterTrial` 的 `state != Trial ⇒ 放弃装表` **对称**）：
	//	本函数**不判断定门**（门已在 `tryFailTrial` / `rejectTrial` 处赢走），幂等性由 **state** 保证：
	//	· 重复调用 ⇒ 状态已是 `Rejected` ⇒ 返回（否则重复写日志，并把 `rejectedAt` 重置
	//	  ⇒ **无端延长 60s TTL**）；
	//	· 若已被 `terminateDown` / `close` 推到 `Down` ⇒ 返回（否则会把**已死的路径复活**
	//	  成 `Rejected` 并重新挂号等 TTL）。
	//	⚠️ 只允许**已赢得判定门**的调用方使用（`tryFailTrial`，或 `rejectTrial` 赢门后转调）。
	if p.state.Load() != pathStateTrial {
		return
	}
	p.mgr.removeRoute(p.peer, p) // 幂等：生产 trial 路径本就不在路由表（夹具会装表，一并摘掉）
	p.rejectedAt.Store(time.Now().UnixMilli())
	p.setState(pathStateRejected)
	p.mgr.setRejectedCooldown(p.peer)
	log.Printf("🧪 [HARP] %s 试用期未通过 ⇒ **保留连接**（方案 A：本侧不用、对端可用；登记保留 %v，"+
		"期间照常回显对端探针）", p.peerVIP, trialRejectedTTL)
	// ⭐ A2（2026-09-28 **拍板 C**）：**补回判负的状态事件**。
	//
	//	为什么必须有：判负后这条路径会从面板消失（`Paths()` 过滤 `Rejected`），若没有事件解释，
	//	用户只会看到「直连突然没了」。
	//	为什么**复用 `(failed, quality-poor)` 而不新增** state/reason：前端**已经**为这一对写好
	//	info 级分支、**不弹提示**（`App.vue` 的 `p2p:status` 处理，注释原文「⭐ 1b-4 方案 A…
	//	不弹错误提示」），文案即 "…failed the quality trial; staying on the relay (auto-retry later)"
	//	—— 与 A2 行为一致；而**新 reason 会落到 `else` 分支 ⇒ 反而弹 error 弹窗**。
	//	⚠️ 载荷**逐字对齐 `terminateDown` 的 emit**（`Path: "relay"`、`Retryable: true`）
	//	⇒ 与方案 A **之前**的 UI 载荷**零差异**（否则就是"顺手改了 UI 面"）。
	//	⚠️ **幂等性由上面那道 `state != Trial` 前置保证**：重复调用不会重复发事件；
	//	而「复用后再判负」是**新的一次判定**（state 已回到 `Trial`）⇒ **应当再发一次**。
	p.mgr.emit(P2PStatus{
		PeerVIP: p.peerVIP, State: P2PStateFailed, ReasonCode: P2PReasonQualityPoor,
		ReasonText: P2PReasonText(P2PReasonQualityPoor), Path: "relay",
		At: time.Now().UnixMilli(), Retryable: true,
	})
}

// reuseRejected 复用**已保留**的连接，重跑试用期（`Rejected` → `Reusing`）。
//
// ⚠️ 这是**同一个对象的转换** ⇒ **不重启** `runOnce` / `watchLoop`
//
//	（`watchLoop` 是常驻 for/select，`checkT` 就跑在它里面）。
//
// ⚠️ CAS 之后**先终检**连接：已断 ⇒ 回滚转 Down（否则会留下「复用中的死连接」）。
func (p *directPath) reuseRejected() bool {
	if !p.state.CompareAndSwap(pathStateRejected, pathStateReusing) {
		return false
	}
	if p.conn == nil || p.conn.Context().Err() != nil {
		p.terminateDown(P2PReasonDirectLost) // 真死优先：回滚转 Down
		return false
	}
	// ⚠️ 末态**直接落 Trial**（Q3 拍板）：`Reusing` 只作为本函数内的 **CAS 保护窗口**存在。
	//
	//	必须用 **CAS 而不是 Store**：若这期间 `terminateDown`/`close` 已把状态推到 Down
	//	（对端关闭 / 管理器关停 / 仲裁丢弃），CAS 失败 ⇒ 我们**绝不覆盖** Down，
	//	否则会留下「状态 Trial 但连接已关、资源已释放」的不一致（自愈但状态说谎）。
	//	⚠️ 这也消灭了「另设 terminated 标志」方案**无法消除**的 TOCTOU 窗口：
	//	  两个原子变量之间没有相互顺序 ⇒ 标志检查通过后仍可能被对方覆盖；
	//	  而把「判定 + 转移」合成一次 CAS 就没有这个窗口（零新增字段）。
	//
	// ⚠️⚠️ **顺序纪律：CAS 是准入 —— 未通过则一个字都不动**（review 2026-09-27 追问）。
	//
	//	曾经的顺序是「先重置 settled/trialDone 与基线，再 CAS」，后果是：CAS 失败（路径已被
	//	`close()` 推到 Down）时字段已被改过 —— 尤其 **`trialDone` 被从 true 打开成 false**，
	//	而 `close()` 刚把它置 true 当作「第一道取消门」（"装表一条已关的连接"就是靠它挡的）
	//	⇒ 会在 Down 路径上留下**破门**状态（今天不触发只因 `evalTrial` 先查 state，属侥幸）。
	//	⇒ 正确顺序：**先用 CAS 拿到准入，再动任何字段**。
	if !p.state.CompareAndSwap(pathStateReusing, pathStateTrial) {
		return false // 已被别人终结（Down）：那条路已完成清理，这里什么都不动
	}
	// —— 准入已拿到，从这里开始才允许改字段 ——
	p.settled.Store(false)
	p.trialDone.Store(false)
	// ⚠️ 开工清单第 1 条：基线取**复用那一刻**的 `lastEcho`，**不是 0**
	//	（写 0 会让复用后第一个采样窗内的任何旧回显都算好样本 ⇒ 试用期虚高通过）。
	p.trialStartedAt.Store(time.Now().UnixMilli())
	p.trialLastEcho.Store(p.lastEcho.Load())
	p.trialLastSampleAt.Store(0)
	p.trialGood.Store(0)
	p.trialSamples.Store(0)
	// ⚠️ 终检（收掉「CAS 之后」的窄窗口）：`close()`/`terminateDown` 仍可能在我们刚拿到准入
	//	之后的这一小段里把状态推 Down。若已发生 ⇒ 把取消门**还回去**并报失败，
	//	绝不留下「Down 但 trialDone=false」的破门组合。
	//	⚠️ 残余窗口（诚实记账）：`close()` 的两个 Store（`trialDone=true` 与 `setState(Down)`）
	//	  若恰好跨过本行前后，理论上仍可能让 trialDone 落回 false；此时路径已是 Down（死），
	//	  而**所有** `trialDone` 的读者都先查 `state`（`evalTrial`/`tryPass`/`tryFail` 三道门）
	//	  ⇒ 无实际后果；要彻底消除需把两个变量合成一个（不值得）。
	if p.state.Load() != pathStateTrial {
		p.trialDone.Store(true) // 还回取消门
		return false
	}
	// ⚠️ `reuseCount` 计的是**成功复用次数**（review 追问 2）：放在准入之后，
	//	否则"复用失败"也会 +1 ⇒ 将来任何"失败但仍存活"的分支会**提前触发**
	//	「最多复用 1 次」的立即释放。
	p.reuseCount.Add(1)
	log.Printf("♻️ [HARP] %s 复用已保留的连接重跑试用期（第 %d 次复用，窗口 %v）",
		p.peerVIP, p.reuseCount.Load(), p.trialWindow())
	return true
}

// releaseRejected **释放**这条「判负保留连接」的路径（TTL 到期 / 二次判负后调用）。
//
// ⚠️ **命名与 `terminateDown` 的不对称是有意为之**（review 2026-09-27）：
//
//	`terminate` = **真死终结**（连接坏了/被终结，语义是"这条路径死了"）；
//	`release`   = **释放保留的连接**（连接本身可能还好，只是本侧不再保留它）。
//	⇒ **不要为了对称而统一命名** —— 统一会抹掉「连接是否还好」这个关键区别。
//
// ⚠️ **终态是 `Down`（不是 Rejected/RejectedSettling）**：因为 `close()` 内部会
//
//	`setState(pathStateDown)`（`path.go` 的 close，注释写明它是「唯一写入点」之一）
//	⇒ 顺带保证 `alive()` 归假、探针/读写协程退出。**这是 `close()` 决定的，不是本函数写的。**
//
// ⚠️ **状态白名单**：只处理 `Rejected`/`RejectedSettling` 两态，其余（`Reusing` 复用窗口、
//
//	`Trial`、`Up`、`Standby`、`Down`）**一律 no-op** —— 否则会把**正在复用/正在跑**的连接关掉
//	（review 追问抓到的真实危险；由 `TestReleaseRejectedIgnoredOutsideRejectedState` 钉住）。
//
// ⚠️ **不得**共用 `terminateOnce`（那会吞掉后续 `terminateDown` 的 close ⇒ 泄漏）：
//
//	幂等靠 `settled` 这道**可重置**的收尾门（CAS）。
//
// ⚠️ **不排退避**：对端关闭 / TTL 到期 / 二次判负都不是新的失败（短冷却已由
//
//	`rejectTrial` → `setRejectedCooldown` 写过），与 `failPeerClosed` 同口径。
func (p *directPath) releaseRejected() {
	switch p.state.Load() {
	case pathStateRejected, pathStateRejectedSettling:
		// 允许：正是本函数负责的两态
	default:
		return // 其余状态一律不碰（尤其 Reusing：那是正在复用的连接）
	}
	if !p.settled.CompareAndSwap(false, true) {
		return
	}
	p.state.CompareAndSwap(pathStateRejected, pathStateRejectedSettling)
	p.untrack()
	p.close()
}

// terminateDown 路径的**终结**实现（唯一出口）：摘路由 → 关路径 → 排退避（顺序是本函数的契约）。
//
// ⚠️ A2 纪律：`terminateOnce` 由本函数**独占**（`releaseRejected` 不得共用，见字段注释）。
// ⚠️ 「真死优先」：即使当前是 `Rejected`（保留连接态），真死也必须走这条路 ⇒ 状态落 Down。
// ⚠️ 原因码已在 `demoteWith` 里按事实分类（peer-closed / direct-lost）⇒ 本函数只管执行。
func (p *directPath) terminateDown(reason string) {
	p.terminateOnce.Do(func() {
		defer close(p.demotedCh)
		// ⭐ 1b-4：**第一道取消门**（无条件置位，不参与判定）。
		//
		// 必须在 setState 之前：`setState(pathStateDown)` 已经会让 evalTrial 的
		// 「state != trial」门生效，但那条门的判定与结算之间仍有窗口 —— 两条门叠加
		// 才能保证「试用期判定」与「降级」**绝不双写**（一个装表 + 一个关路径 ⇒ 路径
		// 被装进路由表却已经关掉，表现为「面板显示直连但不通」）。
		p.trialDone.Store(true)
		p.untrack() // 摘掉「试用中」登记（幂等；此时自己不可能已装表）
		// ⭐ 1b-4：必须走 setState（唯一写入点）——它同时清零 stableSince，
		// 直接写 state 字段会让「稳定 ≥5min」的持续语义在不同路径上不一致（review 提醒 1 的缺口）。
		p.setState(pathStateDown) // 软状态：写协程看到它不是 Up 就不再走这条路径

		// ① 先摘路由：从这一刻起，所有写协程立刻回中继（零握手、零等待）
		//    ⚠️ 锁契约：removeRoute 自己取 routeMu；调用方此时**不持任何锁**
		//    （写协程/看门狗路径），且**绝不能**在持 routeMu 时调用 demote（会自死锁）。
		p.mgr.removeRoute(p.peer, p)
		if h := p.mgr.hooks; h != nil && h.RouteRemoved != nil {
			h.RouteRemoved(p.peerVIP)
		}

		// ② 再关路径（conn/transport/socket 全部释放；幂等）
		p.close()
		if h := p.mgr.hooks; h != nil && h.PathClosed != nil {
			h.PathClosed(p.peerVIP)
		}

		// ③ 最后排退避重试
		//    ⚠️ 锁契约：scheduleRetry 自己取 m.mu，调用方不持锁（同上）。
		p.mgr.scheduleRetry(p.peer, reason)

		log.Printf("⚠️ [HARP] 已回退中继：%s（原因=%s；本路径共承载 ↑%d ↓%d 字节）",
			p.peerVIP, P2PReasonText(reason), p.bytesUp.Load(), p.bytesDown.Load())
		p.mgr.emit(P2PStatus{
			PeerVIP: p.peerVIP, State: P2PStateFailed, ReasonCode: reason,
			ReasonText: P2PReasonText(reason), Path: "relay",
			At: time.Now().UnixMilli(), Retryable: true,
		})
	})
}

// isPeerInitiatedClose 判断「这条路径的终结」是不是**由对端发起**的。
//
// ⭐ 2026-09-27（Bug 3）：用途见 `demoteWith` —— 对端主动结束不该被当成「本机链路质量差」，
// 否则会白排一档退避（实测 5m/30m）并误导诊断。
//
// 判据覆盖 **4 种形态**（顺序：类型级优先、EOF 其次、文案兜底）：
//
//	① 连接级 · 应用层 CONNECTION_CLOSE：`*quic.ApplicationError` ⇒ 读 `Remote`
//	   （`quic-go/errors.go` 把它导出为 qerr 的**类型别名**，`Remote` 是 fork 的实现细节）
//	② 连接级 · 传输层 CONNECTION_CLOSE：`*quic.TransportError` ⇒ **故意 return false**
//	   ⚠️ 该类型在**本 fork 里确实有** `Remote` 字段（qerr/errors.go:16，`Error()` 会用
//	   `getRole(Remote)` 打印 `(remote)`），这里不看它是**口径选择**而非漏写：
//	   传输层错误（idle timeout / 握手超时 / 无可用路径 / 对端协议错误）一律按本机侧处理 —
//	   对端因协议错误关闭时，长退避比短冷却更合适（短冷却会掩盖问题）。
//	   📌 待评审：改为读 `Remote` 可多覆盖「对端因协议错误关闭」，A2 或独立切片评审。
//	③ 流级 · 对端 RESET_STREAM：`*quic.StreamError`（`Remote bool`）⇒ 读 `Remote`
//	   ⚠️ **必须类型级**：它的文案是 `stream N canceled by remote with error code N`，
//	   **不含 `(remote)`** ⇒ 文案兜底救不了。
//	④ 流级 · 对端 FIN：`io.EOF` / `io.ErrUnexpectedEOF` ⇒ true
//	   ⚠️ **为什么必须认**（2026-09-27 真机复盘的第二个洞）：`directPath.close()` 的顺序是
//	   「三条流 `Close()`（FIN）→ `conn.CloseWithError`」（path.go），而对端
//	   `receiveStream.readImpl` 的判序把 `currentFrameIsLast && currentFrame==nil ⇒ io.EOF`
//	   排在 `closeForShutdownErr` **之前** ⇒ **即使连接关闭错误已经写好，读循环拿到的仍是
//	   `io.EOF`**。真机日志「`Application error 0x0 (remote)` + 三条流 EOF」正是这个形态：
//	   前者来自 L1-c 的 conn cause，后者来自三条读循环。
//	⑤ 兜底：文案含 `(remote)` —— 留给「将来 quic-go 换了错误包装」的情形（见下）。
//
// ⚠️ **升级守卫**（`go.mod` 依赖版本变化时必须复核本函数）：
//
//	`TestQuicGoApplicationErrorShape` / `TestQuicGoStreamErrorShape` 用**编译期断言**
//	钉住「这两个类型存在且带 `Remote`、且文案形态符合预期」⇒ 升级 quic-go 导致形状变化时
//	会在编译/首次运行时红，而不是线上静默失效。
//
// ⚠️ 保守取向：只有明确「对端发起」才判 true；**本机关闭 / idle timeout / EOF 除外**：
// 传输层错误一律 false（见 ②）。
func isPeerInitiatedClose(cause error) bool {
	if cause == nil {
		return false
	}
	// ① 连接级：应用层 CONNECTION_CLOSE（类型级）
	var appErr *quic.ApplicationError
	if errors.As(cause, &appErr) {
		return appErr.Remote
	}
	// ② 连接级：传输层错误 —— **故意**不看 Remote（口径选择，见函数头 ②）
	var trErr *quic.TransportError
	if errors.As(cause, &trErr) {
		return false
	}
	// ③ 流级：对端 RESET_STREAM（类型级；文案兜底救不了）
	var stErr *quic.StreamError
	if errors.As(cause, &stErr) {
		return stErr.Remote
	}
	// ④ 流级：对端 FIN（读循环拿到的就是它）
	if errors.Is(cause, io.EOF) || errors.Is(cause, io.ErrUnexpectedEOF) {
		return true
	}
	// ⑤ 兜底：文案判据
	return strings.Contains(cause.Error(), "(remote)")
}

// close 关闭路径资源（幂等；不含路由与退避，**也不等 goroutine 退出**）
//
// ⚠️ 不能在这里 wg.Wait()：数据面协程自己会因为读写失败走 demote() → close()，
// 等自己就是死锁（踩过一次：写超时降级 → 整个测试卡死到超时）。
// 需要等 goroutine 退出的调用方请用 wait()，且**不能**是这条路径自己的协程。
func (p *directPath) close() {
	p.closeOnce.Do(func() {
		// ⭐ 第 3 步-D：测试侧泄漏定位埋点（与 notePathCreated 配对）
		if p.leakKey != "" {
			notePathClosed(p.leakKey)
		}
		// ⭐ 1b-4：**第一道取消门**。close() 可能由管理器（Close/ClearAll/淘汰）
		// 或仲裁丢弃直接调用，这时 demote() 没走过 ⇒ 必须在这里也置位，
		// 否则试用期判定可能在路径关闭之后才结算（装表一条已关的连接）。
		p.trialDone.Store(true)
		p.untrack()               // 摘掉「试用中」登记（幂等）
		p.setState(pathStateDown) // ⭐ 1b-4：走唯一写入点（同时清零 stableSince）
		// 放行（或立刻结束）还没开始的 goroutine
		p.readyOnce.Do(func() { close(p.ready) })
		bulk, crit, ctrl := p.streams()
		if bulk != nil {
			_ = bulk.Close()
		}
		if crit != nil {
			_ = crit.Close()
		}
		if ctrl != nil {
			_ = ctrl.Close()
		}
		_ = p.conn.CloseWithError(0, "path closed")
		for _, c := range p.closers {
			if c != nil {
				_ = c()
			}
		}
	})
}

// wait 等这条路径的数据面 goroutine 全部退出。
//
// ⚠️ 只能从**非本路径**的 goroutine 调用（管理器关闭、淘汰、仲裁丢弃旧连接）。
//
// ⚠️ **不要直接用本函数**（第 3 步-B）：无界等待会在串行路径上永久占住调用方
// （装表点 / 淘汰 / pathManager.Close 都是串行的）。生产与测试都实测到过
// 「某条路径的数据面协程不退出 ⇒ 调用方永久阻塞」。请用 `waitTimeout`。
func (p *directPath) wait() { p.wg.Wait() }

// pathWaitTimeout **等待数据面协程退出的上界**（第 3 步-B）。
//
// 为什么需要：`p.wait()` 是**串行路径上的阻塞等待**，共 7 处调用点，其中三处是用户可见的：
//   - `installAfterTrial`（装表点）：仲裁被卡住 ⇒ 试用期结算再也推进不了；
//   - `evictIdle` / `evictLRU`（淘汰）：看门狗被卡住 ⇒ 后续淘汰/试用期判定全停；
//   - `pathManager.Close` / `ClearAll`：客户端关闭被卡住。
//
// 语义契约（review 拍板）：
//   - 超时后**不 panic、不阻塞调用方、不改路径状态机**——`close()` 已经完成全部释放动作
//     （置 Down / 摘路由 / 关流 / 关 conn / 跑 closers），这里是**纯等待**；
//   - 只记一条告警日志，便于事后定位「哪条路径的哪些协程没退出」；
//   - 变量而非常量：与 `stableClearFailuresAfter` 等同规矩，测试可临时调小。
var pathWaitTimeout = 5 * time.Second

// waitTimeout 带界的等待：最多等 `pathWaitTimeout`，返回 true 表示**超时**（协程没退完）。
//
// ⚠️ 关键细节：**每个调用者都拿自己的 timer 去 select 同一个缓存通道** ⇒
// 无论被调用多少次，**每次调用都在界内返回**（不会出现「第一个调用者超时返回、
// 后续调用者却等那个永远不关闭的通道」这种半有界形态）。
//
// ⚠️ 本函数**自身不新建 goroutine**（边界五项「无新增 goroutine」）：
// 「等 wg」的协程由 `waitDone` 用 `waitDoneOnce` 保证**每条路径最多起一个**，
// 它在协程最终退出后自然结束；超时只是**不再等**，不会取消或影响那些协程。
func (p *directPath) waitTimeout() bool {
	t := time.NewTimer(pathWaitTimeout)
	defer t.Stop()
	select {
	case <-p.waitDone():
		return false
	case <-t.C:
		return true
	}
}

// waitDone 返回一个「数据面协程全部退出」时关闭的通道（每条路径最多一个等待协程）。
func (p *directPath) waitDone() <-chan struct{} {
	p.waitDoneOnce.Do(func() {
		ch := make(chan struct{})
		p.waitDoneCh = ch
		go func() {
			p.wg.Wait()
			close(ch)
		}()
	})
	return p.waitDoneCh
}

// waitTimeoutLogged 统一的「带界等待 + 超时告警」入口（**所有调用点都走这里**，避免 7 处各写一遍）。
//
// `where` 传调用点用途（如 "装表点" / "淘汰" / "关停"），便于从日志区分超时来源。
func (p *directPath) waitTimeoutLogged(where string) {
	if p.waitTimeout() {
		log.Printf("⚠️ [路径] wait() 超时（%v）：%s（%s；role=%s state=%s）——"+
			"数据面协程未在期限内退出，不阻塞调用方（close 已完成释放）",
			pathWaitTimeout, p.peerVIP, where, p.role, pathStateName(p.state.Load()))
	}
}

// ---------- 小工具 ----------

func (p *directPath) touch() { p.lastUse.Store(time.Now().UnixMilli()) }

// demoted 返回一个在 demote() 完成后关闭的通道（测试用）
func (p *directPath) demoted() <-chan struct{} { return p.demotedCh }

// rttValue 当前直连 RTT（0 = 还没测到）
func (p *directPath) rttValue() time.Duration { return time.Duration(p.rtt.Load()) }

func (p *directPath) status(state, reason string) P2PStatus {
	path := "relay"
	if state == P2PStateDirect {
		path = "direct"
	}
	return P2PStatus{
		PeerVIP: p.peerVIP, State: state, ReasonCode: reason, ReasonText: P2PReasonText(reason),
		Path: path, RTTDirectMs: msAtLeast1(p.rtt.Load()),
		RTTQuicMs: msAtLeast1(p.mgr.hostRTT()), At: time.Now().UnixMilli(),
		PathState: pathStateName(p.state.Load()), Trigger: P2PTriggerTraffic,
		BytesUp: p.bytesUp.Load(), BytesDown: p.bytesDown.Load(), DirectSince: p.since.UnixMilli(),
	}
}

func (m *pathManager) emit(st P2PStatus) {
	if m.host != nil {
		m.host.onPathEvent(st)
	}
}

// hostRTT 中继 RTT（直连 vs 中继对比用）；宿主没提供时返回 0
func (m *pathManager) hostRTT() int64 {
	if h, ok := m.host.(interface{ relayRTT() int64 }); ok {
		return h.relayRTT()
	}
	return 0
}

// writeFrameToStreamIntf 已合并进 client.go 的 writeFrameToStream（改成作用于窄接口 directStream）

func parseIPv4(s string) ([4]byte, bool) {
	var out [4]byte
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return out, false
	}
	copy(out[:], ip.To4())
	return out, true
}

func ip4ToString(b [4]byte) string {
	ip := net.IPv4(b[0], b[1], b[2], b[3])
	return ip.String()
}

// bytesGreater a > b（按 IPv4 字节序，等价于数值比较）
func bytesGreater(a, b [4]byte) bool {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// isBroadcastOrMulticast4 与服务端 data_server.isBroadcastOrMulticast 同款判据
func isBroadcastOrMulticast4(ip [4]byte) bool {
	if ip[0] >= 0xE0 && ip[0] <= 0xEF {
		return true
	}
	if ip == [4]byte{0xFF, 0xFF, 0xFF, 0xFF} || ip == [4]byte{} || ip[3] == 0xFF {
		return true
	}
	return false
}

// io.Closer 兼容（closers 允许 nil）
var _ io.Closer = (*directPath)(nil)

func (p *directPath) Close() error { p.close(); return nil }
