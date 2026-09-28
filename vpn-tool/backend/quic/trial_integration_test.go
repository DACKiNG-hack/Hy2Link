package quic

// vpn-tool/backend/quic/trial_integration_test.go
//
// ⭐ 1b-4 第一步（切片 2 · 状态机本体）的**集成**用例：直接驱动 `newDirectPath` + `run()`
// + 看门狗，覆盖设计 §9 的每一条定论：
//
//	A. 试用期本体
//	  1. 先验后切：新建路径在 trial、数据走中继、**不装表**，且发出一条 trial 事件；
//	  2. 试用期通过（3 取 2 + RTT 判据）⇒ 才装表切直连，且首批包真的走直连；
//	  3. 质量差（直连 RTT 不达标）⇒ 窗口到点判负 ⇒ quality-poor 关路径 + 质量差退避档；
//	  4. 探针无回显 ⇒ **L2 在试用期内照常生效**（不等满窗口，原因码更准）；
//	  5. 窗口内不提前结算（harness 自检，防「假绿」）；
//	  6. 两道取消门：结算与降级并发 ⇒ 不双写（装表的那次不可能是「已判死的路径」）。
//
//	B. 5 条重置接线
//	  7. 对端换 IP（信令 peerPublicAddr 变化）⇒ 清该对端失败记录；首次观测/未变/空串都不清；
//	  8. NAT 重探测**成功** ⇒ 清全部失败记录（失败不清）；
//	  9. 本机 VIP 变更 ⇒ 清全部失败记录（同值 no-op）；
//	 10. 稳定 ≥5min ⇒ 清失败记录，且**离开 Up 后重新计时**（持续语义，不是累计）；
//	 11. 重连 ⇒ 新 pathManager 天然空退避表（reset 语义由构造保证）。
//
// ⚠️ 时间参数一律**在启动前注入到管理器实例**（`trialWindowOverride` / `probeInterval` /
// `checkInterval`，见 path.go 的「时序契约」）与路径的 `setupTimeout`，
// 并统一用 `stableClearFailuresAfter` 压缩「稳定 ≥5min」门槛，不真等 15 秒；
// 生产默认值由 trial_backoff_test.go / TestStableClearFailuresDefaultIsFiveMinutes 钉住。

import (
	"encoding/binary"
	"encoding/json"
	"log"
	"sync"
	"testing"
	"time"
)

// ---------- harness ----------

// trialHarness 一条「正在试用」的路径 + 驱动它所需的假件。
type trialHarness struct {
	pm       *pathManager
	host     *fakeHost
	path     *directPath
	conn     *fakeConn
	echoStop chan struct{}
	echoDone chan struct{}
	// hookLog 记录 pathHooks.TrialPassed/TrialFailed 的触发顺序（"pass" / "fail"）
	hookMu  sync.Mutex
	hookLog []string
}

// trialCfg harness 的全部注入参数。
//
// ⚠️ 这里刻意做成**一个结构体、一次传入**：所有字段都必须在 `run()` 之前写好
// （见 path.go 的「时序契约」）。第一版把这些散成「建好后逐个赋值」，
// 已经连续踩了三次（trial window / 中继基准 / probeMissLimit）——**每个都在
// `-race` 下变成数据竞争或偶发红**。收成一个结构体后，「在 harness 之外改 pm」这件事
// 就没有入口了。
type trialCfg struct {
	window     time.Duration
	probeEvery time.Duration
	checkEvery time.Duration
	// relaySeed 中继 RTT 基准的初始种子（0 = 不种，模拟「服务端还不知道」）。
	// 需要「第一拍就按真实基准判定」的用例必须传非 0，否则前几个样本会因 `relay <= 0`
	// 被判「不好」，用例退化成在窗口内抢样本。
	relaySeed time.Duration
	// missLimit 无回显判死阈值。默认给 1000（多数用例只想考察试用期判定，不想被 L2 抢）；
	// L2 专项用例传 2（真实值）。
	missLimit int
	// goodRecord 在**建路径之前**往质量表写一条「质量好」记录（命中档用例用）。
	//
	// ⚠️ 必须在建路径前注入：`pm.setQualityTable` 之后、`newDirectPath` 之前。
	//	建完路径再改（例如 `h.path.peer = …`）会与看门狗/数据面协程**数据竞争**
	//	（`-race` 实测报过），而且窗口可能已被首拍读过 ⇒ 用例变 flaky。
	goodRecord bool
}

// newRawTrialPath 造一条**真正的** trial 路径（不结算试用期）：
// newDirectPath → addTrialPath → run()，再等控制流建好（否则试探针回显会白丢）。
func newRawTrialPath(t *testing.T, cfg trialCfg) *trialHarness {
	t.Helper()
	host := newFakeHost()
	pm := newPathManager(host)
	// ⚠️ 时序契约：这些参数由看门狗 goroutine 读取 ⇒ 必须在 run() 之前注入。
	//    本 harness 不调 pm.start()，且下面在 run() 之前完成全部注入（一次性、无遗漏入口）。
	pm.probeInterval = cfg.probeEvery
	pm.checkInterval = cfg.checkEvery
	pm.trialWindowOverride = cfg.window
	pm.trialNeedOverride = trialNeedGoodNormal
	pm.trialRelayRttSeed = int64(cfg.relaySeed)
	// ⭐ A1（2026-09-27）：试用期**已与质量表解耦**（`hasGoodQualityRecord` 已删除）
	//    ⇒ 空表/非空表都不再影响这些用例的试用期语义。
	pm.setQualityTable(newPeerTable())
	// ⭐ 命中档：**在建路径之前**写「质量好」记录（见 trialCfg.goodRecord 的时序契约）
	if cfg.goodRecord {
		pm.qualityTable().Record(ip4("192.168.30.12"), peerOutcome{
			Kind: peerGood, Reason: P2PReasonOKDirect,
		})
	}
	if cfg.missLimit > 0 {
		pm.probeMissLimit = cfg.missLimit
	} else {
		pm.probeMissLimit = 1000
	}
	t.Cleanup(pm.close)

	h := &trialHarness{
		pm: pm, host: host,
		echoStop: make(chan struct{}), echoDone: make(chan struct{}),
	}
	pm.hooks = &pathHooks{
		TrialPassed: func(string) {
			h.hookMu.Lock()
			h.hookLog = append(h.hookLog, "pass")
			h.hookMu.Unlock()
		},
		TrialFailed: func(string, string) {
			h.hookMu.Lock()
			h.hookLog = append(h.hookLog, "fail")
			h.hookMu.Unlock()
		},
	}

	conn := newFakeConn()
	p, err := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"),
		role: pathRoleInitiator, conn: conn, myVIP: host.vip,
		closers: []func() error{func() error { return nil }},
	})
	if err != nil {
		t.Fatalf("newDirectPath: %v", err)
	}
	// ⚠️ 这里没有直接调 handleEstablished（它内部就 run() 了），而是在 run() 之前把
	//    路径级参数（setupTimeout）写好，其余步骤与它逐条一致：
	//    进试用表 → run() → 通道日志 → 进入试用期日志 → emit(trial)。
	// ⚠️ setup 超时给 **3s**（不是 300ms）：正常路径下 setup 在毫秒级完成，这个值只是
	//    **负载余量** —— 全量 `-race` 运行时调度抖动可能让 300ms 不够，那会让 setup 失败
	//    ⇒ 路径被判死（`direct-handshake-failed`），而本用例的 `waitFor` 只等 `pathStateUp`
	//    ⇒ 报出「试用期未通过」这种**误导性**失败（实测踩过）。
	p.setupTimeout = 3 * time.Second
	h.path, h.conn = p, conn

	pm.routeMu.Lock()
	pm.addTrialPath(p)
	p.run()
	pm.routeMu.Unlock()
	log.Printf("✅ [HARP] 通道已建立：%s（role=%s，RTT=%s；进入试用期，数据仍走中继）",
		p.peerVIP, p.role, rttText(p.rtt.Load()))
	p.logTrialEnter()
	pm.emit(p.status(P2PStateTrial, P2PReasonTrialProbing))

	waitFor(t, "控制流建立", func() bool {
		_, _, ctrl := p.streams()
		return ctrl != nil
	})
	// ⭐ review 追问 4：setup 的**真实**耗时告警。
	//
	//	为什么需要：本 harness 把 `setupTimeout` 放宽到 3s 只是为了**负载余量**
	//	（正常路径 setup 在毫秒级完成）。若某天它真超过 500ms，那不是"余量"，而是
	//	**产品代码变慢或卡住**的信号 —— 放宽超时会把这种回归掩盖成"绿"。
	//	⇒ 这里显式把「setup 耗时」转成一条 warning，让真问题**可见**（不失败、不阻塞）。
	if d := time.Since(p.since); d > 500*time.Millisecond {
		t.Logf("⚠️ [harness] setup 耗时 %v（>500ms）：正常路径应在毫秒级完成；"+
			"若稳定复现，请查 path.setup/openStreams/acceptStreams 是否有回归", d.Round(time.Millisecond))
	}
	return h
}

// TestTrialInsufficientSamplesFailsConservatively ⭐ 采样修复后的边界（review 拍板 A，2026-09-27）：
//
//	采样判据改成「本窗内有回显才落样本」之后，15s 窗口内**可能只有 1 个样本**
//	（0好0坏 / 1好0坏 / 1坏0好）—— 都到不了「3 取 2」的门槛。
//
// 判据（**保守**）：「证明不了可用」不能当「通过」⇒ **样本不足 ⇒ 判负**。
//
// 本用例构造「窗口内只有 1 个好样本」：窗口很短、探针间隔很长、回显只来一次
// ⇒ 窗口到点时好样本 1 < need 2 ⇒ 必须判负（而不是因为「有 1 个好样本」就通过）。
//
// ⚠️ 有牙：把「好样本够才通过」改成「有任意好样本就通过」⇒ 本用例红。
func TestTrialInsufficientSamplesFailsConservatively(t *testing.T) {
	h := newRawTrialPath(t, trialCfg{
		// 窗口 1s、探针间隔 800ms ⇒ 窗口内最多 1~2 个采样点
		window: time.Second, probeEvery: 800 * time.Millisecond, checkEvery: 50 * time.Millisecond,
		relaySeed: 100 * time.Millisecond, missLimit: 1000,
	})
	h.path.rtt.Store(int64(38 * time.Millisecond))
	// 只喂**一次**回显（在窗口刚开始不久）⇒ 最多 1 个好样本
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, _, ctrl := h.path.streams()
		fs, ok := ctrl.(*fakeStream)
		if !ok {
			return
		}
		msg, _ := json.Marshal(pathCtrlMsg{Type: ctrlProbeEcho, Seq: 1, TS: time.Now().UnixNano()})
		frame := make([]byte, 4+len(msg))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(msg)))
		copy(frame[4:], msg)
		select {
		case fs.reads <- frame:
		case <-h.echoStop:
		}
	}()

	// ⚠️ A2（方案 A，2026-09-28）：判负**不再走 Down** ⇒ 不能等 `demoted()`（会永远等不到，
	//	实测红在 `waitFor` 超时）。等待目标改为「进入 `Rejected`」；
	//	「样本不足 ⇒ 保守判负」这条**不变量本身不变**（下面的断言照旧）。
	waitFor(t, "窗口到点必须判负（样本不足 ⇒ Rejected）", func() bool {
		return h.path.state.Load() == pathStateRejected
	})
	if got := h.path.state.Load(); got == pathStateUp {
		t.Fatal("样本不足时**不得**装表通过（保守判负）")
	}
	if n := int(h.path.trialGood.Load()); n >= h.path.trialNeedGood() {
		t.Fatalf("前置：本用例构造的是「好样本不足」情形，实际好样本 %d（need %d）",
			n, h.path.trialNeedGood())
	}
}

// TestTrialSampleNotCollidingWithProbeSend ⭐⭐ 记账 2 的修复守卫（2026-09-27 真机日志）：
//
//	`probeT` 与 `checkT` **同刻创建** ⇒ `checkInterval` 整除 `probeInterval` 时两者同拍触发
//	⇒ 采样点落在「刚发出探针、回显还没回来」的那一毫秒 ⇒ **必然判「无回显」**：
//
//	06:26:49 📤 发出探针 seq=1
//	06:26:49 🧪 采样 0/1：回显增量=false   ← 与探针同一拍
//	06:26:49 🔁 探针回显 seq=1
//
//	白吃一个采样点；**发起方更糟**：直连 RTT 也要靠回显才测到 ⇒ 该拍还叠加
//	`directRtt<=0 ⇒ 不好` ⇒ 第一个样本双重必败。
//
// **修复判据（事实驱动，不是时间相位）**：`trialSampleStep` 只在
//
//	「本样本窗内**已经有回显**」（`lastEcho > trialLastEcho`）时才落样本；
//	没回显就把采样点顺延到下一拍。⇒ 采样点自动落到回显之后，且不会因为
//	「探针刚发出」而白吃样本。
//
// ⚠️ 有牙：
//
//	① 删掉「没回显就不落样本」那段 ⇒ 本用例第 ① 步会消费样本 ⇒ 红；
//	② 把判据改成「距上次发探针 ≥ step/2 才采」（我第一版就是这么写的）⇒
//	   `TestTrialSamplingUnderProductionTiming` 红（采样点被**全部**推掉，试用期拿不到样本）。
//
// ⚠️ 本条**返工过三次**（都是被有牙验证/全量跑揪出来的），教训留档：
//
//	① 只断言「好样本 ≥1」⇒ 不红（假守卫）；
//	② 先「等 lastEcho 非 0」再起回显 goroutine ⇒ 自锁死（`lastEcho` 恒 0）；
//	③ 靠 ticker 相位撞「同刻」⇒ 测试环境不可稳定复现；而时间相位判据本身也是错的（见 ② 的修复）。
//	最终：**手工喂状态 + 事实判据**，确定性可验。
func TestTrialSampleNotCollidingWithProbeSend(t *testing.T) {
	const probeEvery = time.Second
	h := newRawTrialPath(t, trialCfg{
		window: 10 * time.Second, probeEvery: probeEvery, checkEvery: 50 * time.Millisecond,
		relaySeed: 100 * time.Millisecond, missLimit: 1000,
	})
	p := h.path
	p.rtt.Store(int64(38 * time.Millisecond)) // RTT 可测（否则样本会因 RTT=0 判不好，干扰判定）

	// ① 「距上次采样已够久、但本窗内没有回显」⇒ **不得消费样本**（正是真机那一拍）
	p.trialLastSampleAt.Store(time.Now().Add(-probeEvery).UnixMilli())
	before := p.trialSamples.Load()
	p.trialSampleStep(time.Now())
	if got := p.trialSamples.Load(); got != before {
		t.Fatalf("本样本窗内没有回显时不得消费样本（应顺延到下一拍）：之前 %d、之后 %d"+
			" —— 这就是真机 `采样 0/1：回显增量=false` 那一拍", before, got)
	}

	// ② 让「本窗内来了一次回显」⇒ 该采样点必须**落样本且判「好」**
	p.lastEcho.Store(time.Now().UnixMilli())
	p.trialLastSampleAt.Store(time.Now().Add(-probeEvery).UnixMilli())
	p.trialSampleStep(time.Now())
	if got := p.trialSamples.Load(); got != before+1 {
		t.Fatalf("本窗内有回显 ⇒ 必须落一个样本：期望 %d，实际 %d", before+1, got)
	}
	if got := p.trialGood.Load(); got < 1 {
		t.Fatalf("有回显 + RTT 达标 ⇒ 该样本必须判「好」，实际好样本 %d", got)
	}
}

// TestTrialBaselineSampledFromTrialEntry ⭐⭐ 记账 1 的修复守卫（2026-09-27 真机 bug）：
//
//	**试用期采样基线必须在「进入试用期那一刻」写**，不能拖到第一个采样点。
//
// 为什么必须这样（旧实现的真实损失）：基线写在第一个采样点（t=checkEvery）时，
// `t ∈ [进入试用期, 第一个采样点)` 之间到达的回显会**全部落在基线之前** ⇒ 第一个
// probeInterval 窗整个白丢 ⇒ 15s 窗口名义「3 个样本」实际只有 **2 个采样点**，
// 而「3 取 2」正好需要 2 个好样本 ⇒ **容错为 0**（真机上任何一次抖动都会判失败）。
//
// ⚠️ 本用例**直接钉住「基线语义」**，不靠「让窗口刚好差一拍」的脆弱构造
//
//	（第一版就是那么写的：它**不红**，因为那个构造下新旧实现都能过 ⇒ 假守卫）：
//
//	① 进入试用期时 `trialLastEcho` 必须 **== 进入那一刻的 `lastEcho`**；
//	② 此后任何新回显（`lastEcho` 增长）在**下一个采样点**必须被算成「好样本」，
//	   即使那次增长发生在**第一个采样点之前**。
//
// ⚠️ 有牙：把 `newDirectPath` 里那行 `p.trialLastEcho.Store(...)` 删掉 ⇒ ② 的
//
//	「基线=0，回显=1 ⇒ 应判好」会红（基线停在 0 也能过 —— 真正暴露缺陷的是
//	`trialLastEcho` 被**第一次采样点重写**的情况，见下面的 ②b）。
func TestTrialBaselineSampledFromTrialEntry(t *testing.T) {
	h := newRawTrialPath(t, trialCfg{
		window: 10 * time.Second, probeEvery: time.Second, checkEvery: 50 * time.Millisecond,
		relaySeed: 100 * time.Millisecond, missLimit: 1000,
	})
	// ① 进入试用期那一刻的旧回显必须被记为基线（不会被算进样本）
	if got := h.path.trialLastEcho.Load(); got != 0 {
		t.Fatalf("基线应等于进入试用期时的 lastEcho（此处 0），实际 %d", got)
	}
	h.path.rtt.Store(int64(38 * time.Millisecond))

	// ② 模拟「第一个采样点之前」就到了一次回显：lastEcho 增长到 1
	h.path.lastEcho.Store(time.Now().UnixMilli())
	// 等一个采样点（按 probeInterval 节流：第一采样点 = started + probeEvery）
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if h.path.trialSamples.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h.path.trialSamples.Load() < 1 {
		t.Fatal("窗口内应至少落一个样本（采样机制没跑起来？）")
	}
	// ②b ⭐ 关键断言：这次回显发生在第一个采样点之前，但它**必须**被算进样本。
	//     旧实现会在第一个采样点把基线重写成「当时的值」⇒ 这次回显被吃掉 ⇒ 好样本 0。
	if got := h.path.trialGood.Load(); got < 1 {
		t.Fatalf("「进入试用期后、第一个采样点前」到达的回显必须算作好样本，实际好样本 %d（样本 %d）"+
			" —— 说明基线被第一个采样点重写了（记账 1 的缺陷）",
			got, h.path.trialSamples.Load())
	}
}

// TestTrialSamplingUnderProductionTiming ⭐ 试用期采样在**生产时序**下确实能通过（真机 bug 的排除项）。
//
// 背景（2026-09-27 真机双设备验证）：直连进入试用期后 15s 被判 `direct-lost` 关掉，
// **从未出现**「试用期通过」。第一嫌疑是「采样机制在真机没跑起来」。
//
// 本用例按**生产比例**（window:probe:check = 15:5:1，缩小 4 倍）复现真机形态：
//   - 路径级探针按 `probeInterval` 发；
//   - 对端**只在每次探针之后**回显一次（不像 `startEcho` 那样每 5ms 一次 ——
//     每 5ms 回显会把时序问题掩盖掉，这正是本地一直没抓到这个 bug 的原因）；
//   - 中继基准与直连 RTT 用真机量级（100ms / 38ms）。
//
// **结论：通过**（实测 3.12s 装表，样本数/好样本数都达标）
// ⇒ **采样机制不是根因**；真机上「15s 内只有 1 次探针」是因为**路径级回显根本没到**
// （路径级探针与回显**不打日志**，所以日志里看不到它们）。
//
// ⚠️ 本用例的价值是把这条排除项**钉死**：以后任何人再怀疑采样机制，先看这里；
// 同时它守住「生产比例下必须能在窗口内通过」这条不变量（若哪天有人调窗口/间隔调坏，它会红）。
func TestTrialSamplingUnderProductionTiming(t *testing.T) {
	// 生产比例 15:5:1 缩小 4 倍 ⇒ 3.75s : 1.25s : 0.3125s（用例 ≤5s）
	const (
		window     = 3750 * time.Millisecond
		probeEvery = 1250 * time.Millisecond
		checkEvery = 312 * time.Millisecond
	)
	h := newRawTrialPath(t, trialCfg{
		window: window, probeEvery: probeEvery, checkEvery: checkEvery,
		relaySeed: 100 * time.Millisecond, // 中继基准：直连 38ms ≪ 80ms ⇒ 样本可判「好」
		missLimit: 1000,
	})
	h.path.rtt.Store(int64(38 * time.Millisecond)) // 真机实测直连 RTT

	// ⭐ 关键：回显**只在每次路径级探针之后**到达（= 真机形态）。
	go func() {
		tk := time.NewTicker(probeEvery)
		defer tk.Stop()
		_, _, ctrl := h.path.streams()
		fs, ok := ctrl.(*fakeStream)
		if !ok {
			return
		}
		seq := int64(0)
		for {
			select {
			case <-h.echoStop:
				return
			case <-tk.C:
				seq++
				msg, _ := json.Marshal(pathCtrlMsg{Type: ctrlProbeEcho, Seq: seq, TS: time.Now().UnixNano()})
				frame := make([]byte, 4+len(msg))
				binary.BigEndian.PutUint32(frame[:4], uint32(len(msg)))
				copy(frame[4:], msg)
				select {
				case fs.reads <- frame:
				case <-h.echoStop:
					return
				}
			}
		}
	}()

	waitFor(t, "生产时序下试用期应在窗口内通过", func() bool {
		return h.path.state.Load() == pathStateUp
	})
	if n := int(h.path.trialSamples.Load()); n < trialNeedGoodNormal {
		t.Fatalf("窗口内应至少采到 %d 个样本（3 取 2 的前提），实际 %d", trialNeedGoodNormal, n)
	}
	if n := int(h.path.trialGood.Load()); n < trialNeedGoodNormal {
		t.Fatalf("窗口内应有 ≥%d 个「好」样本，实际 %d（样本数=%d）",
			trialNeedGoodNormal, n, h.path.trialSamples.Load())
	}
}

// startEcho 启动「对端一直在回显探针」的假对端（每 5ms 一次，保证每个样本窗都有回显）。
//
// ⚠️ 必须把回显帧**直接塞进控制流的读通道**：`fakeStream` 的 Write 只写 `wrote` 缓冲，
//
//	不会回环到自己的 Read（真实 QUIC 的对端是**另一条流**）。用 `writeCtrl` 假装对端回显，
//	本机的 `ctrlLoop` 永远读不到（harness 第一版就踩了这个坑：试用期样本全是「无回显」）。
func (h *trialHarness) startEcho() { h.startEchoRTT(0) }

// startEchoRTT 同上，但把回显时间戳**回拨** rttBackdate ⇒ 本机算出的直连 RTT ≈ rttBackdate。
func (h *trialHarness) startEchoRTT(rttBackdate time.Duration) {
	_, _, ctrl := h.path.streams()
	fs, ok := ctrl.(*fakeStream)
	if !ok {
		panic("harness 依赖 fakeStream 的控制流")
	}
	go func() {
		defer close(h.echoDone)
		t := time.NewTicker(5 * time.Millisecond)
		defer t.Stop()
		seq := int64(0)
		for {
			select {
			case <-h.echoStop:
				return
			case <-t.C:
				seq++
				msg, _ := json.Marshal(pathCtrlMsg{
					Type: ctrlProbeEcho, Seq: seq,
					TS: time.Now().Add(-rttBackdate).UnixNano(),
				})
				frame := make([]byte, 4+len(msg))
				binary.BigEndian.PutUint32(frame[:4], uint32(len(msg)))
				copy(frame[4:], msg)
				select {
				case fs.reads <- frame:
				case <-h.echoStop:
					return
				}
			}
		}
	}()
}

func (h *trialHarness) stopEcho() {
	select {
	case <-h.echoStop:
	default:
		close(h.echoStop)
	}
	<-h.echoDone
}

// events 状态事件快照（判定两条通道：event 的 State/ReasonCode）
func (h *trialHarness) events() []P2PStatus {
	h.host.mu.Lock()
	defer h.host.mu.Unlock()
	return append([]P2PStatus(nil), h.host.events...)
}

// hooks 试用期判定的触发顺序快照
func (h *trialHarness) hooks() []string {
	h.hookMu.Lock()
	defer h.hookMu.Unlock()
	return append([]string(nil), h.hookLog...)
}

func hasEvent(evs []P2PStatus, state, reason string) bool {
	for _, e := range evs {
		if e.State == state && e.ReasonCode == reason {
			return true
		}
	}
	return false
}

// ---------- A1：先验后切 ----------

// TestTrialEntersTrialWithoutInstallingRoute ⭐ 设计 §9 Q5 + §8.1：
// 通道建成后**进 trial、不装表、数据走中继**，并且**两条通道都能看到 trial**
// （面板走 pathStateName、事件走 emit —— 少任何一条前端都不会显示「测试中」）。
func TestTrialEntersTrialWithoutInstallingRoute(t *testing.T) {
	h := newRawTrialPath(t, trialCfg{window: 300 * time.Millisecond, probeEvery: 40 * time.Millisecond, checkEvery: 20 * time.Millisecond, relaySeed: 100 * time.Millisecond})

	// ① 状态与「活着」：trial 必须 alive（否则探针/读写协程退出，试用期永远拿不到样本）
	if got := h.path.state.Load(); got != pathStateTrial {
		t.Fatalf("新建路径必须在 trial，实际 %v", got)
	}
	if !h.path.alive() {
		t.Fatal("trial 必须 alive（Q2 的前提）")
	}
	// ② 不进路由表 ⇒ 数据走中继；但面板可见（Paths 必须包含它且状态为 trial）
	if ch := h.pm.sinkFor(h.path.peer, planeTCP); ch != nil {
		t.Fatal("trial 期间不得承载流量（sinkFor 必须为 nil）")
	}
	infos := h.pm.Paths()
	if len(infos) != 1 || infos[0].State != "trial" {
		t.Fatalf("面板必须能看到试用中的路径且状态为 trial，实际 %+v", infos)
	}
	// ③ 事件通道：必须已经发过一条 (trial, trial-probing)
	if !hasEvent(h.events(), P2PStateTrial, P2PReasonTrialProbing) {
		t.Fatalf("进入试用期必须 emit (trial, trial-probing)，实际事件 %+v", h.events())
	}
}

// TestTrialPassInstallsRouteAndCarriesTraffic ⭐ 设计 §9 Q1/Q2 + 日志：
// 「3 取 2」通过后才装表；装表后首批包真的走直连（不是只改了个状态位）。
func TestTrialPassInstallsRouteAndCarriesTraffic(t *testing.T) {
	// 窗口给足 5s：结算本身在「好样本 ≥ 2」时**提前发生**（≈80ms），窗口只是上限；
	// 给宽是为了在全量 `-race` 负载下不受调度抖动影响（窗口太短会让用例退化成
	// 「在 1s 内抢到 2 个好样本」，实测偶发红）。
	h := newRawTrialPath(t, trialCfg{window: 5 * time.Second, probeEvery: 40 * time.Millisecond, checkEvery: 20 * time.Millisecond, relaySeed: 100 * time.Millisecond})
	h.startEcho() // 直连 ≈ 0ms（< 100×0.8）
	defer h.stopEcho()

	waitFor(t, "试用期通过并转 Up", func() bool { return h.path.state.Load() == pathStateUp })
	if got := h.hooks(); len(got) != 1 || got[0] != "pass" {
		t.Fatalf("试用期判定应恰好通过一次，实际 %v", got)
	}
	if ch := h.pm.sinkFor(h.path.peer, planeTCP); ch == nil {
		t.Fatal("试用期通过后必须装表：sinkFor 应能选中该路径")
	}
	if _, ok := h.pm.routeVIP(h.path.peer); !ok {
		t.Fatal("routeVIP 也必须能看到它（面板/诊断用）")
	}
	if n := int(h.path.trialGood.Load()); n < trialNeedGoodNormal {
		t.Fatalf("好样本数应 ≥ %d，实际 %d", trialNeedGoodNormal, n)
	}
	if got := h.pm.trialPathCount(); got != 0 {
		t.Fatalf("通过后必须从试用表里摘掉，实际还剩 %d 条", got)
	}
	// 首批包真的走直连：往 sinkFor 拿到的队列投一个包 ⇒ 出现在 bulk 流上
	ch := h.pm.sinkFor(h.path.peer, planeTCP)
	ch <- pathPkt{plane: planeTCP, data: ipPacket(h.host.vip, h.path.peer, []byte("first"))}
	waitFor(t, "直连流上出现首个数据帧", func() bool {
		bs := h.conn.bulkStream()
		return bs != nil && len(bs.dataFrames()) >= 1
	})
	if !hasEvent(h.events(), P2PStateDirect, P2PReasonOKDirect) {
		t.Fatalf("通过试用期必须 emit (direct, ok-direct)，实际 %+v", h.events())
	}
}

// TestTrialFailOnPoorQualityRetainsConnection ⭐ A2（方案 A）改写版 —— 原
// `TestTrialFailOnPoorQualityClosesWithQualityPoor`（2026-09-28 按 A2 契约改写，**非删除**）：
// 直连 RTT 不达标 ⇒ 窗口到点判负 ⇒ **保留连接**（`Rejected`）+ 30s 短冷却。
//
// ⚠️ 为什么改写而不是删除（review 2026-09-28）：它是**端到端**用例（真实 ticker/窗口/emit/hook），
// A2 的单文件用例是夹具级；直接删掉会丢掉「窗口到点判定」+「hooks 次数」+「原因码」这三类覆盖。
//
// ⚠️ 与旧版的差异（旧版编码的是**方案 A 之前**的契约）：
//
//	旧：判负 ⇒ 关路径（`demoted()`）+ `Down` + `pathCount()==0` + `qualityStep=1` + 5min 档
//	新：判负 ⇒ **保留连接**（`Rejected`；`alive()` 真）+ 登记保留（`pathCount()==1`）
//	     + **不推进档位** + 30s 短冷却（`backoffBusy`）
//	不变：hooks 恰好判负一次 / 判负路径不进路由表 / **必须排退避** / 不推进打洞 streak
//
// ⚠️ **已知缺口（2026-09-28 实测，待拍板）**：A2 之后判负**不再 emit `(failed, quality-poor)`**
// ——`emit` 只存在于 `terminateDown`（`path.go`），而 `rejectTrial()` 只写日志。
// 旧版此处有 `hasEvent(h.events(), P2PStateFailed, P2PReasonQualityPoor)` 断言 ⇒ **补 emit 时
// 必须把这条守卫一起加回**（见 A2 文档 §0.3 的待拍板项）。
func TestTrialFailOnPoorQualityRetainsConnection(t *testing.T) {
	// 中继 50ms（种在 run() 之前 ⇒ 第一拍就按真实基准判定）
	h := newRawTrialPath(t, trialCfg{window: 200 * time.Millisecond, probeEvery: 40 * time.Millisecond, checkEvery: 20 * time.Millisecond, relaySeed: 50 * time.Millisecond})
	h.startEchoRTT(200 * time.Millisecond) // 直连 ≈ 200ms（远差于 50×0.8=40ms）
	defer h.stopEcho()

	// ⚠️ A2：判负的观察点是「进入 Rejected」，**不是** `demoted()`（判负不再走 Down）
	waitFor(t, "窗口到点必须判负（RTT 不达标 ⇒ Rejected）", func() bool {
		return h.path.state.Load() == pathStateRejected
	})
	if got := h.hooks(); len(got) != 1 || got[0] != "fail" {
		t.Fatalf("试用期判定应恰好判负一次，实际 %v", got)
	}
	if !h.path.alive() {
		t.Fatal("判负保留连接 ⇒ 必须 alive()（否则探针/回显协程全停 ⇒ 对端 probe-timeout）")
	}
	if got := h.path.state.Load(); got == pathStateDown {
		t.Fatal("判负**不得**置 Down（方案 A：路径没死，只是本侧不用）")
	}
	if _, ok := h.pm.routeVIP(h.path.peer); ok {
		t.Fatal("判负的路径不得进路由表")
	}
	// ⚠️ A2 反转：登记必须**保留**（TTL 淘汰靠扫它）—— 旧版断言的是 0（旧契约会 untrack）
	if n := h.pm.pathCount(); n != 1 {
		t.Fatalf("判负后登记必须保留在试用表里（TTL 靠它扫）⇒ pathCount 应为 1，实际 %d", n)
	}
	st, ok := h.pm.hasBackoff(h.path.peer)
	if !ok {
		t.Fatal("判负必须排退避（否则会立刻重试，打洞风暴）")
	}
	if st.qualityStep != 0 {
		t.Fatalf("判负保留连接**不推进**质量 streak（复用会重跑试用期，不是新失败），实际 %d", st.qualityStep)
	}
	if st.step != 0 {
		t.Fatalf("判负不得推进打洞 streak（双 streak 必须独立），实际 %d", st.step)
	}
	if d := time.Until(st.until); d < 25*time.Second || d > 35*time.Second {
		t.Fatalf("判负应排 backoffBusy=%v 短冷却（A2：不再是质量差 5min 档），实际 %v",
			backoffBusy, d.Round(time.Second))
	}
	// ⭐ A2 拍板 C（2026-09-28）：判负**必须发** `(failed, quality-poor)` 事件 ——
	//	判负后路径从面板消失（`Paths()` 过滤 `Rejected`），没有事件，用户只会看到「直连突然没了」。
	//	⚠️ 这条守卫是**从旧用例 `TestTrialFailOnPoorQualityClosesWithQualityPoor` 移回来的**：
	//	原断言随 A2 改写被移除，而它守的行为在 A2 里**真的丢了**（A2 文档 §0.3 第 8 项的评估）。
	//	ℹ️ **本项目的判负 emit 只由这一条（端到端）守**；夹具级的 `TestTrialRejectedKeepsConnection`
	//	重复它没有意义（`b3Harness` 没有事件通道）⇒ **刻意不重复覆盖**。
	if !hasEvent(h.events(), P2PStateFailed, P2PReasonQualityPoor) {
		t.Fatalf("判负必须 emit (failed, quality-poor)（否则面板无解释），实际 %+v", h.events())
	}
}

// TestL2StillDemotesDuringTrial ⭐ 设计 §9 Q2：
// 试用期内探针无回显 ⇒ L2 照常触发（trial 属于 alive()，不需要新的状态机分支）。
func TestL2StillDemotesDuringTrial(t *testing.T) {
	// missLimit=2 = 真实值：本用例考察的正是 L2（无回显 ⇒ 连续 2 次判死）
	h := newRawTrialPath(t, trialCfg{
		window: 3 * time.Second, probeEvery: 30 * time.Millisecond,
		checkEvery: 30 * time.Millisecond, relaySeed: 100 * time.Millisecond, missLimit: 2,
	})

	// 不回显（不启动 echo）⇒ 探针连续无回显
	select {
	case <-h.path.demoted():
	case <-time.After(5 * time.Second):
		t.Fatal("试用期内探针无回显必须触发 L2 降级（否则要拖到窗口末尾才发现）")
	}
	st, ok := h.pm.hasBackoff(h.path.peer)
	if !ok {
		t.Fatal("L2 降级必须排退避")
	}
	if st.lastErr != P2PReasonDirectLost && st.lastErr != P2PReasonProbeTimeout {
		t.Fatalf("L2 在试用期内的原因码应为 direct-lost，实际 %q", st.lastErr)
	}
	if got := h.hooks(); len(got) != 0 {
		t.Fatalf("L2 降级走的不是试用期判负（不该触发试用期结算钩子），实际 %v", got)
	}
}

// TestTrialNoEarlySettlementInsideWindow ⭐ harness 自检（防「假绿」）：
// 试用期**没到窗口**时不得结算。
//
// ⚠️ 必须用**质量差**的样本（不回显 ⇒ 样本恒为「不好」）来测这条：
// 「好样本够了就提前通过」是**设计行为**，用回显去测「不提前」会自相矛盾
// （本用例第一版就是这么写的，在 `-race` 下随机红）。质量差时窗口就是**唯一**的结算条件，
// 于是「窗口未到 ⇒ 不装表、不降级」才是可判定的断言。
func TestTrialNoEarlySettlementInsideWindow(t *testing.T) {
	h := newRawTrialPath(t, trialCfg{window: 2 * time.Second, probeEvery: 40 * time.Millisecond, checkEvery: 20 * time.Millisecond, relaySeed: 100 * time.Millisecond})
	// 故意**不**启动 echo：探针回不来 ⇒ 每个样本都判「不好」
	time.Sleep(300 * time.Millisecond) // 远小于 2s 窗口
	if got := h.path.state.Load(); got != pathStateTrial {
		t.Fatalf("窗口未到且质量差时不得结算，实际状态 %v", got)
	}
	if ch := h.pm.sinkFor(h.path.peer, planeTCP); ch != nil {
		t.Fatal("窗口未到不得装表")
	}
	select {
	case <-h.path.demoted():
		t.Fatal("窗口未到不得降级")
	default:
	}
	if got := h.hooks(); len(got) != 0 {
		t.Fatalf("窗口未到不得触发结算钩子，实际 %v", got)
	}
	// 但**看门狗确实在跑**（否则上面「没结算」可能只是看门狗没动）：
	//
	// ⚠️ 判据不能再用「样本数 ≥2」—— 2026-09-27 的修复**故意**让「本窗内无回显」的采样点
	//	**不落样本**。
	// ⚠️⚠️ 也**不能**再用「`trialLastSampleAt` 被推进」—— **2026-09-28（B2 修复）**起，
	//	"无新回显"时**不推进**闸门（那正是 B2 的修复点：旧实现跳过时推走一个 `probeInterval`
	//	⇒ 造成 5s 盲区 ⇒ 真机 15s 窗口只采到 1 个样本 ⇒ 判负）。
	//	⇒ 改用**专门的观测计数** `watchdogTicks`（在 `watchLoop` 的调用处自增，零语义）：
	//	  它直接回答"看门狗跑过几拍"，与采样逻辑解耦。
	if h.path.watchdogTicks.Load() <= 0 {
		t.Fatal("看门狗未跑过任何一拍（watchdogTicks == 0）—— 试用期判定没在跑")
	}
	if n := int(h.path.trialSamples.Load()); n != 0 {
		t.Fatalf("无回显时**不得**落样本（应顺延采样点）：实际样本数 %d", n)
	}
	if n := int(h.path.trialGood.Load()); n != 0 {
		t.Fatalf("无回显的样本必须全部判「不好」，实际好样本 %d", n)
	}
}

// TestTrialCancelGateNoDoubleWrite ⭐ 设计 §9 的两道取消门：
// 「试用期结算」与「路径被降级/关闭」并发到达 ⇒ 不双写。
//
// 可判定不变量（不依赖调度顺序）：
//   - 试用期判定**至多发生一次**（取消门 ② 的 CAS）；
//   - **一旦 demote 走过，试用期就绝不能再装表** —— 否则会出现「面板显示直连、
//     实际连接已关闭」的双写形态（最坏情况）。判据：钩子顺序里不得出现 pass 在 fail 之后，
//     且 demote 结束时路径必须不在路由表里。
func TestTrialCancelGateNoDoubleWrite(t *testing.T) {
	for round := 0; round < 30; round++ {
		// ⚠️ 给一个**远大于用例时长**的窗口：看门狗绝不能在结算竞态中途插一脚，
		//    否则「最终状态」会被后台的试用期判定搅进来，断言变得不可判定。
		h := newRawTrialPath(t, trialCfg{window: 10 * time.Second, probeEvery: 40 * time.Millisecond, checkEvery: 20 * time.Millisecond, relaySeed: 100 * time.Millisecond})
		h.startEcho()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); h.path.passTrialForTest() }()
		go func() { defer wg.Done(); h.path.demote(P2PReasonDirectLost) }()
		wg.Wait()
		h.stopEcho()

		// ① 试用期判定至多一次（含 ② 里加入的直接入口）
		if got := h.hooks(); len(got) > 1 {
			t.Fatalf("第 %d 轮：试用期判定发生了 %d 次（取消门失效）：%v", round, len(got), got)
		}
		// ② 等 demote **整个临界区**结束：`demotedCh` 在 defer 里关闭，且关闭前所有
		//    「装表 / close / wait / emit」都已跑完 ⇒ 它才是「降级真的做完」的同步点
		//    （测试只等 `wg.Wait()` 不够：pass 那一侧可能正在里面 close+wait 数据面协程）。
		select {
		case <-h.path.demoted():
		case <-time.After(5 * time.Second):
			t.Fatalf("第 %d 轮：demote 未在 5s 内完成", round)
		}
		// ③ 补一发结算（取消门 ② 的 win-once：第二次必须被挡），再确认状态已定型
		h.path.passTrialForTest()
		if got := h.path.state.Load(); got != pathStateDown {
			t.Fatalf("第 %d 轮：demote 完成后状态必须为 Down，实际 %v（钩子=%v）", round, got, h.hooks())
		}
		if (*h.pm.routes.Load())[h.path.peer] == h.path {
			t.Fatalf("第 %d 轮：demote 之后路径不得还在路由表里（双写：装表了一条已关的连接）", round)
		}
		if got := h.pm.trialPathCount(); got != 0 {
			t.Fatalf("第 %d 轮：demote 之后不得还挂在试用表里，实际 %d 条", round, got)
		}
		// ④ demote 的事件必须恰好一条（不得双发）
		failedN := 0
		for _, e := range h.events() {
			if e.State == P2PStateFailed {
				failedN++
			}
		}
		if failedN != 1 {
			t.Fatalf("第 %d 轮：failed 事件应恰好一条（demoteOnce 保护），实际 %d", round, failedN)
		}
	}
}

// TestTrialDemoteFirstThenEvalNeverInstalls ⭐ 取消门顺序（review 追问 1 的牙）：
// `demote` **先**发生、试用期判定**后**到（含看门狗自己的那一拍）⇒ 绝不能装表。
//
// 为什么单独测这个顺序：`demote` 里「置 trialDone → setState(Down)」与
// `evalTrial` 的「读 state → CAS」是两组独立原子操作，若把 demote 的两步顺序写反
// （或 evalTrial 去掉 state 门），就会出现「装表一条已判死的连接」——
// 面板显示直连、实际不通（最坏形态）。本用例把该顺序钉住。
func TestTrialDemoteFirstThenEvalNeverInstalls(t *testing.T) {
	h := newRawTrialPath(t, trialCfg{window: 10 * time.Second, probeEvery: 40 * time.Millisecond, checkEvery: 20 * time.Millisecond, relaySeed: 100 * time.Millisecond})
	h.startEcho()
	defer h.stopEcho()

	// ① 先降级（把它判死）
	h.path.demote(P2PReasonDirectLost)
	// ⚠️ 等 demote **整个临界区**结束（`demotedCh` 在 defer 里关闭）：
	//    `demote` 可能在别的 goroutine 里走到 `p.wait()`，只等调用返回不够。
	select {
	case <-h.path.demoted():
	case <-time.After(5 * time.Second):
		t.Fatal("demote 未在 5s 内完成")
	}
	if got := h.path.state.Load(); got != pathStateDown {
		t.Fatalf("前置条件：demote 后应为 Down，实际 %v", got)
	}

	// ② 试用期判定随后到达：真实入口（tryPassTrial 同款两道门）+ 测试入口（passTrialForTest）
	//    都必须拒绝装表。同时让看门狗多跑几拍（它每 20ms 一次，窗口 10s 内不会自己结算）。
	h.path.tryPassTrial()
	h.path.passTrialForTest()
	time.Sleep(120 * time.Millisecond)

	if (*h.pm.routes.Load())[h.path.peer] != nil {
		t.Fatal("已降级的路径被装进路由表（双写：面板会显示直连但实际不通）")
	}
	if got := h.pm.trialPathCount(); got != 0 {
		t.Fatalf("已降级的路径不得留在试用表里，实际 %d 条", got)
	}
	if got := h.hooks(); len(got) != 0 {
		t.Fatalf("判定不该结算（两道门都应拦住），实际钩子 %v", got)
	}
	// 事件语义：只有 demote 那一条 failed，不得再出现 direct
	for _, e := range h.events() {
		if e.State == P2PStateDirect {
			t.Fatalf("已降级后不得再发 direct 事件：%+v", e)
		}
	}
}

// TestDemoteOnlyRemovesItsOwnRoute ⭐ `removeRoute` 的指针守卫（review 追问 1 的结论钉住）。
//
// 判据原文：`if (*old)[dst] != p { return false }` —— 只有「表里还是它」才摘。
// 本用例证明：A 降级**摘不掉** B 的注册（所以「失败 trial 摘掉别人的成功路由」不成立）。
// 它同时是「分离试用表」这一架构决策的**边界条件**：正因为守卫成立，
// 分离试用表不是为了绕开 demote，而是为了消除「一个槽位两条路径」这个非法中间态。
func TestDemoteOnlyRemovesItsOwnRoute(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()
	dst := ip4("192.168.30.12")

	mk := func(role string) *directPath {
		p, err := newDirectPath(pm, establishedReq{
			peerVIP: "192.168.30.12", peer: dst, role: role,
			conn: newFakeConn(), myVIP: host.vip,
			closers: []func() error{func() error { return nil }},
		})
		if err != nil {
			t.Fatalf("newDirectPath: %v", err)
		}
		return p
	}
	a, b := mk(pathRoleInitiator), mk(pathRoleResponder)
	pm.installRoute(dst, a)
	pm.installRoute(dst, b) // 当前注册是 B
	// 本用例直接经 installRoute 摆状态（不走试用期），所以两者都必须是 Up（sinkFor 只认 Up）
	a.setState(pathStateUp)
	b.setState(pathStateUp)

	// A 降级（它不是当前注册）⇒ 不得摘掉 B
	a.demote(P2PReasonDirectLost)
	if cur := (*pm.routes.Load())[dst]; cur != b {
		t.Fatalf("A 降级摘掉了 B 的注册（守卫失效）：cur=%v a=%v b=%v", cur, a, b)
	}
	if ch := pm.sinkFor(dst, planeTCP); ch == nil {
		t.Fatal("B 仍在表里且应为 Up ⇒ sinkFor 必须能选中")
	}
	// B 降级 ⇒ 摘掉自己的注册
	b.demote(P2PReasonDirectLost)
	if cur := (*pm.routes.Load())[dst]; cur != nil {
		t.Fatalf("B 降级应摘掉自己的注册，实际 %v", cur)
	}
}

// TestTrialStatusSequenceTrialThenDirect ⭐ 追问 2：`direct` 事件**只由装表点发**。
//
// 两个门禁：
//  1. `handleEstablished` 只发 `trial`、**不得**发 `direct`（`punchSession.succeed()` 同理 ——
//     有路径管理器时它已不再抢先发 direct），否则前端会先记一条「已建立直连」成功日志、
//     再回退到「测试中」，正是方案 A 记账里那条「用户可能感知到细微抖动」；
//  2. `installAfterTrial` 装表成功才发 `direct`（此时接口状态确实是 Up）。
//
// 这条保证「接口(Routes/Paths) 状态」与「事件状态」在同一时刻一致：
// 收到 `trial` 时一定不在路由表里；收到 `direct` 时一定已在路由表里。
func TestTrialStatusSequenceTrialThenDirect(t *testing.T) {
	h := newRawTrialPath(t, trialCfg{window: 10 * time.Second, probeEvery: 40 * time.Millisecond, checkEvery: 20 * time.Millisecond, relaySeed: 100 * time.Millisecond})

	evs := h.events()
	if !hasEvent(evs, P2PStateTrial, P2PReasonTrialProbing) {
		t.Fatalf("通道建立后必须发 (trial, trial-probing)，实际 %+v", evs)
	}
	if hasEvent(evs, P2PStateDirect, P2PReasonOKDirect) {
		t.Fatalf("装表之前不得出现 direct 事件（接口与事件会不一致）：%+v", evs)
	}
	if _, ok := h.pm.routeVIP(h.path.peer); ok {
		t.Fatal("发 trial 的这一刻必须还没装表")
	}

	// 结算试用期（真实入口的两道门 + 装表点仲裁）⇒ 此刻才允许 direct
	h.path.passTrialForTest()
	if _, ok := h.pm.routeVIP(h.path.peer); !ok {
		t.Fatal("结算后必须已装表")
	}
	if !hasEvent(h.events(), P2PStateDirect, P2PReasonOKDirect) {
		t.Fatalf("装表成功必须发 (direct, ok-direct)，实际 %+v", h.events())
	}
}

// ---------- A2：5 条重置接线 ----------

// TestResetHookPeerPublicAddrChange ⭐ 第 4 条重置（Q3）：
// 只有信令返回的 peerPublicAddr 能看到「对端换 IP」；变化才清，首次观测/未变/空串都不清。
func TestResetHookPeerPublicAddrChange(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()
	dst := ip4("192.168.30.12")

	pm.onPunchFailed("192.168.30.12", P2PReasonPunchTimeout)
	// ① 首次观测：只建基线，不清退避（否则「第一次查询」会白清一次记录）
	pm.notePeerPublicAddr(dst, "1.2.3.4:1000")
	if _, ok := pm.hasBackoff(dst); !ok {
		t.Fatal("首次观测只是基线，不得清掉失败记录")
	}
	// ② 地址未变：不清
	pm.notePeerPublicAddr(dst, "1.2.3.4:1000")
	if _, ok := pm.hasBackoff(dst); !ok {
		t.Fatal("地址未变不得清失败记录")
	}
	// ③ 地址变化（4G ↔ WiFi）：清
	pm.notePeerPublicAddr(dst, "5.6.7.8:2000")
	if _, ok := pm.hasBackoff(dst); ok {
		t.Fatal("对端公网地址变化必须清掉该对端的失败记录（环境变了）")
	}
	// ④ 旧服务端没有 peerPublicAddr（空串）：既不建基线也不清
	pm.onPunchFailed("192.168.30.12", P2PReasonPunchTimeout)
	pm.notePeerPublicAddr(dst, "")
	if _, ok := pm.hasBackoff(dst); !ok {
		t.Fatal("拿不到对端公网地址时不得清（不能凭空调基线）")
	}
}

// TestResetHookNATReprobeSuccess ⭐ 第 2 条重置：
// NAT 重探测**成功**才清全部失败记录；失败只记日志、不清。
func TestResetHookNATReprobeSuccess(t *testing.T) {
	host := newFakeHost()
	host.addPeer("192.168.30.12") // 信号门要求对端在线，否则走不到 refreshNAT
	pm := newPathManager(host)
	pm.tiebreakDelay = time.Millisecond
	pm.start()
	defer pm.close()
	dst := ip4("192.168.30.12")

	// ① 成功路径：重探测成功 ⇒ 清掉**全部**对端的失败记录。
	//
	// ⚠️ 退避记录必须**在触发之后**才造：`handleTrigger` 会先查退避窗口，
	//    未到点的对端直接返回（连 refreshNAT 都不会走），用例会卡在等待上。
	pm.setNATStale()
	pm.handleTrigger(dst)
	waitFor(t, "NAT 重探测成功回调", func() bool { return host.natReprobeCount() == 1 })
	pm.onPunchFailed("192.168.30.12", P2PReasonPunchTimeout)
	pm.onPunchFailed("192.168.30.13", P2PReasonPunchTimeout)
	if _, ok := pm.hasBackoff(dst); !ok {
		t.Fatal("前置条件：应有失败记录")
	}
	pm.resetAllBackoff("用例直接调用：验「全部清空」语义")
	if _, ok := pm.hasBackoff(dst); ok {
		t.Fatal("resetAllBackoff 必须清空全部对端的失败记录")
	}
	if _, ok := pm.hasBackoff(ip4("192.168.30.13")); ok {
		t.Fatal("resetAllBackoff 必须清空**全部**对端（不只一个）")
	}

	// ② 失败路径不清：第二次触发时让 refreshNAT 报错 ⇒ 不得回调重置。
	//    此时该对端没有退避记录 ⇒ handleTrigger 会走到 refreshNAT。
	host.mu.Lock()
	host.refreshErr = errFakeRefresh
	host.mu.Unlock()
	pm.setNATStale()
	pm.handleTrigger(dst)
	waitFor(t, "重探测失败也走完一次尝试", func() bool { return host.queryCount() >= 1 })
	time.Sleep(150 * time.Millisecond) // 留出「万一错误地回调」的窗口
	if got := host.natReprobeCount(); got != 1 {
		t.Fatalf("重探测失败不得触发重置（那会把冷却白清一遍），实际回调 %d 次", got)
	}
}

// TestResetHookVIPChange ⭐ 第 3 条重置：本机隧道地址（VIP）变更 ⇒ 清全部失败记录；同值 no-op。
func TestResetHookVIPChange(t *testing.T) {
	cli := &Hysteria2Client{}
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()
	cli.pathMgr = pm
	cli.assignedIP = "192.168.30.11"

	pm.onPunchFailed("192.168.30.12", P2PReasonNATSymmetric)
	cli.noteAssignedIP("192.168.30.11") // 同值：no-op
	if _, ok := pm.hasBackoff(ip4("192.168.30.12")); !ok {
		t.Fatal("VIP 未变不得清失败记录")
	}
	cli.noteAssignedIP("192.168.30.99") // 变了
	if _, ok := pm.hasBackoff(ip4("192.168.30.12")); ok {
		t.Fatal("VIP 变更必须清掉全部对端的失败记录（路由键/仲裁依据都变了）")
	}
	if cli.assignedIP != "192.168.30.99" {
		t.Fatalf("VIP 应已更新，实际 %q", cli.assignedIP)
	}
}

// TestResetHookStableFiveMinutes ⭐ 第 5 条重置：直连**持续**稳定 ≥5min ⇒ 清该对端失败记录。
//
// 两种时序（对应 review 的「持续 vs 累计」）：
//   - 连续 Up 未满窗口 ⇒ 看门狗的重置钩子不得清；
//   - 降级 → 再 Up（重新计时）后仍未满窗口 ⇒ 仍不得清（累计时长不算数）；
//   - 之后再连续稳定超过窗口 ⇒ 由看门狗的钩子真的清掉。
//
// 默认门槛 5 分钟本身由 TestStableClearFailuresDefaultIsFiveMinutes 钉住。
func TestResetHookStableFiveMinutes(t *testing.T) {
	old := stableClearFailuresAfter
	stableClearFailuresAfter = 150 * time.Millisecond
	defer func() { stableClearFailuresAfter = old }()

	host := newFakeHost()
	pm := newPathManager(host)
	pm.checkInterval = 20 * time.Millisecond
	defer pm.close()

	p, _ := newTestPathOwned(t, pm, host, "192.168.30.12", pathRoleInitiator)
	pm.onPunchFailed("192.168.30.12", P2PReasonPunchTimeout)

	// ① 连续 Up 100ms（< 150ms 窗口）⇒ 不该清
	time.Sleep(100 * time.Millisecond)
	if _, ok := pm.hasBackoff(p.peer); !ok {
		t.Fatal("未满窗口就清了失败记录（说明判据不是「持续」的）")
	}
	// ② 降级 → 立刻回到 Up：stableSince 重新计时 ⇒ 再等 100ms 仍不该清
	p.setState(pathStateStandby)
	time.Sleep(2 * time.Millisecond) // 避开同毫秒（Windows 上踩过）
	p.setState(pathStateUp)
	time.Sleep(100 * time.Millisecond)
	if _, ok := pm.hasBackoff(p.peer); !ok {
		t.Fatal("累计时长不算数：重新进入 Up 后未满窗口不得清（必须是持续成功）")
	}
	// ③ 继续稳定（这次连续超过窗口 + 一个看门狗节拍）⇒ 清
	waitFor(t, "持续稳定后清掉失败记录", func() bool {
		_, ok := pm.hasBackoff(p.peer)
		return !ok
	})
}

// TestStableClearFailuresDefaultIsFiveMinutes 钉住第 5 条重置的**默认门槛**（5 分钟）。
//
// 上面的接线用例把门槛压到 150ms 才测得起 ⇒ 测不出「默认值被顺手改成 1 分钟」。
func TestStableClearFailuresDefaultIsFiveMinutes(t *testing.T) {
	if stableClearFailuresAfter != 5*time.Minute {
		t.Fatalf("「稳定 ≥5min 清失败记录」的默认门槛应为 5 分钟，实际 %v", stableClearFailuresAfter)
	}
}

// TestResetHookReconnectIsFreshManager 第 1 条重置（重连）：
// 每次 Connect 都新建 pathManager ⇒ 退避表天然从空开始。
// 这条不变量由**构造**保证，用例把它钉住（防止将来「复用管理器」的优化把重连重置悄悄丢掉）。
func TestResetHookReconnectIsFreshManager(t *testing.T) {
	cli := &Hysteria2Client{p2pServerEnabled: true, p2pLocalEnabled: true}
	cli.startPunchManager()
	pm1 := cli.pathManagerOrNil()
	if pm1 == nil {
		t.Fatal("P2P 生效时 startPunchManager 应建好路径管理器")
	}
	pm1.onPunchFailed("192.168.30.12", P2PReasonNATSymmetric)
	if _, ok := pm1.hasBackoff(ip4("192.168.30.12")); !ok {
		t.Fatal("前置条件：旧管理器应有失败记录")
	}

	// 重连：停掉再起（与 cleanupPartial → Connect 的时序一致）
	cli.stopPunchManager()
	cli.startPunchManager()
	pm2 := cli.pathManagerOrNil()
	defer cli.stopPunchManager()
	if pm2 == nil || pm2 == pm1 {
		t.Fatal("重连必须换一个新的路径管理器（否则退避/试用记录会跨连接残留）")
	}
	if _, ok := pm2.hasBackoff(ip4("192.168.30.12")); ok {
		t.Fatal("新管理器不得继承旧的失败记录（重连 = 第 1 条重置）")
	}
	if pm2.pathCount() != 0 {
		t.Fatalf("新管理器不得继承旧路径，实际 %d 条", pm2.pathCount())
	}
}

// ---------- 小工具 ----------

var errFakeRefresh = errFake("假 NAT 重探测失败")

type errFake string

func (e errFake) Error() string { return string(e) }
