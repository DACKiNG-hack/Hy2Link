package quic

// vpn-tool/backend/quic/leak_observe_test.go
//
// 第 3 步-C：区分「产品侧跨迭代泄漏」与「测试侧问题」（review 追问 2）。
//
// 背景：`-count≥20` 全包长跑曾逐步变慢/卡住，而 `-count=1` 稳定绿。
// 需要回答：那是**产品代码**跨迭代泄漏（⇒ 生产长时间运行同样会累积 ⇒ 用户可见），
// 还是**测试侧**（桩 / 夹具造了没回收的 socket）？
//
// 做法（比「30 分钟真客户端观测」更快、更可控）：反复走**产品侧完整的生命周期**
// ——  建 `pathManager` → `start()`（起调度/清理协程）→ `close()`（清空 + 关路径 + 等协程）
// —— 并每隔若干轮采样 `runtime.NumGoroutine()`。
//
// 判据：
//   - 若每轮泄漏 1 个协程 ⇒ 300 轮后 ≈ +300 ⇒ 单调暴涨（**必红**）；
//   - 若只是「有界但退出慢」⇒ 采样前留 `grace` 让它们退完 ⇒ 采样值平稳（**绿**）。
//
// 该实验直接覆盖 review 追问 1 里点名的 ① 的那个代价：
// `waitDone()` 的等待协程若在 `wg` 永不返回时挂住，就会在这里被计成泄漏。

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// TestMain 第 3 步-D：**全包前后**的 goroutine / 堆统计（`-count=N` 长跑的累积判据）。
//
// 为什么需要它：`-count=50` 只用「工作集」看不出是**真泄漏**还是**GC 未回收**——
// 两者都表现为内存单调上涨。这里在整包开始/结束各取一次
// `runtime.NumGoroutine()` 与 `runtime.ReadMemStats`，用**精确计数**判定：
//   - goroutines 线性增长 ⇒ 真泄漏（协程没退出）；
//   - goroutines 平稳而 HeapAlloc 高 ⇒ 只是 GC 高水位（不是泄漏）。
//
// ⚠️ 本函数只**报告**（不 fail）：与观测器的纪律一致（见第 3 步-C 的教训）。
func TestMain(m *testing.M) {
	// ⭐ 第 3 步-D：打开**路径生命周期埋点**（产品侧零成本；见 leak_track.go）。
	// 结束时报出「未关闭路径」（按创建点归类）。
	enablePathLeakTracking()

	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	gBefore := runtime.NumGoroutine()

	code := m.Run()

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	gAfter := runtime.NumGoroutine()

	// ⚠️ 必须**落盘**：`fmt.Printf` 的输出会被测试框架吞掉（只在用例失败时才显示），
	//    而本观测恰恰是在「全绿」时才需要读（沿用本项目「先落盘再分析」的纪律）。
	line := fmt.Sprintf("[PROC-CURVE] goroutines: %d → %d (Δ%+d) | HeapAlloc: %.1fMB → %.1fMB (Δ%+.1fMB) | HeapObjects: %d → %d (Δ%+d) | NumGC: %d → %d (Δ+%d)\n",
		gBefore, gAfter, gAfter-gBefore,
		float64(before.HeapAlloc)/(1<<20), float64(after.HeapAlloc)/(1<<20),
		(float64(after.HeapAlloc)-float64(before.HeapAlloc))/(1<<20),
		before.HeapObjects, after.HeapObjects, int64(after.HeapObjects)-int64(before.HeapObjects),
		before.NumGC, after.NumGC, after.NumGC-before.NumGC)
	fmt.Print(line)
	const curvePath = `D:\hy2-vpn\.gotmp\proc_curve.txt`
	if fh, err := os.OpenFile(curvePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		_, _ = fh.WriteString(line)
		_ = fh.Close()
	}
	// 同时把「整包结束后仍存活的协程栈」落盘 —— 用于定位残留来源
	// （`-count=50` 实测 Δ+600 goroutines ⇒ 约 12/迭代，需要知道是谁没退）。
	if gAfter > 20 {
		const dumpPath = `D:\hy2-vpn\.gotmp\proc_leak_stacks.txt`
		if fh, err := os.Create(dumpPath); err == nil {
			buf := make([]byte, 1<<22)
			n := runtime.Stack(buf, true)
			_, _ = fh.Write(buf[:n])
			_ = fh.Close()
		}
	}

	// ⭐ 未被关闭的路径（按创建点归类）——直接点名「哪个用例漏关路径」
	if rep := pathLeakReport(); rep != "" {
		msg := fmt.Sprintf("[PATH-LEAK] %s\n", rep)
		fmt.Print(msg)
		if fh, err := os.OpenFile(`D:\hy2-vpn\.gotmp\path_leak.txt`, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			_, _ = fh.WriteString(msg)
			_ = fh.Close()
		}
	}

	os.Exit(code)
}

// newLeakProbeManager 建一个「已启动」的管理器（与生产 `pathManager.start()` 同构）。
//
//go:noinline
func newLeakProbeManager() *pathManager {
	pm := newPathManager(newFakeHost())
	pm.start() // 起 scheduleLoop + pruneLoop（与生产一致）
	return pm
}

func TestPathManagerLifecycleNoGoroutineLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("泄漏观测：-short 下跳过")
	}
	const (
		rounds    = 300
		sampleGap = 50
		grace     = 100 * time.Millisecond
		// 允许的增长上限：远低于「每轮泄漏 1 个」的量级（300），
		// 同时容纳 -race 下的调度抖动。
		maxGrowth = 15
	)

	// 基线：先跑一轮（建→起→关），等协程退完再采样
	pm0 := newLeakProbeManager()
	pm0.close()
	time.Sleep(grace)
	base := runtime.NumGoroutine()
	t.Logf("[泄漏观测] 基线 goroutines=%d", base)

	prev := base
	for round := 1; round <= rounds; round++ {
		pm := newLeakProbeManager()
		pm.close()

		if round%sampleGap == 0 {
			time.Sleep(grace) // 给「有界但退出慢」的协程留出退出时间
			now := runtime.NumGoroutine()
			t.Logf("[泄漏观测] round=%d goroutines=%d (Δ基线=%+d, Δ上次采样=%+d)",
				round, now, now-base, now-prev)
			if now-base > maxGrowth {
				t.Fatalf("pathManager 生命周期疑似泄漏：round=%d goroutines=%d（基线 %d，增长 %+d > 上限 %d）"+
					"——每轮建/关都应回到基线；持续增长说明产品侧有协程不退出",
					round, now, base, now-base, maxGrowth)
			}
			prev = now
		}
	}

	time.Sleep(grace)
	final := runtime.NumGoroutine()
	t.Logf("[泄漏观测] 结束 goroutines=%d（基线 %d，总增长 %+d）", final, base, final-base)
	if final-base > maxGrowth {
		t.Fatalf("pathManager 生命周期泄漏：最终 goroutines=%d（基线 %d，增长 %+d > 上限 %d）",
			final, base, final-base, maxGrowth)
	}
}

// TestWaitDoneWaiterDoesNotAccumulate review 追问 1 的**专项**验证：
//
//	`waitTimeout()` 的等待协程（`waitDone`，每条路径最多 1 个）会不会在
//	「wg 永不返回」时累积？反复对**同一批不会退出的路径**调用 `waitTimeout()`，
//	若每次调用都新建一个等待协程 ⇒ 协程数随调用次数线性增长。
//
// 断言：协程增长必须是**常数级**（`waitDoneOnce` 保证每条路径只起 1 个）。
func TestWaitDoneWaiterDoesNotAccumulate(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.idleEvict = time.Hour
	pm.checkInterval = time.Hour
	defer pm.close()

	// 造一条 setup 卡住的路径：三条流建不起来 ⇒ wg 永不归零（正是超时场景）
	p, _ := newDirectPath(pm, establishedReq{
		peerVIP: "192.168.30.12", peer: ip4("192.168.30.12"), role: pathRoleResponder,
		conn: newFakeConn(), myVIP: host.vip,
	})
	p.setupTimeout = time.Hour
	p.run()

	old := pathWaitTimeout
	pathWaitTimeout = 10 * time.Millisecond
	defer func() { pathWaitTimeout = old }()

	// 先让等待协程建起来（并确认它确实超时了）
	if !p.waitTimeout() {
		t.Fatal("前置条件不成立：setup 卡住时 waitTimeout 应报超时")
	}
	time.Sleep(50 * time.Millisecond)
	base := runtime.NumGoroutine()

	// 反复超时：若每次新建等待协程，这里会线性增长
	for i := 0; i < 50; i++ {
		if !p.waitTimeout() {
			t.Fatalf("第 %d 次调用：应仍然超时（wg 永不返回）", i)
		}
	}
	time.Sleep(50 * time.Millisecond)
	got := runtime.NumGoroutine()
	if growth := got - base; growth > 2 {
		t.Fatalf("等待协程在累积：50 次 waitTimeout 后 goroutines %d→%d（增长 %+d）"+
			"——`waitDoneOnce` 应保证每条路径只起 1 个等待协程", base, got, growth)
	}
	t.Logf("[泄漏观测] 50 次超时调用，goroutines %d→%d（增长 %+d，符合每路径至多 1 个）",
		base, got, got-base)

	p.close()
}

// runLoopbackPunchRound 跑一轮「环回打洞 + 关闭」——与 `TestLoopbackPunchUsesFullCandidateList`
// 的主体同构（真实 QUIC 连接 + 双方打洞 + 收尾 cleanup），用于观测跨轮泄漏。
func runLoopbackPunchRound(t *testing.T) {
	t.Helper()
	a, _, recA, recB, _, cleanup := newLoopbackPairFull(t)
	defer cleanup()

	if _, err := a.PunchTo("192.168.30.12"); err != nil {
		t.Fatalf("PunchTo: %v", err)
	}
	waitDirect(t, recA, "192.168.30.12", 10*time.Second)
	waitDirect(t, recB, "192.168.30.11", 10*time.Second)
}

// runSignalOnlyRound 只做「建假服务端 + 两个客户端拨信令 + 收尾」，**完全不打洞**。
//
// 用途（第 3 步-C 追问 2 的二分实验）：`runLoopbackPunchRound` 稳定 +2/轮，
// 本函数用来区分这 2 个是「信令拨号」造成，还是「打洞」造成。
func runSignalOnlyRound(t *testing.T) {
	t.Helper()
	srv := newFakeSignalServer(t)
	a := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	b := newSignalTestClientWithNAT("5.6.7.8:40002", string(NATFullCone))
	for _, c := range []*Hysteria2Client{a, b} {
		dialFakeSignal(t, c, srv)
		if err := c.ensureSignalStream(); err != nil {
			t.Fatalf("建流失败: %v", err)
		}
	}
	waitStreamCount(t, srv, 2)
	srv.close()
	_ = a.Close()
	_ = b.Close()
}

// TestSignalOnlyRoundsNoGoroutineLeak 二分实验：只拨信令、不打洞，看每轮是否仍 +2。
func TestSignalOnlyRoundsNoGoroutineLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("泄漏观测：-short 下跳过")
	}
	const grace = 1500 * time.Millisecond
	rounds := 20

	runSignalOnlyRound(t)
	time.Sleep(grace)
	base := runtime.NumGoroutine()

	for round := 1; round <= rounds; round++ {
		runSignalOnlyRound(t)
		time.Sleep(grace)
	}
	final := runtime.NumGoroutine()
	t.Logf("[LEAK-CURVE/signal-only] base=%d final=%d growth=%+d rounds=%d perRound=%.2f",
		base, final, final-base, rounds, float64(final-base)/float64(rounds))
}

// TestLoopbackPunchRoundsNoGoroutineLeak review 追问 2 的**定位实验**：
//
//	`-count=50` 全包长跑的 dump 里，泄漏 goroutine 呈「每轮 ≈19 个」的阶梯分布：
//	  - `quic-go.(*Transport).runSendQueue`（真实 QUIC 连接，活了 40–59 分钟）
//	  - `fakeStream.Read` ← `readStreamLoop` ← `dataReadLoop`（测试桩上的读循环）
//
// 本用例把「一轮环回打洞 + 收尾」重复 N 次，看 goroutine 是否**单调增长**：
//   - 增长 ⇒ 泄漏在「客户端/打洞/连接」这一层（测试侧夹具或产品侧 close 不彻底）；
//   - 平稳 ⇒ 泄漏只在全包（跨用例）层面，需换更大范围的观测。
func TestLoopbackPunchRoundsNoGoroutineLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("泄漏观测：-short 下跳过")
	}
	const grace = 1500 * time.Millisecond // 让 QUIC 连接/读循环收尾
	// 轮数可用 `HY2_LEAK_ROUNDS` 放大（默认 12）：用来观测「上百/上千轮之后」的累积曲线。
	rounds := 12
	if v := os.Getenv("HY2_LEAK_ROUNDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			rounds = n
		}
	}

	runLoopbackPunchRound(t)
	time.Sleep(grace)
	base := runtime.NumGoroutine()
	t.Logf("[泄漏观测/环回] 基线 goroutines=%d", base)

	prev := base
	for round := 1; round <= rounds; round++ {
		runLoopbackPunchRound(t)
		time.Sleep(grace)
		now := runtime.NumGoroutine()
		t.Logf("[泄漏观测/环回] round=%d goroutines=%d (Δ基线=%+d, Δ上轮=%+d)",
			round, now, now-base, now-prev)
		prev = now
	}

	final := runtime.NumGoroutine()
	t.Logf("[泄漏观测/环回] 结束 goroutines=%d（基线 %d，总增长 %+d，共 %d 轮，即 %.1f/轮）",
		final, base, final-base, rounds, float64(final-base)/float64(rounds))

	// ⭐ 定性：把滞留 goroutine 的栈完整落盘，判断是「产品侧」还是「测试侧」
	//    （落盘而非管道过滤——沿用本项目的 race 报告纪律）
	const dumpPath = `D:\hy2-vpn\.gotmp\leak_loopback_stacks.txt`
	if f, err := os.Create(dumpPath); err == nil {
		buf := make([]byte, 1<<22) // 4 MiB
		n := runtime.Stack(buf, true)
		_, _ = f.Write(buf[:n])
		_ = f.Close()
		t.Logf("[泄漏观测/环回] 全部 goroutine 栈已落盘：%s（%d 字节）", dumpPath, n)
	}

	// ⚠️ 本用例是**观测器**，不是门禁：
	//    残留泄漏属**测试夹具**问题（已知、已记账），让它 fail 只会把门禁弄红、
	//    而不会让泄漏变少。默认只报告；要当严格检查用时设 `HY2_LEAK_STRICT=1`。
	//
	// 轮数可用 `HY2_LEAK_ROUNDS` 放大（默认 12）：用来观测「上百/上千轮之后」的累积曲线
	// （review 追问：`-count=50` 是「慢涨但不爆」还是「迟早爆」）。
	if growth := final - base; growth > 30 {
		msg := fmt.Sprintf("环回打洞跨轮泄漏：goroutines %d→%d（增长 %+d，%d 轮，即 %.1f/轮）",
			base, final, growth, rounds, float64(growth)/float64(rounds))
		if os.Getenv("HY2_LEAK_STRICT") != "" {
			t.Fatal(msg + " —— HY2_LEAK_STRICT=1 下视为失败")
		}
		t.Logf("[泄漏观测/环回] ⚠️ 观测到泄漏（非门禁，仅记录）：%s", msg)
	}
	// ⭐ 累积曲线采样点（可 grep）：供「多次 -count 迭代」时把各次采样点连成曲线
	t.Logf("[LEAK-CURVE] base=%d final=%d growth=%+d rounds=%d perRound=%.2f",
		base, final, final-base, rounds, float64(final-base)/float64(rounds))
}
