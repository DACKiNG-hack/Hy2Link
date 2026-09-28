package quic

// vpn-tool/backend/quic/trial_backoff_test.go
//
// ⭐ 1b-4 第一步（切片 1）：试用期参数/判据 + 退避分层的**纯逻辑**测试。
//
// 本文件只覆盖已经落地的部分（常量、接口预留、分类与台阶表、判据函数）。
// 状态机接入（pathStateTrial / installRoute 后移 / 双 streak 接线）在切片 2，
// 届时会补「试用期通过才装表」「双 streak 不互相推进」等集成用例。

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go"
)

// TestTrialWindowAndNeedAreConstants ⭐ A1（2026-09-27 改名 + 改写）：
// **试用期窗口与票数是常量，不再由接口决定**
//
//	旧名 `TestTrialDurationUsesInterface`：它断言「试用期长度由 `hasGoodQualityRecord()`
//	决定」。A1 起该接口**已删除**（试用期与质量表解耦）⇒ 旧前提不成立，
//	用例改写为「参数就是常量」。
//
// ⚠️ 有牙：改 `trialWindowNormal` / `trialNeedGoodNormal` 中任一常量 ⇒ 红；
//
//	把 `trialWindow()` 改回读质量表 ⇒ `TestTrialWindowIsIndependentOfQualityTable` 红。
func TestTrialWindowAndNeedAreConstants(t *testing.T) {
	// ⚠️ `trialWindow/trialNeedGood` 要读管理器上的注入口（见 path.go 的时序契约），
	//    所以这里必须挂一个真实管理器（`&directPath{}` 裸结构会 nil 解引用）。
	pm := newPathManager(newFakeHost())
	defer pm.close()
	real := &directPath{mgr: pm}

	if got := real.trialWindow(); got != trialWindowNormal {
		t.Fatalf("无注入时窗口应为常量 %v，实际 %v", trialWindowNormal, got)
	}
	if got := real.trialNeedGood(); got != trialNeedGoodNormal {
		t.Fatalf("无注入时票数应为常量 %d，实际 %d", trialNeedGoodNormal, got)
	}
	// 常量口径（与「参数口径表」一致）
	if trialWindowNormal != 15*time.Second {
		t.Fatalf("正常档窗口常量应为 15s，实际 %v", trialWindowNormal)
	}
	if trialNeedGoodNormal != 2 {
		t.Fatalf("票数常量应为 2（3 取 2），实际 %d", trialNeedGoodNormal)
	}
}

// TestTrialSampleCriteria ⭐ 试用期单样本判据：RTT 与丢包**两个都满足**才算好
//
// ⭐ 2026-09-27 阈值改 0.8 → 1.0（真机根因，见 `trialRTTRatio` 注释）：
// 判据从「直连要比中继**快 20%**」放宽为「**不比中继差**」。
func TestTrialSampleCriteria(t *testing.T) {
	relay := 100 * time.Millisecond
	cases := []struct {
		name    string
		direct  time.Duration
		success float64
		want    bool
	}{
		{"RTT 明显更低 + 无丢包", 50 * time.Millisecond, 1.0, true},
		{"恰好 1.2×（不满足「严格小于」）", 120 * time.Millisecond, 1.0, false},
		{"略快于中继（0.96×）⇒ 判好", 96 * time.Millisecond, 1.0, true},
		{"略慢于中继但 ≤1.2×（1.1×）⇒ 判好（容忍双侧不对称）", 110 * time.Millisecond, 1.0, true},
		// ⭐ 真机拓扑回归（2026-09-27）：直连 38–39ms / 中继 46–48ms ⇒ 比值 0.80–0.85。
		//	  旧阈值 0.8 下这两条**必然判负** ⇒ 直连永远过不了试用期。
		{"真机比例 38/46 ≈ 0.83 ⇒ 必须判好", 38 * time.Millisecond, 1.0, true},
		{"真机比例 39/48 ≈ 0.81 ⇒ 必须判好", 39 * time.Millisecond, 1.0, true},
		// ⭐ 第二次真机回归：B 侧 48/51 ≈ 0.94 判好、A 侧因输入不同判负 ⇒ ×1.2 留余量
		{"真机比例 48/51 ≈ 0.94 ⇒ 必须判好", 48 * time.Millisecond, 1.0, true},
		{"慢 20% 以上（1.25×）⇒ 仍须判不好", 125 * time.Millisecond, 1.0, false},
		{"RTT 达标但丢包 15%", 50 * time.Millisecond, 0.85, false},
		{"丢包 10%（恰好 90%）+ RTT 达标", 50 * time.Millisecond, 0.90, true},
		{"RTT 比中继差", 150 * time.Millisecond, 1.0, false},
		{"直连 RTT 未知", 0, 1.0, false},
		{"中继 RTT 未知", 50 * time.Millisecond, 1.0, false}, // relay 由外层置 0 的情况单独测
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := relay
			if tc.name == "中继 RTT 未知" {
				r = 0
			}
			if got := trialSampleGood(tc.direct, r, tc.success); got != tc.want {
				t.Fatalf("trialSampleGood(%v, %v, %.2f) = %v，期望 %v",
					tc.direct, r, tc.success, got, tc.want)
			}
		})
	}
}

// TestTrialRTTRatioToleratessAsymmetry ⭐ 阈值语义守卫（2026-09-27 两次真机修复）：
//
//	判据必须是「**不比中继差太多**」（`< relay × 1.2`）：
//	  - 退回 `0.8` ⇒ 「直连只快 15~17%」的拓扑永远过不了（第一次真机根因）；
//	  - 退回 `1.0` ⇒ **两侧判据输入本来就不对称**（`relayRtt` 是两个 `SmoothedRTT` 之和、
//	    两侧取自不同 ctrl 连接；`directRtt` 是各自自环回）⇒ 一侧过、一侧不过，
//	    判负侧单方面关连接（第二次真机根因）。
//
// ⚠️ 有牙：把 `trialRTTRatio` 改成 1.0 ⇒ 「1.1×」那条立刻红；改成 0.8 ⇒ 真机那几条红。
func TestTrialRTTRatioToleratessAsymmetry(t *testing.T) {
	if trialRTTRatio != 1.2 {
		t.Fatalf("trialRTTRatio 必须是 1.2（容忍双侧估算/实测不对称），实际 %v", trialRTTRatio)
	}
	// 真机现场点（两次）：都不能判负
	for _, tc := range []struct{ direct, relay time.Duration }{
		{38 * time.Millisecond, 46 * time.Millisecond}, // 第一次真机
		{39 * time.Millisecond, 48 * time.Millisecond},
		{48 * time.Millisecond, 51 * time.Millisecond}, // 第二次真机（B 侧）
	} {
		if !trialSampleGood(tc.direct, tc.relay, 1.0) {
			t.Fatalf("真机实测 直连 %v / 中继 %v 必须判「好」", tc.direct, tc.relay)
		}
	}
	// 放宽不等于取消判据：慢 20% 以上仍然要判负
	if trialSampleGood(130*time.Millisecond, 100*time.Millisecond, 1.0) {
		t.Fatal("直连比中继慢 30% 时仍须判「不好」")
	}
}

// TestTrialWindowFloorFitsNeededSamples ⭐ 窗口下界（2026-09-27 真机 Bug 2）：
//
//	窗口必须容得下 `trialNeedGood` 个样本：样本间隔 = `probeInterval`
//	⇒ `窗口 >= need × probeInterval × 1.5`（留回显与相位余量）。
//
// 真机故障：质量表命中 ⇒ `trialWindowShort = 5s`，而 `probeInterval = 5s`、`need = 2`
// ⇒ 窗口内最多 1 个采样点、**实测 0 个** ⇒ `samples < need` ⇒ **必然判负**
// （日志：`**样本不足** 好样本 0/0`）⇒ 「质量好记录」反而让这条路永远连不上。
//
// ⚠️ 有牙：删掉 `trialWindow()` 里的下界校正 ⇒ 生产参数下（probe=5s/need=2）
//
//	缩短档会返回 5s ⇒ 本用例红。
func TestTrialWindowFloorFitsNeededSamples(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.probeInterval = defaultProbeInterval // 生产 5s
	pm.setQualityTable(newPeerTable())
	p := &directPath{mgr: pm}

	// 生产参数下：无论是否命中质量表，窗口都必须 ≥ need × probe × 1.5 = 15s
	for _, good := range []bool{false, true} {
		pm.trialWindowOverride = 0
		if good {
			// 造一条「质量好」记录 ⇒ hasGoodQualityRecord() 为真 ⇒ 名义走缩短档
			p.peer = ip4("192.168.30.12")
			pm.qualityTable().Record(p.peer, peerOutcome{
				Kind: peerGood, Reason: P2PReasonOKDirect,
			})
		} else {
			p.peer = ip4("192.168.30.13")
		}
		win, need := p.trialWindow(), p.trialNeedGood()
		stairs := time.Duration(need) * pm.probeInterval * 3 / 2
		if win < stairs {
			t.Fatalf("窗口 %v 装不下 %d 个样本（probeInterval=%v，至少需要 %v）—— "+
				"真机上这会表现为「样本不足 ⇒ 必然判负」", win, need, pm.probeInterval, stairs)
		}
	}
}

// TestTrialRTTRatioIsNotWorseThanRelay 别名守卫（保留旧名，语义已升级为「容忍不对称」）：
// 与 `TestTrialRTTRatioToleratessAsymmetry` 同源，两者都钉住真机现场点。
func TestTrialRTTRatioIsNotWorseThanRelay(t *testing.T) {
	if trialRTTRatio != 1.2 {
		t.Fatalf("trialRTTRatio 必须是 1.2（不比中继差太多就用直连），实际 %v"+
			" —— 0.8 会让「直连只快 15~17%%」的拓扑永远过不了试用期（真机实测根因）",
			trialRTTRatio)
	}
	// 直接钉住真机那几个点（比只断言常量更靠近现场）
	if !trialSampleGood(38*time.Millisecond, 46*time.Millisecond, 1.0) {
		t.Fatal("真机实测 直连 38ms / 中继 46ms 必须判「好」（这是发版前的现场数据）")
	}
	if !trialSampleGood(39*time.Millisecond, 48*time.Millisecond, 1.0) {
		t.Fatal("真机实测 直连 39ms / 中继 48ms 必须判「好」")
	}
	if trialSampleGood(130*time.Millisecond, 100*time.Millisecond, 1.0) {
		t.Fatal("直连明显慢于中继时仍须判「不好」（放宽不等于不要判据）")
	}
}

// TestTrialParamTableClarified ⭐ 参数口径（review 追问，2026-09-27）：把上表**逐项钉住**，
// 避免「3 取 2」与「need 降到 2」这类口径再次自相矛盾。
//
//	表在 `path.go` 的「试用期参数口径表」；本用例是它的**可执行版本**。
//
// ⚠️ 有牙：改动其中任一参数（例如又把 `trialWindowShort` 用回去、或把 need 改成 3）⇒ 红。
func TestTrialParamTableClarified(t *testing.T) {
	// ① 常量口径（生产值）
	if defaultProbeInterval != 5*time.Second {
		t.Fatalf("probeInterval 生产值应为 5s（样本间隔与它同源），实际 %v", defaultProbeInterval)
	}
	if defaultCheckInterval != time.Second {
		t.Fatalf("checkInterval 生产值应为 1s，实际 %v", defaultCheckInterval)
	}
	if trialWindowNormal != 15*time.Second {
		t.Fatalf("正常档窗口应为 15s，实际 %v", trialWindowNormal)
	}
	// ⚠️ `trialWindowShort` 已**删除**（生产不可达的死代码，review 拍板）⇒ 这里断言
	//	「两档窗口同值」把删除**钉死**：若有人加回一个 5s 档却没同时缩 probeInterval，
	//	本用例立刻红（那正是真机 Bug 2 的形态）。
	//
	// ⚠️ A1 起 `trialWindowFor` 也**已删除**（试用期与质量表解耦）⇒ 改为直接断言
	//	「窗口由常量决定」+ 「need 两档常量同值」。
	if trialWindowNormal != 15*time.Second {
		t.Fatalf("trialWindowNormal 必须是 15s，实际 %v", trialWindowNormal)
	}
	if trialNeedGoodNormal != 2 || trialNeedGoodShort != 2 {
		t.Fatalf("两档 need 都应为 2（≠「2 取 2 更严」：正常档样本上限是 3、命中档被下界抬到同一窗口），"+
			"实际 normal=%d short=%d", trialNeedGoodNormal, trialNeedGoodShort)
	}

	// ② ⭐ 生产参数下：**窗口不由质量表决定**（A1 解耦）⇒ 与"表里有没有好记录"无关
	host := newFakeHost()
	pm := newPathManager(host)
	pm.setQualityTable(newPeerTable()) // 生产 probeInterval（5s）保持默认
	good := ip4("192.168.30.12")
	plain := ip4("192.168.30.13")

	pGood := &directPath{mgr: pm, peer: good}
	pm.qualityTable().Record(good, peerOutcome{Kind: peerGood, Reason: P2PReasonOKDirect})
	pPlain := &directPath{mgr: pm, peer: plain}

	wGood, wPlain := pGood.trialWindow(), pPlain.trialWindow()
	if wGood != trialWindowNormal {
		t.Fatalf("⚠️ 记账项：生产参数下窗口应恒为 %v，实际 %v"+
			" —— 若不再是 15s，说明「缩短档」被重新启用，必须同步确认 probeInterval 也缩短了",
			trialWindowNormal, wGood)
	}
	if wGood != wPlain {
		t.Fatalf("窗口必须与质量表无关（A1 解耦），实际 good=%v plain=%v", wGood, wPlain)
	}
	// ③ 且窗口必须装得下 need 个样本
	if floor := pGood.trialSampleFloor(); wGood < floor {
		t.Fatalf("窗口 %v 装不下 %d 个样本（下界 %v）", wGood, pGood.trialNeedGood(), floor)
	}
}

// TestTrialQualityHitPassesWithinWindow ⭐ Bug 2 的**确定性**验收（A1 后：与质量表无关）
//
//	用**生产参数**（probe=5s、check=1s、need=2）直接断言：
//	  ① 窗口 = 15s（= 采样下界与正常档的较大者）⇒ 装得下 2 个样本；
//	  ② 按生产探针节奏喂 2 次回显 ⇒ 试用期**通过**。
//
//	修复前的故障：窗口 5s + probe=5s ⇒ 最多 1 个采样点、实测 0 个 ⇒ 必然判负。
//	⚠️ A1 起「质量表命中」这条前置**已删除**（试用期与质量表解耦）——本用例保留的是
//	  「生产参数下窗口必须装得下样本且能通过」这条核心不变量。
//
// ⚠️ 时间用手工驱动（`trialSampleStep` + 手工喂时间轴），避免 ticker 相位带来的 flaky；
//
//	真实 ticker 路径另有 `TestTrialSamplingUnderProductionTiming` 覆盖。
//
// ⚠️ 有牙：删掉 `trialWindow()` 的下界校正 ⇒ ① 立刻红（窗口回到 5s）。
func TestTrialQualityHitPassesWithinWindow(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	pm.setQualityTable(newPeerTable()) // probeInterval 保持生产 5s
	peer := ip4("192.168.30.12")

	p := &directPath{mgr: pm, peer: peer}

	// ① 窗口 = 15s ⇒ 装得下 need 个样本
	if got, floor := p.trialWindow(), p.trialSampleFloor(); got < floor {
		t.Fatalf("窗口 %v 装不下 %d 个样本（下界 %v）—— 这就是真机「样本不足必判负」的形态",
			got, p.trialNeedGood(), floor)
	}
	if got := p.trialWindow(); got != trialWindowNormal {
		t.Fatalf("生产参数下窗口应为 %v，实际 %v", trialWindowNormal, got)
	}

	// ② 手工驱动 2 个「好样本」⇒ 必须提前通过（`trialGoodEnough`）
	now := time.Now()
	p.rtt.Store(int64(48 * time.Millisecond))           // 直连 RTT（第二次真机实测）
	p.trialRelayRtt.Store(int64(51 * time.Millisecond)) // 中继基准
	p.trialStartedAt.Store(now.UnixMilli())
	p.trialLastEcho.Store(0)

	for i := 1; i <= trialNeedGoodShort; i++ {
		// 每次：先到一次回显，再把采样点推到 probeInterval 之后
		p.lastEcho.Store(now.Add(time.Duration(i) * defaultProbeInterval).UnixMilli())
		p.trialLastSampleAt.Store(now.Add(time.Duration(i-1) * defaultProbeInterval).UnixMilli())
		p.trialSampleStep(now.Add(time.Duration(i) * defaultProbeInterval))
	}
	if !p.trialGoodEnough() {
		t.Fatalf("按生产节奏喂 %d 个「好样本」后应满足通过条件，实际好样本 %d/%d",
			trialNeedGoodShort, p.trialGood.Load(), p.trialSamples.Load())
	}
	if got := p.trialGood.Load(); got < trialNeedGoodShort {
		t.Fatalf("好样本应 ≥%d，实际 %d", trialNeedGoodShort, got)
	}
}

// TestTrialVerdictThreeOfTwo ⭐ 3 取 2：容忍一次偶发抖动
func TestTrialVerdictThreeOfTwo(t *testing.T) {
	if !trialVerdict(2, 3, trialNeedGoodNormal) {
		t.Fatal("3 个样本里 2 个好 ⇒ 必须通过")
	}
	if trialVerdict(1, 3, trialNeedGoodNormal) {
		t.Fatal("3 个样本只有 1 个好 ⇒ 不得通过")
	}
	if !trialVerdict(2, 2, trialNeedGoodShort) {
		t.Fatal("缩短试用期 2 个样本都得好 ⇒ 通过")
	}
	if trialVerdict(1, 2, trialNeedGoodShort) {
		t.Fatal("缩短试用期只 1 个好 ⇒ 不得通过")
	}
}

// TestPathStateConstBlockHasNoStateAfterSentinel ⭐⭐ A1 复盘后的**真正穷举守卫**（2026-09-27）：
//
//	用 `go/parser` **直接解析 `path.go`**，断言状态常量块里**没有** `= iota` 常量被声明在
//	`pathStateSentinel` **之后**。
//
// 为什么必须这样（而不是"再维护一份手工清单"）：
//
//	`allPathStates()` 只遍历 `[1, pathStateSentinel)`。若把新状态加在哨兵**之后**：
//	  · `TestPathStateNameCoversAllStates` 遍历不到它 ⇒ 绿；
//	  · 若还有第二份手工清单（曾用的 `maxPathState()`）而忘了加它 ⇒ 也绿
//	⇒ **两个守卫双双静默失效**（实测确认过一次）。源码级解析**不依赖任何清单**。
//
// ⚠️ 有牙：在 `pathStateSentinel` **之后**加一个状态常量（两种写法都要红）：
//
//	① `pathStateX`（单名一行、省略表达式 ⇒ Go 常量块继承 `iota`）；
//	② `pathStateX = iota`（显式写法）。
//
//	❗❗ **本守卫的第一版是假守卫**（2026-09-27 有牙验证抓到，第 4 次同型问题）：
//	  第一版只认「显式 `= iota`」⇒ 写法 ①（**真实提交里最常见的那种**）**不红**。
//	  根因：Go 常量块里省略表达式的 spec 在 AST 上 `len(Values) == 0`，
//	  但语义上**照样自动编值**。⇒ 修法：按「上一条是否自动编值」继承判断。
//
//	这也是 A2 加 `Rejected`/`Reusing`/`RejectedSettling` 时的**位置纪律**检查。
func TestPathStateConstBlockHasNoStateAfterSentinel(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "path.go", nil, 0)
	if err != nil {
		t.Fatalf("解析 path.go 失败: %v", err)
	}
	// 规则 A（块内位置）：哨兵之后不得再声明任何常量
	if found := pathStateConstsAfterSentinel(f); len(found) > 0 {
		t.Fatalf("在 pathStateSentinel **之后**（同一个 const 块内）声明了 %v —— "+
			"`allPathStates()` 只遍历 [1, sentinel)，这些常量**逃出穷举范围**；"+
			"若被当成状态用，忘加 `pathStateName` 的 case 也**不会红**。"+
			"请把所有状态常量声明在 pathStateSentinel **之前**。", found)
	}
	// 规则 B（跨块）：不得在别的 const 块里声明 pathState* 常量
	if found := pathStateConstsInOtherBlocks(f); len(found) > 0 {
		t.Fatalf("在**另一个** const 块里声明了 %v —— Go 的 `iota` **每个 const 块独立**："+
			"新块从 0 重新计数 ⇒ 值可能落到 [1, sentinel) 之外、或与现有状态**撞值**，"+
			"两条都会逃过 `allPathStates()` 的穷举（且 panel 上显示 unknown/错名）。"+
			"状态常量必须全部声明在哨兵块内、且哨兵**之前**。", found)
	}
}

// pathStateConstsAfterSentinel 规则 A 的判定核心：**同一个 const 块内**、在
// `pathStateSentinel` 之后声明的常量名。
//
// ⭐⭐ 判定规则已刻意**不分析 iota**（2026-09-27 第二次有牙验证后简化）：
//
//	只要**位置**在哨兵之后就算违规，与它是下面 4 种写法里的哪一种无关：
//	  ① `= iota`（显式）      ② 省略表达式、继承 iota
//	  ③ `= 固定值`（显式）    ④ 省略表达式、继承固定值
//
//	为什么不做「按上一条是否自动编值继承判断」（**第一版的做法，被证明有洞**）：
//	  · 省略表达式的语义是「重复**上一条非空表达式列表**」⇒ 判断必须跨 spec 传递（不是单层），
//	    写对很绕；更致命的是 ③④ 两类**固定值**写法会被判成「非自动编值 ⇒ 放过」——
//	    而 `pathStateSentinel = 8` 之后写 `pathStateRejected`（继承 8）**照样逃出穷举范围**，
//	    这正是 review 追问 2 点出的漏判。
//	  ⇒ 位置判据**不区分**这四种写法 ⇒ 不可能漏判、也没有语义分支要维护。
//
// 为什么抽成函数：守卫的判定逻辑本身也是代码，也必须**被自证**——
// 否则又是一条「假守卫」（本项目已 4 次踩同型坑）⇒ 见 `TestPathStateConstAfterSentinelDetector`。
func pathStateConstsAfterSentinel(f *ast.File) []string {
	var found []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		// 只审「含哨兵的那个 const 块」
		hasSentinel := false
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if name.Name == "pathStateSentinel" {
					hasSentinel = true
				}
			}
		}
		if !hasSentinel {
			continue
		}

		afterSentinel := false
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			// ⚠️ 位置判据：**不看** vs.Values ⇒ 4 种写法一视同仁（见函数头注释）
			for _, name := range vs.Names {
				if name.Name == "pathStateSentinel" {
					afterSentinel = true
					continue
				}
				if afterSentinel {
					found = append(found, name.Name)
				}
			}
		}
	}
	return found
}

// pathStateConstsInOtherBlocks 规则 B 的判定核心：**别的** const 块里有没有 `pathState` 前缀的常量。
//
// ⚠️ 为什么规则 B 必须靠**命名前缀**（而规则 A 不需要）：
//
//	Go 的 `iota` 每个 const 块**独立** ⇒「新块里第一条 `= iota`」的值是 **0**、不是 5
//	⇒ 单看**值**判不出来；而「值落在 [1, sentinel) 就报警」的值域判据又会误伤
//	同文件里 `probeMissLimit = 2` 这类普通 int 常量。
//	⇒ 用前缀圈出「疑似状态常量」：本文件的状态常量**全部**带 `pathState` 前缀，
//	  所以「别的块里出现 `pathState*`」必定是放错地方了（对现有文件零误报，已实测）。
func pathStateConstsInOtherBlocks(f *ast.File) []string {
	const prefix = "pathState"
	var found []string
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		hasSentinel := false
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if name.Name == "pathStateSentinel" {
					hasSentinel = true
				}
			}
		}
		if hasSentinel {
			continue // 哨兵块由规则 A 负责
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if strings.HasPrefix(name.Name, prefix) {
					found = append(found, name.Name)
				}
			}
		}
	}
	return found
}

// TestPathStateConstAfterSentinelDetector ⭐ 守卫的**自证**（2026-09-27）：
// 用**合成源码**给判定核心喂违规/合法样本，断言各自的结论。
//
//	为什么必须存在：`path.go` 本身是**合法样本**（恒为绿），若判定核心写坏了，
//	主守卫仍然全绿 ⇒ 「绿」不能证明守卫有牙。这里用故意写坏的**违规样本**证明它会红。
//
// ⚠️ 前提（已在 `TestQuicGoApplicationErrorShape` 同类用例中确认同型风险）：
//
//	这里解析的是**内联字符串**，改动 `path.go` 的写法不影响本用例；
//	但若有人把判定改回「只看显式 `= iota`」或「只按上一行是否含 iota 单层判断」
//	⇒ A-违规的写法③④样本立刻红（这两条正是 review 追问点名的漏判形态）。
type detectorSample struct {
	name      string
	src       string
	wantAfter []string // 规则 A（哨兵之后，块内）
	wantOther []string // 规则 B（别的 const 块里）
}

func TestPathStateConstAfterSentinelDetector(t *testing.T) {
	samples := []detectorSample{
		// ---- 规则 A：哨兵之后（4 种写法全覆盖，review 追问 2 点名的 ③④ 必须有样本）----
		{
			name: "A-违规 · 写法② 省略表达式（继承 iota）",
			src: `package p

const (
	pathStateRelay = iota
	pathStateSentinel
	pathStateRejected
)
`,
			wantAfter: []string{"pathStateRejected"},
		},
		{
			name: "A-违规 · 写法① 显式 = iota",
			src: `package p

const (
	pathStateRelay = iota
	pathStateSentinel
	pathStateRejected = iota
)
`,
			wantAfter: []string{"pathStateRejected"},
		},
		{
			name: "A-违规 · 写法③ 显式固定值（第一版漏判的形态）",
			src: `package p

const (
	pathStateRelay = iota
	pathStateSentinel
	pathStateRejected = 7
)
`,
			wantAfter: []string{"pathStateRejected"},
		},
		{
			name: "A-违规 · 写法④ 省略表达式、继承**固定值**（哨兵本身是显式固定值）",
			src: `package p

const (
	pathStateRelay = iota
	pathStateTrial
	pathStateSentinel = 8
	pathStateRejected
)
`,
			wantAfter: []string{"pathStateRejected"},
		},
		{
			name: "A-违规 · 哨兵之后多个（4 种写法混合，全部要抓到）",
			src: `package p

const (
	pathStateRelay = iota
	pathStateSentinel
	pathStateRejected
	pathStateReusing = iota
	pathStateRejectedSettling = 9
)
`,
			wantAfter: []string{"pathStateRejected", "pathStateReusing", "pathStateRejectedSettling"},
		},
		{
			name: "A-合法 · 全部在哨兵之前（含混合写法）",
			src: `package p

const (
	pathStateRelay = iota
	pathStateStandby
	pathStateTrial = iota
	pathStateRejected
	pathStateSentinel
)
`,
			wantAfter: nil,
		},

		// ---- 规则 B：跨 const 块（iota 每块独立）----
		{
			name: "B-违规 · 新 const 块里另起 iota 声明状态",
			src: `package p

const (
	pathStateRelay = iota
	pathStateSentinel
)

const (
	pathStateRejected = iota
)
`,
			wantOther: []string{"pathStateRejected"},
		},
		{
			name: "B-违规 · 新块里显式赋值",
			src: `package p

const (
	pathStateRelay = iota
	pathStateSentinel
)

const (
	pathStateRejected = 99
)
`,
			wantOther: []string{"pathStateRejected"},
		},
		{
			name: "B-合法 · 别的块是无关常量（零误报）",
			src: `package p

const (
	pathStateRelay = iota
	pathStateSentinel
)

const (
	probeMissLimit = 2
	trialWindowNormal = 15
)

const (
	otherA = iota
	otherB
)
`,
			wantAfter: nil,
			wantOther: nil,
		},
	}

	for _, s := range samples {
		t.Run(s.name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "sample.go", s.src, 0)
			if err != nil {
				t.Fatalf("解析样本失败: %v\n%s", err, s.src)
			}
			gotAfter := pathStateConstsAfterSentinel(f)
			if !sameStrings(gotAfter, s.wantAfter) {
				t.Fatalf("规则 A 命中项不符：want %v，got %v", s.wantAfter, gotAfter)
			}
			gotOther := pathStateConstsInOtherBlocks(f)
			if !sameStrings(gotOther, s.wantOther) {
				t.Fatalf("规则 B 命中项不符：want %v，got %v", s.wantOther, gotOther)
			}
		})
	}
}

// sameStrings 顺序敏感的切片相等（nil 与空切片等价）
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPathStateNameCoversAllStates ⭐⭐ A1 核心守卫（2026-09-27）：
// **每个合法路径状态都必须有名字**，否则「新增状态忘了加 case」会静默变成 `"unknown"`。
//
//	机制：`allPathStates()` 由 `pathStateSentinel` **区间推导**（不是手工清单 ⇒ 无「双清单漂移」）
//	⇒ 在这里遍历它，任何没有 `case` 的状态都会拿到 `"unknown"` ⇒ **红**。
//
// ⚠️ 有牙（mutation）：删掉 `pathStateName` 里任一 `case`（例如 `pathStateStandby`）
//
//	⇒ 遍历到它 ⇒ 得到 `"unknown"` ⇒ 红。
//	⚠️ 这就是「新增状态时红在哪里」的答案：**加常量 + 忘加 case ⇒ 本用例红**。
func TestPathStateNameCoversAllStates(t *testing.T) {
	states := allPathStates()
	if len(states) == 0 {
		t.Fatal("allPathStates() 不得为空（否则本守卫形同虚设）")
	}
	for _, s := range states {
		if got := pathStateName(s); got == "unknown" {
			t.Fatalf("路径状态 %d 没有名字（pathStateName 漏了 case）—— "+
				"新增状态时必须同时在 pathStateName 加 case；否则面板/日志会静默显示 unknown", s)
		}
	}
}

// TestPathStateSentinelIsLast ⭐ A1 守卫的**另一半**：哨兵必须是最后一个状态。
//
//	`allPathStates()` 只遍历 `[1, pathStateSentinel)` ⇒ 若有人把新状态加在 sentinel **之后**，
//	那个状态**不会被遍历到**（守卫失效）⇒ 本用例把它挡住。
//
// ⚠️ ❗ 本用例**抓不到**「新常量加在哨兵之后」——2026-09-27 有牙验证实测确认：
//
//	在哨兵之后加 `pathStateTeethProbe`（继承 iota）后，本用例**仍然绿**。
//	原因：①③ 的判据全部只看 `allPathStates()` 的**区间形状**，而哨兵值没变 ⇒ 形状不变。
//	⇒ 该情形由**源码级解析**守卫 `TestPathStateConstBlockHasNoStateAfterSentinel` 负责。
//	（本用例保留的价值：哨兵本身不该有名字、状态名不得重复。）
func TestPathStateSentinelIsLast(t *testing.T) {
	// ① 哨兵必须是**最大**的合法状态值 + 1
	states := allPathStates()
	if len(states) == 0 || states[len(states)-1] != pathStateSentinel-1 {
		t.Fatalf("allPathStates() 的末项应为 pathStateSentinel-1=%d，实际 %v",
			pathStateSentinel-1, states)
	}
	// ② 哨兵本身**不是**状态（不应有名字；它只是计数哨兵）
	if got := pathStateName(pathStateSentinel); got != "unknown" {
		t.Fatalf("pathStateSentinel 本身不是状态，不应有名字，实际 %q", got)
	}
	// ③ 每个状态必须互不相同（防止复制粘贴出重复常量）
	seen := map[string]int32{}
	for _, s := range states {
		name := pathStateName(s)
		if prev, dup := seen[name]; dup {
			t.Fatalf("状态 %d 与 %d 名字相同（%q）—— 状态常量必须两两不同", prev, s, name)
		}
		seen[name] = s
	}
}

// TestAllPathStatesSliceIsComplete ⭐ A1：`allPathStates()` 必须覆盖**全部**已知状态。
//
//	判据：长度 == `pathStateSentinel - 1`（区间推导的自然结果）且从 1 开始连续。
//	⚠️ 这条与 `TestPathStateSentinelIsLast` 互补：前者管「区间对不对」，这条管「区间全不全」。
//
// ⚠️ 有牙：把 `allPathStates()` 改成手工清单（漏掉一个）⇒ 红。
func TestAllPathStatesSliceIsComplete(t *testing.T) {
	states := allPathStates()
	if want := int(pathStateSentinel) - 1; len(states) != want {
		t.Fatalf("allPathStates() 应有 %d 项（1..pathStateSentinel-1），实际 %d 项：%v",
			want, len(states), states)
	}
	for i, s := range states {
		if s != int32(i+1) {
			t.Fatalf("allPathStates() 必须从 1 连续递增：第 %d 项为 %d", i, s)
		}
	}
	// ⚠️ 「状态被加在哨兵之后」这条**不在这里**判 —— 见
	//	`TestPathStateConstBlockHasNoStateAfterSentinel`（源码级解析，不依赖手工清单）。
	//	⚠️ 这里曾经用 `maxPathState()`（一份手工清单）来判，实测**有洞**：
	//	  「加在哨兵之后 + 忘加进那份清单」⇒ 两个守卫双双静默失效 ⇒ 该清单已删除。
}

// TestBackoffClassTiers ⭐ 退避四档：分类、台阶内容、忙不推进、双 streak 独立
//
// ⚠️ 切片 2 起**唯一权威**是既有的 `classifyPathFail` + `backoffDelayFor`（切片 1 那套重复类型已删除）。
func TestBackoffClassTiers(t *testing.T) {
	// ① 原因码 → 类别
	classCases := map[string]pathFailClass{
		P2PReasonNATSymmetric:        failPermanent,
		P2PReasonFingerprintMismatch: failPermanent,
		P2PReasonServerP2PDisabled:   failPermanent,
		P2PReasonPunchTimeout:        failRetryable,
		P2PReasonPeerNoPunchAddr:     failRetryable,
		P2PReasonNATUnknown:          failRetryable, // ⭐ 已批准：临时性（可重探测）
		P2PReasonQualityPoor:         failQuality,
		P2PReasonProbeTimeout:        failQuality,
		P2PReasonDirectLost:          failQuality,
		P2PReasonPeerBusy:            failBusy,
		P2PReasonRateLimited:         failBusy,
		// ⭐ 2026-09-27（Bug 3）：对端主动关闭 ⇒ 独立类别（不排退避）
		P2PReasonPeerClosed: failPeerClosed,
	}
	for reason, want := range classCases {
		if got := classifyPathFail(reason); got != want {
			t.Fatalf("classifyPathFail(%q) = %v，期望 %v", reason, got, want)
		}
	}

	// ② 台阶内容（逐项断言，防止改错顺序/数值）
	wantBig := []time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour}
	for i, want := range wantBig {
		if got := ladderStep(backoffLadderDeterministic, i); got != want {
			t.Fatalf("确定性台阶[%d] = %v，期望 %v", i, got, want)
		}
		if got := ladderStep(backoffLadderQuality, i); got != want {
			t.Fatalf("质量差台阶[%d] = %v，期望 %v", i, got, want)
		}
	}
	wantTransient := []time.Duration{60 * time.Second, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute}
	for i, want := range wantTransient {
		if got := ladderStep(backoffLadder, i); got != want {
			t.Fatalf("临时性台阶[%d] = %v，期望 %v（应与原 backoffLadder 一致）", i, got, want)
		}
	}
	// ③ 封顶
	if got := ladderStep(backoffLadderDeterministic, 99); got != time.Hour {
		t.Fatalf("超长 streak 应封顶 1h，实际 %v", got)
	}
	if got := ladderStep(backoffLadder, 99); got != 10*time.Minute {
		t.Fatalf("临时性超长 streak 应封顶 10min，实际 %v", got)
	}

	// ④ 忙：固定 30s 且**不推进**
	if d, adv := backoffDelayFor(failBusy, backoffState{step: 5, qualityStep: 5}); d != backoffBusy || adv {
		t.Fatalf("忙应固定 %v 且不推进，实际 d=%v advance=%v", backoffBusy, d, adv)
	}
	// ⑤ 双 streak 独立：同一个 backoffState 里，两类各自读自己的 streak
	st := backoffState{step: 2, qualityStep: 0}
	if d, adv := backoffDelayFor(failPermanent, st); d != wantBig[2] || !adv {
		t.Fatalf("确定性第 2 档应 %v 且推进，实际 %v/%v", wantBig[2], d, adv)
	}
	if d, adv := backoffDelayFor(failQuality, st); d != wantBig[0] || !adv {
		t.Fatalf("质量差应读 qualityStep(0) ⇒ %v，实际 %v（说明两套 streak 读串了）", wantBig[0], d)
	}
	// ⑥ ⭐ 2026-09-27（Bug 3）：对端主动关闭 ⇒ **不排退避、不推进任何 streak**
	//	（退避档虚涨的实测形态：`30m0s 后重试：probe-timeout` 紧跟 `5m0s 后重试：direct-lost`）
	if d, adv := backoffDelayFor(failPeerClosed, backoffState{step: 3, qualityStep: 3}); d != 0 || adv {
		t.Fatalf("对端主动关闭不得排退避（d 应为 0、不得推进），实际 d=%v advance=%v"+
			" —— 非本机链路问题，给它记退避会让「对端重启后想重连」被自己挡在门外", d, adv)
	}
}

// TestQuicGoApplicationErrorShape ⭐ 升级守卫（Bug 3）：把「本实现依赖的 quic-go 错误形状」钉死。
//
//	`isPeerInitiatedClose` 的一级判据是 `errors.As` 到 `quic.ApplicationError` 并读 `Remote`
//	—— 那是 fork 的实现细节（`quic-go/errors.go` 的类型别名）。
//
// ⭐ **拦截时机要说清（review 追问，避免误导后来者）**：
//
//	本用例混了两种检查，**红的时机不同**：
//	  ① **编译期红**：`&quic.ApplicationError{ErrorCode:…, ErrorMessage:…, Remote:…}` 是**字面量构造**
//	     ⇒ 字段名/类型/包路径一改，**编译就失败**（不必等到跑测试）。
//	     ⚠️ 前提：该 struct **不能有未导出字段**（否则外部字面量构造会编译失败 = 用例恒红）。
//	     已核实：`qerr.ApplicationError` 的字段全是导出的（`ErrorCode` / `ErrorMessage` / `Remote`），
//	     且本用例当前**通过** ⇒ 前提成立。将来若加了未导出字段，本用例会**变成恒失败**，
//	     那时应改用 `new(quic.ApplicationError)` + 赋值而非字面量。
//	  ② **运行期红**：`errors.As` 能否取出、`Remote` 语义、`(remote)`/`(local)` 文案契约
//	     ⇒ 只有**跑测试**才红（CI 的 test 阶段）。
//
//	⇒ 类型改名/删字段 → 编译期拦；语义/文案变化 → 测试期拦。
//
// ⚠️ 有牙：把 `quic-go/errors.go` 的 `ApplicationError = qerr.ApplicationError` 删掉
//
//	（或改类型名/去掉 Remote 字段）⇒ 本用例**编译失败**。
func TestQuicGoApplicationErrorShape(t *testing.T) {
	// ① 类型必须存在且可由 errors.As 取出（编译期即验证字段与名字）
	remote := &quic.ApplicationError{ErrorCode: 0, ErrorMessage: "path closed", Remote: true}
	var target *quic.ApplicationError
	if !errors.As(error(remote), &target) {
		t.Fatal("quic.ApplicationError 必须能被 errors.As 取出（isPeerInitiatedClose 的一级判据）")
	}
	if !target.Remote {
		t.Fatal("quic.ApplicationError.Remote 必须可读且为 true（本实现依赖该字段）")
	}
	// ② 文案契约：Remote=true ⇒ 含 "(remote)"；false ⇒ 含 "(local)"
	if s := remote.Error(); !strings.Contains(s, "(remote)") {
		t.Fatalf("Remote=true 的错误文案应含 \"(remote)\"（文案兜底判据依赖它），实际 %q", s)
	}
	local := &quic.ApplicationError{ErrorCode: 0, ErrorMessage: "path closed", Remote: false}
	if s := local.Error(); !strings.Contains(s, "(local)") {
		t.Fatalf("Remote=false 的错误文案应含 \"(local)\"，实际 %q", s)
	}
}

// TestIsPeerInitiatedClose ⭐ 2026-09-27（Bug 3）：**分清「对端主动关闭」与「本机链路问题」**。
//
//	覆盖四类：`(remote)` 应用层关 / `(local)` 应用层关 / idle timeout / EOF。
//	前一类必须判 true，后三类必须判 false（否则会漏掉真正的链路问题）。
//
// ⚠️ 有牙：把判据改成「永远 true」⇒ 后三类红；改成「永远 false」⇒ 第一类红。
func TestIsPeerInitiatedClose(t *testing.T) {
	// ① 真机原文（B 侧日志）与同形态：必须判为「对端发起」
	remoteCases := []error{
		errors.New("Application error 0x0 (remote): path closed"),
		errors.New("Application error 0x1 (remote): bye"),
		&quic.ApplicationError{ErrorCode: 0, ErrorMessage: "path closed", Remote: true}, // 类型级判据
	}
	for _, e := range remoteCases {
		if !isPeerInitiatedClose(e) {
			t.Fatalf("%v 应判为「对端主动关闭」", e)
		}
	}
	// ② 本机/网络侧原因：**不得**误判成对端发起
	localCases := []error{
		errors.New("Application error 0x0 (local): path closed"),
		errors.New("idle timeout: no recent network activity"),
		errors.New("timeout: no recent network activity"),
		errors.New("EOF"),
		errors.New(""),
		&quic.ApplicationError{ErrorCode: 0, ErrorMessage: "path closed", Remote: false}, // 类型级：本机关
		&quic.TransportError{ErrorCode: quic.InternalError, ErrorMessage: "no recent network activity"},
	}
	for _, e := range localCases {
		if isPeerInitiatedClose(e) {
			t.Fatalf("%v 不得判为「对端主动关闭」（这是本机/网络侧原因，仍应走 direct-lost）", e)
		}
	}
	if isPeerInitiatedClose(nil) {
		t.Fatal("nil 不得判为对端主动关闭")
	}
}

// TestScheduleRetryShortCooldownForPeerClosed ⭐ Bug 3 的**端到端**那一半（2026-09-27 补）：
//
//	对端主动关闭 ⇒ `scheduleRetry` 必须排一个**固定短冷却**（复用 `backoffBusy` = 30s），
//	且：
//	  - **不推进任何 streak**（`step`/`qualityStep` 原样）；
//	  - **不覆盖 `lastErr`**（保留此前的真实原因，便于诊断）；
//	  - 冷却窗口 ≈ 30s（防「对端关闭后有流量就立刻再打」的重试风暴）。
//
// ⚠️ 有牙：把 `failPeerClosed` 分支删掉（落回 `backoffDelayFor` 的 (0,false)）⇒
//
//	`until` 会变成 `now+0`（等于没冷却）⇒ 红。
func TestScheduleRetryShortCooldownForPeerClosed(t *testing.T) {
	host := newFakeHost()
	pm := newPathManager(host)
	dst := ip4("192.168.30.12")

	// 先造一条已有的退避（模拟此前有过失败）——档位必须**原样保留**
	pm.mu.Lock()
	pm.backoff[dst] = backoffState{until: time.Now().Add(time.Hour), step: 2, qualityStep: 3, lastErr: "probe-timeout"}
	pm.mu.Unlock()

	start := time.Now()
	pm.scheduleRetry(dst, P2PReasonPeerClosed)
	elapsed := time.Since(start)

	pm.mu.Lock()
	st, ok := pm.backoff[dst]
	pm.mu.Unlock()
	if !ok {
		t.Fatal("应留下一条短冷却记录（否则退避门不拦，会重试风暴）")
	}
	if st.step != 2 || st.qualityStep != 3 {
		t.Fatalf("对端主动关闭**不得推进任何 streak**：step=%d qualityStep=%d（应保持 2/3）",
			st.step, st.qualityStep)
	}
	if st.lastErr != "probe-timeout" {
		t.Fatalf("不得覆盖 lastErr（保留真实历史原因便于诊断），实际 %q", st.lastErr)
	}
	// 冷却窗口应被**缩短**到 ≈30s（不是原来的 1h，也不是 0）
	left := time.Until(st.until)
	if left > backoffBusy+2*time.Second || left < backoffBusy-2*time.Second {
		t.Fatalf("对端主动关闭应排 %v 短冷却，实际剩余 %v（elapsed=%v）", backoffBusy, left, elapsed)
	}
	if backoffBusy != 30*time.Second {
		t.Fatalf("短冷却常量应为 30s（与 failBusy 共用值、但分支独立），实际 %v", backoffBusy)
	}
}
