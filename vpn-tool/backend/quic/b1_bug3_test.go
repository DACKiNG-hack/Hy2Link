package quic

// vpn-tool/backend/quic/b1_bug3_test.go
//
// ⭐ B1 切片（2026-09-27）：**Bug 3 覆盖修复** + **灰度期「响应方探路收尾」启发式** 的用例。
//
// 背景（真机复盘，两条错判链）：
//  1. 五个 L1 分支里只有 L1-c 判过「对端主动关闭」⇒ 其余四条把「对端关连接」当成本机链路质量差，
//     白排 5m/30m 退避。**而且**：`demoteOnce` 是「先到先赢」⇒ 各分支自己算原因码仍是竞态
//     ⇒ 判定收敛到唯一入口 `demoteWith`。
//  2. 读循环拿到的其实是 **io.EOF**（对端先 FIN，且 `receiveStream.readImpl` 把 EOF 排在
//     关闭错误之前）⇒ 判据必须扩到 4 形态（见 `TestIsPeerInitiatedCloseFourForms`）。
//
// 灰度期残余：未升级对端的预打洞「探路收尾」若其 CONNECTION_CLOSE 丢包，本机只能靠试用期
// 判负（15s，早于判活判死 16-17s）发现 ⇒ 走 `quality-poor`（5min）⇒ 启发式把它收敛到
// `peer-closed`（30s 短冷却）。**全网升级后整体删除**（删除条件见 A2 文档）。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/apernet/quic-go"
)

// ---------- ① 判据 4 形态（含反向） ----------

// TestIsPeerInitiatedCloseFourForms ⭐⭐ Bug 3 覆盖修复的核心判据。
//
// 覆盖 4 种「对端发起」形态 + 5 种必须为 false 的形态：
//
//	① ApplicationError{Remote}   连接级应用层 CONNECTION_CLOSE
//	② TransportError{Remote}     **故意 false**（口径选择，见函数头；不是漏写 Remote）
//	③ StreamError{Remote}        对端 RESET_STREAM（文案不含 `(remote)` ⇒ 必须类型级）
//	④ io.EOF / io.ErrUnexpectedEOF  对端 FIN（读循环实际拿到的就是这个）
//
// ⚠️ 有牙：把 ④ 删掉 ⇒ 本用例红（而这正是真机上三条读循环的形态）。
func TestIsPeerInitiatedCloseFourForms(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"① ApplicationError{Remote:true}", &quic.ApplicationError{Remote: true}, true},
		{"① ApplicationError{Remote:false}", &quic.ApplicationError{Remote: false}, false},
		{"① 包装后的 ApplicationError（errors.As 穿透 %w）",
			fmt.Errorf("stream closed: %w", &quic.ApplicationError{Remote: true}), true},

		// ② 口径选择：**本 fork 的 TransportError 确实有 Remote 字段**，
		//    但本判据故意不看它（传输层错误一律按本机侧处理）。
		//    ⚠️ 这条是**有意行为**：改成读 Remote 会让本用例红，那时请先评审再改。
		{"② TransportError{Remote:true} ⇒ 口径：false", &quic.TransportError{Remote: true}, false},
		{"② TransportError{Remote:true} 文案确实含 (remote)（说明 false 是选择不是漏写）",
			&quic.TransportError{Remote: true}, false},

		{"③ StreamError{Remote:true}", &quic.StreamError{Remote: true}, true},
		{"③ StreamError{Remote:false}", &quic.StreamError{Remote: false}, false},

		{"④ io.EOF", io.EOF, true},
		{"④ io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, true},
		{"④ 包装后的 io.EOF（readFrame → io.ReadFull 的返回）",
			fmt.Errorf("控制流读失败: %w", io.EOF), true},

		{"否定 · context.Canceled", context.Canceled, false},
		{"否定 · 普通错误", errors.New("boom"), false},
		{"否定 · nil", nil, false},
	}
	for _, c := range cases {
		if got := isPeerInitiatedClose(c.err); got != c.want {
			t.Fatalf("%s：want %v，got %v", c.name, c.want, got)
		}
	}

	// ② 的文案事实单独钉一次（防止有人以为 TransportError 没有 Remote / 文案无 (remote) 而"顺手修正"）
	te := &quic.TransportError{Remote: true}
	if !strings.Contains(te.Error(), "(remote)") {
		t.Fatalf("TransportError{Remote:true} 的文案应含 (remote)，实际 %q —— "+
			"若 quic-go 形状变了，请重审 isPeerInitiatedClose 的 ② 分支", te.Error())
	}
}

// TestQuicGoStreamErrorShape ⭐ 升级守卫（与 TestQuicGoApplicationErrorShape 同族）：
// **编译期**钉住 `quic.StreamError` 带 `Remote` 字段，且其文案**不含** `(remote)`。
//
// 为什么必须钉：`isPeerInitiatedClose` 对 StreamError 必须走**类型级**判据；
// 若某天文案变成含 `(remote)`，"文案兜底也能救"的错觉会让类型级判据被删掉。
//
// ⚠️ 编译期性质：`var _ *quic.TransportError = &quic.TransportError{Remote: true}` 与
// `e.Remote` 的读取若失败，是**编译错误**（不是运行期红）。
func TestQuicGoStreamErrorShape(t *testing.T) {
	var e *quic.StreamError = &quic.StreamError{Remote: true, ErrorCode: 1}
	if !e.Remote {
		t.Fatal("StreamError.Remote 字段必须可读（类型级判据的前提）")
	}
	if !strings.Contains(e.Error(), "canceled by remote") {
		t.Fatalf("StreamError{Remote:true} 的文案形态变了：%q", e.Error())
	}
	if strings.Contains(e.Error(), "(remote)") {
		t.Fatalf("⚠️ StreamError 文案现在含 `(remote)` 了：%q —— 语义前提已变，请重审判据与注释", e.Error())
	}
	// 形状断言：本 fork 的 TransportError 有 Remote（用于 TestIsPeerInitiatedCloseFourForms 的 ② 说明）
	var _ *quic.TransportError = &quic.TransportError{Remote: true}
}

// ---------- ② 单位与数值守卫 ----------

// TestScoutEchoBoundUnits ⭐ 数值守卫：钉住「右界 = 窗口 + scoutEchoMargin」的量级。
//
// ⚠️ 为什么需要它：`clampPunchWindow` 返回 **int(ms)**、`scoutEchoMargin` 是 `time.Duration`
// ⇒ 漏掉 `.Milliseconds()` 会得到 +5×10⁹ ms（≈58 天）⇒ 启发式**恒真**，
// 而**不会有任何编译错误**。本用例期望值**从常量推导**（上界改动时无需两处同步）。
func TestScoutEchoBoundUnits(t *testing.T) {
	pm := newPathManager(newFakeHost())
	p := &directPath{mgr: pm}

	// ① 未传窗口（旧对端 omitempty）⇒ 兜底 punchWindowDefault
	p.scoutWindowMs = 0
	if got, want := p.scoutEchoBoundMs(), int64(punchWindowDefault)+scoutEchoMargin.Milliseconds(); got != want {
		t.Fatalf("窗口缺失应兜底 %d：want %d，got %d", punchWindowDefault, want, got)
	}
	// ② 负值同样兜底
	p.scoutWindowMs = -1
	if got, want := p.scoutEchoBoundMs(), int64(punchWindowDefault)+scoutEchoMargin.Milliseconds(); got != want {
		t.Fatalf("负窗口应兜底：want %d，got %d", want, got)
	}
	// ③ 正常值
	p.scoutWindowMs = punchWindowDefault
	if got, want := p.scoutEchoBoundMs(), int64(punchWindowDefault)+scoutEchoMargin.Milliseconds(); got != want {
		t.Fatalf("默认窗口：want %d，got %d", want, got)
	}
	// ④ 超上界 ⇒ clamp 到 punchWindowMax（期望值从常量推导，不写死 16000）
	p.scoutWindowMs = 99999
	if got, want := p.scoutEchoBoundMs(), int64(punchWindowMax)+scoutEchoMargin.Milliseconds(); got != want {
		t.Fatalf("超上界应 clamp 到 %d：want %d，got %d", punchWindowMax, want, got)
	}
	// ⑤ 量级哨兵：漏 `.Milliseconds()` 时这里是 5×10⁹
	if got := p.scoutEchoBoundMs(); got > 60_000 {
		t.Fatalf("右界量级异常（%d ms）——极可能漏了 `.Milliseconds()`（scoutEchoMargin 是 Duration）", got)
	}
}

// ---------- ③ 启发式判定矩阵（决策级；含全部反向边界） ----------

// TestScoutTearDownHeuristicMatrix ⭐⭐ 决策级守卫：正例 2 条 + 反例 5 条。
//
// ⚠️ 每条反例都对应一个**具体的判据项**（删掉该项即有一条红）：
//
//	initiator / 有业务流量 / 年龄超界 / 回显太晚（右界）/ 回显刚好越过右界（边界）
//
// ⚠️ 判据里**不含 peer-close 事实**（否则是空操作）⇒ 这里只喂"无事实"的形态。
func TestScoutTearDownHeuristicMatrix(t *testing.T) {
	pm := newPathManager(newFakeHost())
	now := time.Now()

	// mk 造一条「响应方 + 0 字节 + 年轻」的路径（字面量夹具：不调 demote ⇒ 不需要 conn/untrack）
	mk := func() *directPath {
		p := &directPath{mgr: pm, peer: ip4("192.168.30.12"), role: pathRoleResponder}
		p.since = now
		p.trialStartedAt.Store(now.UnixMilli())
		p.lastEcho.Store(0)
		return p
	}

	// 正例 ①：从未回显（对端根本没通过）
	if p := mk(); !p.scoutTearDownHeuristic() {
		t.Fatal("正例①响应方+0字节+从未回显 ⇒ 应命中")
	}
	// 正例 ②：**早期回显后失联**（review 2026-09-27 举的漏报场景：trialSamples=1 时也必须命中）
	{
		p := mk()
		p.lastEcho.Store(now.Add(5 * time.Second).UnixMilli())
		if !p.scoutTearDownHeuristic() {
			t.Fatal("正例②T0+5s 回过一次、之后失联 ⇒ 应命中（这是 trialSamples==0 判据会漏掉的那条）")
		}
	}
	// 正例 ③：右界之内（恰好 = 窗口 + margin）
	{
		p := mk()
		p.lastEcho.Store(now.UnixMilli() + p.scoutEchoBoundMs())
		if !p.scoutTearDownHeuristic() {
			t.Fatal("正例③回显恰好落在右界上 ⇒ 应命中（右界含等号）")
		}
	}

	// 反例 ①：initiator（本机才是发起方 ⇒ 不是"响应方探路收尾"）
	{
		p := mk()
		p.role = pathRoleInitiator
		if p.scoutTearDownHeuristic() {
			t.Fatal("反例①发起方路径不得命中")
		}
	}
	// 反例 ②：承载过业务流量 ⇒ 是"要用的连接"，不是探路
	{
		p := mk()
		p.bytesUp.Store(1)
		if p.scoutTearDownHeuristic() {
			t.Fatal("反例②有出向业务流量 ⇒ 不得命中")
		}
		p2 := mk()
		p2.bytesDown.Store(1)
		if p2.scoutTearDownHeuristic() {
			t.Fatal("反例②有入向业务流量 ⇒ 不得命中")
		}
	}
	// 反例 ③：回显**恰好越过**右界 1ms（边界：写宽/写反都会红）
	{
		p := mk()
		p.lastEcho.Store(now.UnixMilli() + p.scoutEchoBoundMs() + 1)
		if p.scoutTearDownHeuristic() {
			t.Fatal("反例③回显越过右界 1ms ⇒ 不得命中（对端活过了自己的探路窗口）")
		}
	}
	// 反例 ④：回显太晚（review 举的 +12s 场景 ⇒ 应走 direct-lost，不是探路）
	{
		p := mk()
		p.lastEcho.Store(now.Add(12 * time.Second).UnixMilli())
		if p.scoutTearDownHeuristic() {
			t.Fatal("反例④对端活到 +12s ⇒ 不得命中")
		}
	}
	// 反例 ⑤：年龄超 scoutBound（次要守卫；此例的回显项**是**满足的 ⇒ 单独钉住年龄项）
	{
		p := &directPath{mgr: pm, peer: ip4("192.168.30.12"), role: pathRoleResponder}
		p.since = now.Add(-time.Minute)
		p.trialStartedAt.Store(p.since.UnixMilli())
		p.lastEcho.Store(p.since.Add(5 * time.Second).UnixMilli()) // 回显项满足
		if p.scoutTearDownHeuristic() {
			t.Fatal("反例⑤年龄超过 scoutBound ⇒ 不得命中（0 字节僵尸登记）")
		}
	}
	// 反例 ⑥：trialStartedAt 未落（极端：newDirectPath 与 run 之间）⇒ 不判
	{
		p := &directPath{mgr: pm, peer: ip4("192.168.30.12"), role: pathRoleResponder}
		p.since = now
		if p.scoutTearDownHeuristic() {
			t.Fatal("反例⑥trialStartedAt==0 ⇒ 不得命中")
		}
	}
}

// ---------- ④ 端到端：原因码与退避档（用退避状态断言，避免依赖事件通道） ----------

// scoutHarness 造一条「响应方 + 0 字节 + 年轻」的真实路径（有 conn/untrack ⇒ 可走 demote）。
func scoutHarness(t *testing.T, role string) (*pathManager, *directPath, [4]byte) {
	t.Helper()
	host := newFakeHost()
	pm := newPathManager(host)
	const vip = "192.168.30.12"
	p, _ := newTestPathOwned(t, pm, host, vip, role)
	p.scoutWindowMs = punchWindowDefault
	// ⚠️ 夹具造的路径已经走过一遍装表流程（state 可能是 Up、`trialDone` 可能已置位）
	//    ⇒ 显式重置成「正在试用期」的形态（`tryFailTrial` 的两道门都要求它）。
	p.setState(pathStateTrial)
	p.trialDone.Store(false)
	p.trialStartedAt.Store(time.Now().UnixMilli())
	p.trialLastEcho.Store(0)
	p.lastEcho.Store(0)
	return pm, p, ip4(vip)
}

// assertShortCooldown 断言「走了 peer-closed 支」：30s 短冷却且**不推进 qualityStep**。
func assertShortCooldown(t *testing.T, pm *pathManager, dst [4]byte, label string) {
	t.Helper()
	st := pm.backoffSnapshot(dst)
	if st.qualityStep != 0 {
		t.Fatalf("%s：启发式命中时不得推进 qualityStep（实际 %d）⇒ 说明走了 quality-poor 的 5min 档",
			label, st.qualityStep)
	}
	if st.step != 0 {
		t.Fatalf("%s：peer-closed 支不得推进 step（实际 %d）", label, st.step)
	}
	d := time.Until(st.until)
	if d < 25*time.Second || d > 35*time.Second {
		t.Fatalf("%s：应为 backoffBusy=%v 短冷却，实际 %v", label, backoffBusy, d.Round(time.Second))
	}
}

// assertQualityTier 断言「走了 quality-poor 档」：5min 台阶 + 推进 qualityStep。
func assertQualityTier(t *testing.T, pm *pathManager, dst [4]byte, label string) {
	t.Helper()
	st := pm.backoffSnapshot(dst)
	if st.qualityStep != 1 {
		t.Fatalf("%s：应推进到 qualityStep=1，实际 %d", label, st.qualityStep)
	}
	if d := time.Until(st.until); d < 4*time.Minute || d > 6*time.Minute {
		t.Fatalf("%s：应为质量差第一档 5min，实际 %v", label, d.Round(time.Second))
	}
}

// TestResponderScoutHeuristicAtTrialVerdict ⭐⭐ 主用例（挂载点 = tryFailTrial）。
//
// 形态：响应方 + 0 字节 + 对端从未回显 ⇒ 试用期判负 ⇒ 必须记 peer-closed（30s），
//
//	而不是 quality-poor（5min）。这正是灰度期残余场景（对端探路收尾的 close 包丢了）。
func TestResponderScoutHeuristicAtTrialVerdict(t *testing.T) {
	pm, p, dst := scoutHarness(t, pathRoleResponder)
	before := scoutHeuristicHits.Load()
	p.tryFailTrial()
	if got := scoutHeuristicHits.Load(); got != before+1 {
		t.Fatalf("启发式计数器应 +1（否则灰度期无法统计是否真在发生）：before=%d got=%d", before, got)
	}
	assertShortCooldown(t, pm, dst, "响应方探路收尾")
}

// TestResponderScoutHeuristicAtTrialVerdictEarlyEcho ⭐ 早期回显后失联（review 举的漏报场景）。
func TestResponderScoutHeuristicAtTrialVerdictEarlyEcho(t *testing.T) {
	pm, p, dst := scoutHarness(t, pathRoleResponder)
	p.lastEcho.Store(p.trialStartedAt.Load() + 5_000)
	p.trialLastEcho.Store(p.trialStartedAt.Load())
	p.trialSamples.Store(1)
	p.trialGood.Store(1) // 好样本 1 < need 2 ⇒ 判负（真实形态）
	p.tryFailTrial()
	assertShortCooldown(t, pm, dst, "早期回显后失联")
}

// assertRetainedRejected ⭐ A2 判负的**结构判据**（替代 B3/B4 上已失效的「档位差」判据）。
//
// 为什么不能用档位：A2 之后 `tryFailTrial` 的**两条出路都排 30s 且都不推进档位**
// （`path.go` 的 `tryFailTrial` 注释原文：「原来的质量差 5min 档已不再适用」）⇒
// 若照旧断言 `qualityStep=1`/5min，把它改成 30s 后**「启发式错误命中」也会通过 = 假守卫**。
//
//	⇒ 必须换成**结构后果**判据：启发式命中走 `demote(peer-closed)` ⇒ `Down` + 关连接；
//	  非启发式判负走 `rejectTrial()` ⇒ `Rejected` + **连接保留**。两者结构后果不同。
//
// ⚠️ `assertQualityTier`（5min 档）**仍然有效**，但只适用于**走 `demote` 的路径**
// （如 `TestLocalTimeoutStaysDirectLost` 的本地写超时）—— 不适用于 `tryFailTrial` 的判负。
func assertRetainedRejected(t *testing.T, p *directPath, label string) {
	t.Helper()
	if got := p.state.Load(); got != pathStateRejected {
		t.Fatalf("%s：非启发式判负必须**保留连接**（Rejected），实际 %s"+
			"（启发式命中会走 demote ⇒ Down）", label, pathStateName(got))
	}
	if fc, ok := p.conn.(*fakeConn); ok && fc.closed.Load() {
		t.Fatalf("%s：判负后连接**不得**关闭（方案 A 的全部意义）", label)
	}
}

// TestTrialFailStaysQualityPoorOnInitiator ⭐ 反向守卫（Q2 边界）：
// 同样「0 字节 + 从未回显」但**本机是发起方** ⇒ 启发式**不得**命中。
//
// ⚠️ 判据已于 2026-09-28（A2 落地后）**更换**：原判据是「仍是 quality-poor（5min + qualityStep=1）」
// —— A2 之后该断言恒红，且**改成 30s 后会在"启发式错误命中"时也通过**（A2 判负同样是 30s）。
// 现判据有两重：① `scoutHeuristicHits` **不增**（直接问"走没走启发式"）；
//
//	② `assertRetainedRejected` —— 结构后果（保留连接 vs Down+关连接）。
func TestTrialFailStaysQualityPoorOnInitiator(t *testing.T) {
	_, p, _ := scoutHarness(t, pathRoleInitiator)
	before := scoutHeuristicHits.Load()
	p.tryFailTrial()
	if got := scoutHeuristicHits.Load(); got != before {
		t.Fatalf("发起方判负**不得**命中启发式（计数器应不增）：before=%d got=%d", before, got)
	}
	assertRetainedRejected(t, p, "发起方试用期判负")
}

// TestTrialFailStaysQualityPoorWhenPeerAliveLate ⭐ 反向边界：
// 响应方 + 0 字节，但**对端活到 +12s**（超过它自己的探路窗口）⇒ 不得启发式。
// 判据同 `TestTrialFailStaysQualityPoorOnInitiator`（2026-09-28 由档位改为计数器 + 结构后果）。
func TestTrialFailStaysQualityPoorWhenPeerAliveLate(t *testing.T) {
	_, p, _ := scoutHarness(t, pathRoleResponder)
	p.lastEcho.Store(p.trialStartedAt.Load() + 12_000)
	before := scoutHeuristicHits.Load()
	p.tryFailTrial()
	if got := scoutHeuristicHits.Load(); got != before {
		t.Fatalf("对端活到 +12s **不得**命中启发式（计数器应不增）：before=%d got=%d", before, got)
	}
	assertRetainedRejected(t, p, "对端活到 +12s")
}

// TestDemoteErrUpgradesOnPeerCloseErr ⭐ demoteErr 的 err 级升级（ApplicationError{Remote}）。
func TestDemoteErrUpgradesOnPeerCloseErr(t *testing.T) {
	pm, p, dst := scoutHarness(t, pathRoleInitiator) // 发起方 ⇒ 启发式不参与，单看 err 判据
	p.demoteErr(&quic.ApplicationError{Remote: true})
	assertShortCooldown(t, pm, dst, "demoteErr(ApplicationError{Remote})")
}

// TestLocalTimeoutStaysDirectLost ⭐⭐ **负向守卫**（review 拍板的两条之一）：
// 本地写超时（无任何"对端发起"证据、也无探路特征）⇒ 必须仍 direct-lost（5min 档）。
//
// ⚠️ 没有这条，有人把判据写宽（"只要报错就算对端关闭"）也不会红。
func TestLocalTimeoutStaysDirectLost(t *testing.T) {
	pm, p, dst := scoutHarness(t, pathRoleInitiator)
	p.demoteErr(errors.New("write deadline exceeded"))
	assertQualityTier(t, pm, dst, "本地写超时")
}

// TestDemoteErrEOFIsPeerClosed ⭐ 读循环的真实形态：err=io.EOF（对端 FIN）⇒ peer-closed。
func TestDemoteErrEOFIsPeerClosed(t *testing.T) {
	pm, p, dst := scoutHarness(t, pathRoleInitiator)
	p.demoteErr(fmt.Errorf("bulk 流读失败: %w", io.EOF))
	assertShortCooldown(t, pm, dst, "读循环 io.EOF")
}
