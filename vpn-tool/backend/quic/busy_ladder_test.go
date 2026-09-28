package quic

// vpn-tool/backend/quic/busy_ladder_test.go
//
// ⭐ 1b-4 第 3 步（§3.2）：peer-busy / rate-limited 的**独立小台阶**。
//
// 语义（范围文档 §3.2 + 实施计划 §7）：
//
//	30s → 60s → 120s → 300s（第四档起恒 5min 封顶）
//	「忙」**不算失败**：绝不推进 pathManager 的 step / qualityStep
//	peer-busy 与 rate-limited **各记各的 streak**（成因不同，混一起会让台阶涨得过快）
//	成功（succeed）⇒ 清零；**非 busy/rate 的失败** ⇒ 也清零（streak = 连续同类）
//
// 两层测试（追问 5 的要求）：
//   - **纯函数** `ladderForBusy`：各档 + 封顶；
//   - **manager 级**：streak 真的推进、冷却值真的变长、成功/别的失败真的清零。

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestBusyLadderSteps ⭐ 纯函数层：档位与封顶
func TestBusyLadderSteps(t *testing.T) {
	cases := []struct {
		streak int
		want   time.Duration
	}{
		{0, 30 * time.Second}, // 第 0 档（= 原 punchBusyCooldown，既有语义不变）
		{1, 60 * time.Second},
		{2, 120 * time.Second},
		{3, 5 * time.Minute}, // ★ 第四档起恒 5min
		{4, 5 * time.Minute},
		{99, 5 * time.Minute}, // 封顶不再增长
		{-1, 30 * time.Second},
	}
	for _, tc := range cases {
		if got := ladderForBusy(tc.streak); got != tc.want {
			t.Fatalf("ladderForBusy(%d) 应为 %v，实际 %v", tc.streak, tc.want, got)
		}
	}
	// 第 0 档必须与既有常量一致（否则「30s 固定」时代的语义被悄悄改了）
	if ladderForBusy(0) != punchBusyCooldown {
		t.Fatalf("台阶第 0 档必须等于 punchBusyCooldown(%v)，实际 %v",
			punchBusyCooldown, ladderForBusy(0))
	}
	// 封顶档必须大于所有**非末档**台阶值（防「封顶比某档还短」）。
	// ⚠️ 末档本身就等于封顶（台阶显式包含 5min，见 TestBusyLadderShapePinned）。
	for i := 0; i < len(punchBusyLadder)-1; i++ {
		if ladderForBusy(i) >= punchBusyCooldownMax {
			t.Fatalf("非末档第 %d 档(%v) 不应达到/超过封顶 %v", i, ladderForBusy(i), punchBusyCooldownMax)
		}
	}
}

// newBusyTestManager 造一个只用于 streak 判定的 punchManager（无需 client/网络）
func newBusyTestManager() *punchManager {
	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	return newPunchManager(c)
}

// endSessionAt 模拟「一次以 reason 结束的会话收尾」：算冷却 + 写 `cooldown`（**同一临界区**，
// 与生产路径 `noteSessionOutcomeLocked` + `m.cooldown[vip] = ...` 完全一致），返回冷却时长。
//
// ⚠️ 为什么测试不能只调 `bumpBusyStreakLocked`：它内部会做惰性清理，
// 而清理判据是「`cooldown[vip]` 已过期或不存在 ⇒ 删 streak」。
// 只推进不写冷却，刚建出来的 streak 会被立刻正确清掉
// （= 实现是对的，测试少了一步）。这个 helper 保证测试走的时序与生产一致。
func endSessionAt(m *punchManager, vip, reason string) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.bumpBusyStreakLocked(vip, reason)
	m.cooldown[vip] = time.Now().Add(d)
	return d
}

// TestBusyStreakAdvancesAndResets ⭐ manager 级（追问 5 的「有牙」那一半）：
// 连续 peer-busy 三次 ⇒ streak 真的到 3、冷却真的 30s→60s→120s；第四次 5min；
// 换一次别的失败 ⇒ 清零；一次成功 ⇒ 清零。rate-limited 走**独立** streak。
func TestBusyStreakAdvancesAndResets(t *testing.T) {
	m := newBusyTestManager()
	const vip = "192.168.30.12"

	// ---------- ① 连续 peer-busy ----------
	wantLadder := []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 5 * time.Minute}
	for i, want := range wantLadder {
		got := endSessionAt(m, vip, P2PReasonPeerBusy)
		if got != want {
			t.Fatalf("第 %d 次 peer-busy 的冷却应为 %v，实际 %v", i+1, want, got)
		}
		if n := m.busyPeerStreak[vip]; n != i+1 {
			t.Fatalf("第 %d 次 peer-busy 后 streak 应为 %d，实际 %d", i+1, i+1, n)
		}
		// ⚠️ 「连续三次后 streak==3」必须放在循环**之后**断言：
		//    wantLadder 有 4 项，循环第 4 次跑完时 streak 已是 4（下一次收尾才反映）。
		if i == 2 && m.busyPeerStreak[vip] != 3 {
			t.Fatalf("连续三次 peer-busy 后 busyPeerStreak[%s] 应为 3，实际 %d", vip, m.busyPeerStreak[vip])
		}
	}
	// 第四次起恒 5min
	if got := endSessionAt(m, vip, P2PReasonPeerBusy); got != 5*time.Minute {
		t.Fatalf("第四次及以后应为 5min 封顶，实际 %v", got)
	}

	// ---------- ② rate-limited 走**独立** streak（不推进 busyPeer）----------
	if got := endSessionAt(m, vip, P2PReasonRateLimited); got != 30*time.Second {
		t.Fatalf("rate-limited 的**第 0 档**应为 30s（独立 streak），实际 %v", got)
	}
	if n := m.rateStreak[vip]; n != 1 {
		t.Fatalf("rateStreak 应为 1，实际 %d", n)
	}
	if n := m.busyPeerStreak[vip]; n != 5 {
		t.Fatalf("rate-limited 不得推进 busyPeerStreak（应仍为 5，即四次 + 一次封顶后的计数），实际 %d", n)
	}

	// ---------- ③ 换一次「别的失败」⇒ **两条** streak 都清零 ----------
	if got := endSessionAt(m, vip, P2PReasonPunchTimeout); got != punchCooldown {
		t.Fatalf("非 busy/rate 失败应走 punchCooldown(%v)，实际 %v", punchCooldown, got)
	}
	if n := m.busyPeerStreak[vip]; n != 0 {
		t.Fatalf("别的失败后 busyPeerStreak 应清零，实际 %d", n)
	}
	if n := m.rateStreak[vip]; n != 0 {
		t.Fatalf("别的失败后 rateStreak 应清零，实际 %d", n)
	}
	// 再忙一次 ⇒ 回到 30s（而不是接着 5min）
	if got := endSessionAt(m, vip, P2PReasonPeerBusy); got != 30*time.Second {
		t.Fatalf("清零后再忙应从 30s 起算，实际 %v", got)
	}
	if got := endSessionAt(m, vip, P2PReasonPeerBusy); got != 60*time.Second {
		t.Fatalf("第二次忙应为 60s，实际 %v", got)
	}

	// ---------- ④ 「忙」绝不推进 pathManager 的打洞/质量差 streak ----------
	//    本步完全不碰那两个字段：用一个真实的 pathManager 断言未被污染。
	host := newFakeHost()
	pm := newPathManager(host)
	defer pm.close()
	dst := ip4(vip)
	if _, ok := pm.hasBackoff(dst); ok {
		t.Fatal("前置：pathManager 不应有该对端的退避记录")
	}
	busyMgr := newBusyTestManager()
	for i := 0; i < 4; i++ {
		endSessionAt(busyMgr, vip, P2PReasonPeerBusy)
	}
	st, ok := pm.hasBackoff(dst)
	if ok && (st.step != 0 || st.qualityStep != 0) {
		t.Fatalf("「忙」不得推进打洞/质量差 streak，实际 step=%d qualityStep=%d", st.step, st.qualityStep)
	}
}

// TestBusyStreakClearedOnSuccess ⭐ 成功（succeed）⇒ 两条 streak 都清零
func TestBusyStreakClearedOnSuccess(t *testing.T) {
	m := newBusyTestManager()
	const vip = "192.168.30.12"

	endSessionAt(m, vip, P2PReasonPeerBusy)
	endSessionAt(m, vip, P2PReasonPeerBusy)
	endSessionAt(m, vip, P2PReasonRateLimited)
	if m.busyPeerStreak[vip] == 0 || m.rateStreak[vip] == 0 {
		t.Fatal("前置：两条 streak 都应非 0")
	}

	// 造一个「已成功」的会话，走收尾路径（noteSessionOutcomeLocked）
	s := m.newSession("0123456789abcdef", vip, pathRoleInitiator,
		3000, "seed", "", netip.MustParseAddrPort("1.2.3.4:30001"))
	s.succeeded.Store(true)
	s.reason.Store(P2PReasonOKDirect)
	if got := m.noteSessionOutcomeLocked(s); got != 0 {
		t.Fatalf("成功后不设冷却（路径由 pathManager 接管），实际 %v", got)
	}
	if n := m.busyPeerStreak[vip]; n != 0 {
		t.Fatalf("成功后 busyPeerStreak 应清零，实际 %d", n)
	}
	if n := m.rateStreak[vip]; n != 0 {
		t.Fatalf("成功后 rateStreak 应清零，实际 %d", n)
	}
}

// TestBusyStreakPrunedWithCooldown ⭐ 追问 3：streak 寿命与 cooldown 对齐（惰性清理）
func TestBusyStreakPrunedWithCooldown(t *testing.T) {
	m := newBusyTestManager()
	const vip = "192.168.30.12"

	endSessionAt(m, vip, P2PReasonPeerBusy)
	endSessionAt(m, vip, P2PReasonRateLimited)
	if len(m.busyPeerStreak) == 0 || len(m.rateStreak) == 0 {
		t.Fatal("前置：两条 streak 都应有条目")
	}

	// 冷却尚未过期 ⇒ 不清理
	m.cooldown[vip] = time.Now().Add(time.Minute)
	m.pruneBusyLocked(time.Now())
	if len(m.busyPeerStreak) != 1 || len(m.rateStreak) != 1 {
		t.Fatal("冷却未过期时不得清理 streak")
	}

	// 冷却已过期 ⇒ 清理（「那次忙已经无关」）
	m.cooldown[vip] = time.Now().Add(-time.Second)
	m.pruneBusyLocked(time.Now())
	if len(m.busyPeerStreak) != 0 {
		t.Fatalf("冷却过期后 busyPeerStreak 应被清理，实际 %d 条", len(m.busyPeerStreak))
	}
	if len(m.rateStreak) != 0 {
		t.Fatalf("冷却过期后 rateStreak 应被清理，实际 %d 条", len(m.rateStreak))
	}
	// cooldown 不存在（从未失败过）⇒ 也清理
	m.busyPeerStreak["9.9.9.9"] = 2
	m.pruneBusyLocked(time.Now())
	if _, ok := m.busyPeerStreak["9.9.9.9"]; ok {
		t.Fatal("没有冷却记录的对端，其 streak 也应被清理")
	}
}

// TestBusyStreakCapacityRefusesNew ⭐ 追问 3 的兜底：超出上限时**拒绝新增**（不淘汰已有）
func TestBusyStreakCapacityRefusesNew(t *testing.T) {
	m := newBusyTestManager()
	// 先把表填满（直接构造，避免 1024 次真实调用）
	for i := 0; i < punchBusyStreakMaxEntries; i++ {
		m.busyPeerStreak[ip4ToString([4]byte{10, byte(i >> 8), byte(i & 0xFF), 1})] = 1
	}
	// 这些已有条目都不在 cooldown 里 ⇒ 会被 pruneBusyLocked 清掉，
	// 所以这里先给它们写上「未过期」的冷却，避免被惰性清理。
	until := time.Now().Add(time.Hour)
	for k := range m.busyPeerStreak {
		m.cooldown[k] = until
	}
	before := len(m.busyPeerStreak)

	// 新对端 ⇒ 拒绝新增（返回第 0 档，不淘汰任何已有 streak）
	m.mu.Lock()
	got := m.bumpBusyStreakLocked("192.168.30.99", P2PReasonPeerBusy)
	m.mu.Unlock()
	if got != punchBusyCooldown {
		t.Fatalf("超出上限时应退回第 0 档 %v，实际 %v", punchBusyCooldown, got)
	}
	if after := len(m.busyPeerStreak); after != before {
		t.Fatalf("超出上限时不得新增（也不得淘汰），前 %d 后 %d", before, after)
	}
	// 已有条目仍能正常推进（第 1 档 60s）
	got2 := endSessionAt(m, "10.0.0.1", P2PReasonPeerBusy)
	if got2 != 60*time.Second {
		t.Fatalf("已有条目应正常推进到第 1 档(60s)，实际 %v", got2)
	}
}

// TestBusyAndRateStreaksDoNotMix ⭐ review 追问 2：两条 streak **各自计数**，交替不会加速涨档。
//
//	交替 busy → rate → busy 的冷却必须是 **30s → 30s → 60s**
//	（若混成一条 streak，就会是 30s → 60s → 120s —— 两种成因的对策完全不同：
//	  一个等对端腾出余力，一个等本机额度恢复，混算会让台阶被无关原因推高）
func TestBusyAndRateStreaksDoNotMix(t *testing.T) {
	m := newBusyTestManager()
	const vip = "192.168.30.12"

	// ① busy → 走 busyPeer 的第 0 档
	if got := endSessionAt(m, vip, P2PReasonPeerBusy); got != 30*time.Second {
		t.Fatalf("第 1 次（busy）应为 30s，实际 %v", got)
	}
	// ② rate → 走 rate 的**第 0 档**（不是 60s：busy 的那次不参与 rate 的计数）
	if got := endSessionAt(m, vip, P2PReasonRateLimited); got != 30*time.Second {
		t.Fatalf("第 2 次（rate）应为 30s（独立 streak），实际 %v", got)
	}
	// ③ busy → 这时 busyPeer 才是第 1 档
	if got := endSessionAt(m, vip, P2PReasonPeerBusy); got != 60*time.Second {
		t.Fatalf("第 3 次（busy）应为 60s（busy 自己的第 1 档），实际 %v", got)
	}
	// ④ rate → rate 自己的第 1 档
	if got := endSessionAt(m, vip, P2PReasonRateLimited); got != 60*time.Second {
		t.Fatalf("第 4 次（rate）应为 60s（rate 自己的第 1 档），实际 %v", got)
	}
	// 两条 streak 的实际计数（证明是「各记各的」而不是「共用一个」）
	if n := m.busyPeerStreak[vip]; n != 2 {
		t.Fatalf("busyPeerStreak 应为 2，实际 %d", n)
	}
	if n := m.rateStreak[vip]; n != 2 {
		t.Fatalf("rateStreak 应为 2，实际 %d", n)
	}
	// 对照：若**混算**成一条 streak，第 5 次（busy）会落到第 4 档 ⇒ 按越界封顶取 5min；
	// 而正确行为是取 busy 自己的第 2 档（120s）。⇒ 断言「绝不是 5min」。
	// （用 5min 而不是 120s 做对照，是因为末档现在显式等于封顶：见 TestBusyLadderShapePinned）
	if got := endSessionAt(m, vip, P2PReasonPeerBusy); got == punchBusyCooldownMax {
		t.Fatalf("连续交替不得让台阶按「总次数」上涨（那是混算 streak 的症状）：第 5 次不该到封顶 %v",
			punchBusyCooldownMax)
	} else if got != 120*time.Second {
		t.Fatalf("第 5 次（busy 的第 3 次）应为 120s，实际 %v", got)
	}
}

// TestBusyLadderShapePinned ⭐ review 追问 5：台阶**显式包含封顶档**，且与常量一致。
//
// 钉住「改台阶只改一处」的结构：`punchBusyLadder` 必须显式列出 5min，
// 且末档 == `punchBusyCooldownMax`（否则「封顶常量」与「台阶末档」会两处漂移）。
func TestBusyLadderShapePinned(t *testing.T) {
	if len(punchBusyLadder) != 4 {
		t.Fatalf("台阶应显式列出 4 档（30s/60s/120s/5min），实际 %d 档: %v",
			len(punchBusyLadder), punchBusyLadder)
	}
	if punchBusyLadder[0] != punchBusyCooldown {
		t.Fatalf("台阶第 0 档必须等于 punchBusyCooldown(%v)，实际 %v",
			punchBusyCooldown, punchBusyLadder[0])
	}
	if last := punchBusyLadder[len(punchBusyLadder)-1]; last != punchBusyCooldownMax {
		t.Fatalf("台阶末档必须等于 punchBusyCooldownMax(%v)，实际 %v（两处会漂移）",
			punchBusyCooldownMax, last)
	}
	// 单调递增（台阶语义）：后一档必须严格大于前一档
	for i := 1; i < len(punchBusyLadder); i++ {
		if punchBusyLadder[i] <= punchBusyLadder[i-1] {
			t.Fatalf("台阶必须严格递增：第 %d 档 %v ≤ 第 %d 档 %v",
				i, punchBusyLadder[i], i-1, punchBusyLadder[i-1])
		}
	}
	// 越界取末档（不再有「另一个常量」参与）
	if got := ladderForBusy(len(punchBusyLadder)); got != punchBusyCooldownMax {
		t.Fatalf("越界应取末档 %v，实际 %v", punchBusyCooldownMax, got)
	}
	if got := ladderForBusy(999); got != punchBusyCooldownMax {
		t.Fatalf("超长 streak 应取末档 %v，实际 %v", punchBusyCooldownMax, got)
	}
}

// TestCooldownErrorSkipsPathBackoff ⭐ **接线牙**（实施计划 §2.2 / §7.5）：
// 冷却类错误**不得**写 `pathManager.backoff` —— 否则 30s 退避会盖住 60s/120s/5min 长档。
func TestCooldownErrorSkipsPathBackoff(t *testing.T) {
	host := newFakeHost()
	host.addPeer("192.168.30.12")
	pm := newPathManager(host)
	defer pm.close()
	dst := ip4("192.168.30.12")

	// 让宿主把「冷却期内」的错误返回出来（punchWithTrigger 的返回错误被透传）
	host.mu.Lock()
	host.punchErr = errPunchCooldown
	host.mu.Unlock()

	pm.attemptFor(dst, "192.168.30.12", host.vip, false, "")
	if st, ok := pm.hasBackoff(dst); ok {
		t.Fatalf("冷却类错误**不得**写本地退避（否则长档被 30s 盖住），实际 until=%v lastErr=%q",
			time.Until(st.until), st.lastErr)
	}

	// 对照：**非**冷却类错误仍要写退避（保持既有行为）
	host.mu.Lock()
	host.punchErr = errFake("其它原因")
	host.mu.Unlock()
	pm.attemptFor(dst, "192.168.30.12", host.vip, false, "")
	st, ok := pm.hasBackoff(dst)
	if !ok {
		t.Fatal("非冷却类错误仍应写退避（对照）")
	}
	if d := time.Until(st.until); d > backoffBusy+time.Second {
		t.Fatalf("对照组的退避应约为 %v，实际 %v", backoffBusy, d)
	}
}

// TestPunchWithTriggerCooldownErrorIsWrapped ⭐ 哨兵必须**真的**能被 errors.Is 识别：
// `PunchWithTrigger` 在冷却期内返回的错误必须包装 errPunchCooldown。
func TestPunchWithTriggerCooldownErrorIsWrapped(t *testing.T) {
	m := newBusyTestManager()
	const vip = "192.168.30.12"

	// 手动置一个未到期的冷却
	m.mu.Lock()
	m.cooldown[vip] = time.Now().Add(30 * time.Second)
	m.mu.Unlock()

	_, err := m.PunchWithTrigger(vip, P2PTriggerTraffic)
	if err == nil {
		t.Fatal("冷却期内 PunchWithTrigger 应返回错误")
	}
	if !errors.Is(err, errPunchCooldown) {
		t.Fatalf("冷却期内的错误必须包装 errPunchCooldown（否则 pathManager 识别不到、会重复排退避）；实际: %v", err)
	}
	if !strings.Contains(err.Error(), "后可重试") {
		t.Fatalf("面向用户的文案应保留（只说「冷却」用户看不懂），实际: %v", err)
	}
}
