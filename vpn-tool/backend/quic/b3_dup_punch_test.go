package quic

// vpn-tool/backend/quic/b3_dup_punch_test.go
//
// ⭐ B3 切片（2026-09-27）：**重复打洞抑制**。
//
// 问题：试用期路径**不占路由槽位、也不承载流量**（数据仍走中继）⇒ 流量会继续触发打洞，
// 于是同一对端在 15s 试用期内被反复发起 attempt（`byPeer` 只挡"同一个会话在飞"，
// 打洞成功后会话结束、`byPeer` 清空，而 trial 路径还要跑十几秒）。
//
// 处置：`punchManager.PunchWithTrigger` 最前面查 `pathManager.HasUsablePath`，
// **只对 `P2PTriggerTraffic`** 生效（手动/配置触发不抑制）。
//
// HasUsablePath 语义（review 拍板）：
//
//	Up      ✅ 算（承载流量）
//	Trial   ✅ 算（试用中 —— 这正是本切片的主要收益）
//	Standby ❌ 不算（降级应允许重试，设计意图）
//	Down    ❌ 不算
//	A2 落地时：Rejected ❌ 不算、Reusing ✅ 算（2 行扩展，非返工）
//
// ⚠️ 竞态取向（review 拍板）：查到"有路径"与"路径消失"之间**不做 CAS** ——
// 这是**启发式抑制**，最多延迟一拍（下一次流量触发会重新放行）。

import (
	"errors"
	"testing"
	"time"
)

const b3PeerVIP = "192.168.30.12"

// setPunchErr 让假 host 的 `punchWithTrigger` 返回指定错误（B3 用例：观察 attemptFor 的错误分支）。
func (h *fakeHost) setPunchErr(err error) {
	h.mu.Lock()
	h.punchErr = err
	h.mu.Unlock()
}

// b3Harness 造「真实 punchManager + 已注入的 pathManager」。
//
// ⚠️ 只有把两者**真正接上**（`setPathManager`）才谈得上抑制 —— 用 fakeHost 的
// `punchWithTrigger` 替身是打不到 `PunchWithTrigger` 的。
func b3Harness(t *testing.T) (*punchManager, *pathManager, *fakeHost) {
	t.Helper()
	host := newFakeHost()
	pm := newPathManager(host)
	pm.tiebreakDelay = time.Millisecond
	t.Cleanup(pm.close)

	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	m := newPunchManager(c)
	m.setPathManager(pm)
	t.Cleanup(m.close)
	return m, pm, host
}

// b3UpPath 造一条「Up 且已装表」的路径（`newTestPath` 内部会 installRoute + passTrialForTest）。
func b3UpPath(t *testing.T, pm *pathManager, host *fakeHost) *directPath {
	t.Helper()
	p, _ := newTestPathOwned(t, pm, host, b3PeerVIP, pathRoleInitiator)
	if got := p.state.Load(); got != pathStateUp {
		t.Fatalf("夹具前置：路径应为 Up，实际 %s", pathStateName(got))
	}
	return p
}

// b3TrialPath 造一条**只在试用登记里**（不占路由槽位）的 Trial 路径。
func b3TrialPath(t *testing.T, pm *pathManager, host *fakeHost) *directPath {
	t.Helper()
	p, _ := newTestPathOwned(t, pm, host, b3PeerVIP, pathRoleInitiator)
	pm.replaceRoutes(nil) // 从路由表摘掉 ⇒ 只剩"试用中"这一形态
	p.setState(pathStateTrial)
	pm.routeMu.Lock()
	pm.addTrialPath(p)
	pm.routeMu.Unlock()
	return p
}

// ---------- 1) Up ⇒ 抑制 ----------

func TestPunchSkipsWhenPathIsUp(t *testing.T) {
	m, pm, host := b3Harness(t)
	b3UpPath(t, pm, host)

	if ok, st := pm.HasUsablePath(ip4(b3PeerVIP)); !ok || st != pathStateName(pathStateUp) {
		t.Fatalf("HasUsablePath 应对 Up 返回可用：ok=%v state=%q", ok, st)
	}
	before := m.skippedDupPunch.Load()
	_, err := m.PunchWithTrigger(b3PeerVIP, P2PTriggerTraffic)
	if !errors.Is(err, errPunchDupPath) {
		t.Fatalf("已有 Up 路径时流量驱动应被抑制（errPunchDupPath），实际 err=%v", err)
	}
	if got := m.skippedDupPunch.Load(); got != before+1 {
		t.Fatalf("抑制计数器应 +1（否则灰度/发版后无法统计）：before=%d got=%d", before, got)
	}
}

// ---------- 2) Trial ⇒ 抑制（本切片的主要收益） ----------

func TestPunchSkipsWhenPathIsTrial(t *testing.T) {
	m, pm, host := b3Harness(t)
	b3TrialPath(t, pm, host)

	if ok, st := pm.HasUsablePath(ip4(b3PeerVIP)); !ok || st != pathStateName(pathStateTrial) {
		t.Fatalf("HasUsablePath 应对 Trial 返回可用：ok=%v state=%q", ok, st)
	}
	if _, err := m.PunchWithTrigger(b3PeerVIP, P2PTriggerTraffic); !errors.Is(err, errPunchDupPath) {
		t.Fatalf("已有 Trial 路径时流量驱动应被抑制，实际 err=%v", err)
	}
}

// ---------- 3) Standby ⇒ **不**抑制（设计意图：降级应允许重试） ----------

func TestPunchAllowsWhenPathIsStandby(t *testing.T) {
	m, pm, host := b3Harness(t)
	p := b3UpPath(t, pm, host)
	p.setState(pathStateStandby) // 降级：连接还在，但本机不用它承载流量

	if ok, st := pm.HasUsablePath(ip4(b3PeerVIP)); ok {
		t.Fatalf("Standby 不得算「可用」（降级应允许重试），实际 ok=%v state=%q", ok, st)
	}
	before := m.skippedDupPunch.Load()
	_, err := m.PunchWithTrigger(b3PeerVIP, P2PTriggerTraffic)
	if errors.Is(err, errPunchDupPath) {
		t.Fatal("Standby 时不得抑制打洞（否则降级后永远无法重试）")
	}
	if got := m.skippedDupPunch.Load(); got != before {
		t.Fatalf("未抑制时计数器不得变化：before=%d got=%d", before, got)
	}
}

// ---------- 4) 无路径 ⇒ 不抑制 ----------

func TestPunchAllowsWhenNoPath(t *testing.T) {
	m, pm, _ := b3Harness(t)
	pm.replaceRoutes(nil)

	if ok, st := pm.HasUsablePath(ip4(b3PeerVIP)); ok {
		t.Fatalf("无路径时应返回不可用，实际 ok=%v state=%q", ok, st)
	}
	if _, err := m.PunchWithTrigger(b3PeerVIP, P2PTriggerTraffic); errors.Is(err, errPunchDupPath) {
		t.Fatal("无路径时不得抑制打洞")
	}
}

// ---------- 5) 手动触发 ⇒ **不**抑制（用户点名打洞必须照做） ----------

func TestPunchAllowsWhenManualTrigger(t *testing.T) {
	m, pm, host := b3Harness(t)
	b3UpPath(t, pm, host)

	before := m.skippedDupPunch.Load()
	if _, err := m.PunchWithTrigger(b3PeerVIP, P2PTriggerManual); errors.Is(err, errPunchDupPath) {
		t.Fatal("手动触发不得被重复抑制（用户点名打洞必须照做）")
	}
	if got := m.skippedDupPunch.Load(); got != before {
		t.Fatalf("手动触发不得计入抑制计数：before=%d got=%d", before, got)
	}
}

// ---------- 6) ⭐⭐ 关键副作用守卫：抑制**不得**写退避 ----------

// TestDupPunchSkipDoesNotWriteBackoff ⭐⭐
//
//	`attemptFor` 对 punch 返回的**非冷却类**错误会 `setBackoffTransient`。
//	若抑制错误漏了这一支，后果是：每次流量触发都推一档退避 ⇒ 越试越难 ⇒ **比不抑制更差**。
//
// 本用例用「对照法」保证断言非空真：
//
//	① `punchErr = errPunchDupPath` ⇒ **不得**写退避；
//	② `punchErr = 普通错误`      ⇒ **必须**写退避（证明①不是因为"退避根本没被写过"而假绿）。
func TestDupPunchSkipDoesNotWriteBackoff(t *testing.T) {
	pm, host, dst := func() (*pathManager, *fakeHost, [4]byte) {
		host := newFakeHost()
		host.addPeer(b3PeerVIP) // 让 attemptFor 的信号门通过
		pm := newPathManager(host)
		pm.tiebreakDelay = time.Millisecond
		t.Cleanup(pm.close)
		return pm, host, ip4(b3PeerVIP)
	}()

	// ① 抑制错误 ⇒ 不写退避
	host.setPunchErr(errPunchDupPath)
	pm.attemptFor(dst, b3PeerVIP, host.vip, false, "")
	if st := pm.backoffSnapshot(dst); !st.until.IsZero() {
		t.Fatalf("重复抑制**不得**写退避（否则每次流量触发都推一档）：%+v", st)
	}
	if host.punchCount() != 0 {
		t.Fatalf("fakeHost 命中 punchErr 时不计入 punchCount（用例前提），实际 %d", host.punchCount())
	}

	// ② 对照：普通错误 ⇒ **必须**写退避（同一路径、同一断言形态）
	host.setPunchErr(errors.New("boom"))
	pm.attemptFor(dst, b3PeerVIP, host.vip, false, "")
	if st := pm.backoffSnapshot(dst); st.until.IsZero() {
		t.Fatal("对照失败：普通错误应写临时退避（否则本用例的①是假绿）")
	}
}
