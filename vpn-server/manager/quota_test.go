package manager

// vpn-server/manager/quota_test.go
//
// ⭐ P3 补丁的测试：中继配额的运行期复查。
//
// 覆盖：
//   - 判据与认证时一致（>=、Max==0 不限）
//   - 账号级（同一账号多连接只踢一次）
//   - 单个账号失败不影响其它账号
//   - 复查 goroutine 的启停（幂等、可退出、不乱踢不限量账号）

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"vpn-server/admin"
	"vpn-server/store"
)

// quotaOf 造一个配额快照
func quotaOf(used, max uint64) quotaState {
	return quotaState{Used: used, Max: max, Known: true}
}

// ---------- 纯逻辑：kickOverQuota ----------

// TestQuotaStateOverQuota 判据必须与认证时逐字一致：
// authenticator.go: `MaxBytes > 0 && UsedBytes >= MaxBytes`
func TestQuotaStateOverQuota(t *testing.T) {
	cases := []struct {
		name string
		q    quotaState
		want bool
	}{
		{"不限（Max=0）", quotaOf(1<<40, 0), false},
		{"未用尽", quotaOf(100, 1000), false},
		{"刚好用尽（边界，>=）", quotaOf(1000, 1000), true},
		{"已超用", quotaOf(1001, 1000), true},
		{"账号不存在", quotaState{Used: 1 << 40, Max: 1}, false},
	}
	for _, c := range cases {
		if got := c.q.OverQuota(); got != c.want {
			t.Fatalf("%s: OverQuota()=%v，期望 %v", c.name, got, c.want)
		}
	}
}

// TestKickOverQuotaOnlyKicksOverQuota 只踢超限账号，且返回被踢列表
func TestKickOverQuotaOnlyKicksOverQuota(t *testing.T) {
	quotas := map[string]quotaState{
		"alice":  quotaOf(1000, 1000), // 刚好用尽 → 踢
		"bob":    quotaOf(10, 1000),   // 没用完 → 不踢
		"carol":  quotaOf(1<<40, 0),   // 不限 → 不踢
		"dave":   quotaOf(2000, 1000), // 超用 → 踢
		"nobody": {},                  // 账号已删除 → 不踢
	}
	var mu sync.Mutex
	var kicked []string
	logs := 0

	got := kickOverQuota(
		[]string{"alice", "bob", "carol", "dave", "nobody"},
		func(u string) quotaState { return quotas[u] },
		func(u string) error {
			mu.Lock()
			defer mu.Unlock()
			kicked = append(kicked, u)
			return nil
		},
		func(string, ...any) { logs++ },
	)

	if strings.Join(got, ",") != "alice,dave" {
		t.Fatalf("被踢账号应为 alice,dave（字典序），实际 %v", got)
	}
	if strings.Join(kicked, ",") != "alice,dave" {
		t.Fatalf("实际踢人调用应为 alice,dave，实际 %v", kicked)
	}
	if logs != 2 {
		t.Fatalf("应有 2 条踢人日志，实际 %d", logs)
	}
}

// TestKickOverQuotaDedupesSameAccount 同一账号多连接（共用配额）只踢一次
func TestKickOverQuotaDedupesSameAccount(t *testing.T) {
	calls := 0
	got := kickOverQuota(
		[]string{"shared", "shared", "", "shared"},
		func(string) quotaState { return quotaOf(999, 999) },
		func(string) error { calls++; return nil },
		func(string, ...any) {},
	)
	if calls != 1 {
		t.Fatalf("同一账号应只踢一次，实际调用 %d 次", calls)
	}
	if len(got) != 1 || got[0] != "shared" {
		t.Fatalf("返回应为 [shared]，实际 %v", got)
	}
}

// TestKickOverQuotaKickErrorDoesNotAbort 单个账号踢失败不中断其它账号
func TestKickOverQuotaKickErrorDoesNotAbort(t *testing.T) {
	var mu sync.Mutex
	var attempted []string
	got := kickOverQuota(
		[]string{"a", "b", "c"},
		func(u string) quotaState { return quotaOf(10, 10) },
		func(u string) error {
			mu.Lock()
			defer mu.Unlock()
			attempted = append(attempted, u)
			if u == "b" {
				return errors.New("用户不在线")
			}
			return nil
		},
		func(string, ...any) {},
	)
	if strings.Join(attempted, ",") != "a,b,c" {
		t.Fatalf("三个账号都应被尝试，实际 %v", attempted)
	}
	if strings.Join(got, ",") != "a,c" {
		t.Fatalf("只有成功的算被踢，实际 %v", got)
	}
}

// TestKickOverQuotaEmptyInput 空列表不应 panic，也不应调用任何回调
func TestKickOverQuotaEmptyInput(t *testing.T) {
	calls := 0
	got := kickOverQuota(nil,
		func(string) quotaState { calls++; return quotaState{} },
		func(string) error { calls++; return nil },
		func(string, ...any) { calls++ },
	)
	if got != nil || calls != 0 {
		t.Fatalf("空输入应无副作用，实际 got=%v calls=%d", got, calls)
	}
}

// ---------- Manager 级：在线账号来源 + goroutine 启停 ----------

// newQuotaTestManager 造一个只装配了配额复查所需依赖的 Manager
func newQuotaTestManager(t *testing.T, interval time.Duration) (*Manager, *store.Store, *admin.AdminState) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.NewStore(dir + "/users.json")
	if err != nil {
		t.Fatalf("建 store 失败: %v", err)
	}
	state := admin.NewAdminState("test")
	m := &Manager{userStore: st, adminState: state, quotaInterval: interval}
	return m, st, state
}

func addUser(t *testing.T, st *store.Store, name string, used, max uint64) {
	t.Helper()
	if err := st.Create(&store.User{Username: name, Password: "p", Enabled: true, UsedBytes: used, MaxBytes: max}); err != nil {
		t.Fatalf("建用户 %s 失败: %v", name, err)
	}
}

// TestOnlineUsernames 在线账号来自 adminState（按 VIP 登记，同一账号可多条）
func TestOnlineUsernames(t *testing.T) {
	m, _, state := newQuotaTestManager(t, time.Hour)
	if got := m.onlineUsernames(); len(got) != 0 {
		t.Fatalf("初始应为空，实际 %v", got)
	}
	state.OnConnect("192.168.30.11", "alice", "multi", "192.168.30.11", "1.2.3.4:1")
	state.OnConnect("192.168.30.12", "alice", "multi", "192.168.30.12", "1.2.3.5:2")
	state.OnConnect("192.168.30.13", "bob", "multi", "192.168.30.13", "1.2.3.6:3")
	got := m.onlineUsernames()
	if len(got) != 3 {
		t.Fatalf("应有 3 条在线记录（含重复账号），实际 %v", got)
	}
	state.OnDisconnect("192.168.30.11")
	if got := m.onlineUsernames(); len(got) != 2 {
		t.Fatalf("断开后应剩 2 条，实际 %v", got)
	}
}

// TestUserQuotaReadsStoreCopy 配额快照取自 store（副本，读它不会与计费竞争）
func TestUserQuotaReadsStoreCopy(t *testing.T) {
	m, st, _ := newQuotaTestManager(t, time.Hour)
	addUser(t, st, "alice", 500, 1000)
	q := m.userQuota("alice")
	if !q.Known || q.Used != 500 || q.Max != 1000 || q.OverQuota() {
		t.Fatalf("配额快照不对: %+v", q)
	}
	if q := m.userQuota("nobody"); q.Known {
		t.Fatalf("不存在的账号不应 Known: %+v", q)
	}
	// 计费（AddTraffic）之后再读应看到新值
	st.AddTraffic("alice", 600)
	if q := m.userQuota("alice"); !q.OverQuota() {
		t.Fatalf("累计到 1100/1000 之后应判超限: %+v", q)
	}
}

// TestQuotaWatchdogLifecycle 启停幂等、能真正退出（不泄漏 goroutine / 不挂死）
func TestQuotaWatchdogLifecycle(t *testing.T) {
	m, _, _ := newQuotaTestManager(t, 10*time.Millisecond)

	m.startQuotaWatchdog()
	m.startQuotaWatchdog() // 幂等：第二次不应起第二个 goroutine

	// 等它至少跑过一轮（此时 Kick 会因 dataServer 为 nil 失败，但不应 panic/挂死）
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() { m.stopQuotaWatchdog(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stopQuotaWatchdog 未在 2s 内返回（可能死锁）")
	}

	// 未启动时再停一次也必须安全
	m.stopQuotaWatchdog()
}

// TestQuotaWatchdogKicksOnlineOverQuotaUser 端到端（Manager 级）：
// 在线 + 超限 → 被踢；在线 + 不限量 → 不踢；超限但离线 → 不踢。
//
// 这里把 kick 换成一个可观测的替身：直接调用 kickOverQuota（与 checkQuotaOnce 同一入口），
// 避免依赖真实 dataServer。
func TestQuotaWatchdogKicksOnlineOverQuotaUser(t *testing.T) {
	m, st, state := newQuotaTestManager(t, time.Hour)
	addUser(t, st, "alice", 1000, 1000) // 刚好用尽 → 应踢
	addUser(t, st, "bob", 1<<40, 0)     // 不限量 → 不踢
	addUser(t, st, "carol", 9999, 1000) // 超限但**离线** → 不在在线列表里

	state.OnConnect("192.168.30.11", "alice", "multi", "192.168.30.11", "1.2.3.4:1")
	state.OnConnect("192.168.30.12", "bob", "multi", "192.168.30.12", "1.2.3.5:2")

	var kicked []string
	got := kickOverQuota(m.onlineUsernames(), m.userQuota,
		func(u string) error { kicked = append(kicked, u); return nil },
		func(string, ...any) {})

	if strings.Join(got, ",") != "alice" || strings.Join(kicked, ",") != "alice" {
		t.Fatalf("只应踢 alice，实际 got=%v kicked=%v", got, kicked)
	}
}

// TestResetTrafficRestoresUser 端到端语义（P3 的「恢复路径」）：
// 配额用尽 → 会被踢；管理员重置用量 → 不再被判超限（用户能重新连上）。
//
// 这条测试就是「踢人必须有恢复路径」的守卫：如果哪天有人把 ResetTraffic 删了
// 或者改成语义不一致（例如重置了却仍判超限），这里会红。
func TestResetTrafficRestoresUser(t *testing.T) {
	m, st, state := newQuotaTestManager(t, time.Hour)
	addUser(t, st, "alice", 1000, 1000) // 刚好用尽
	state.OnConnect("192.168.30.11", "alice", "multi", "192.168.30.11", "1.2.3.4:1")

	if !m.userQuota("alice").OverQuota() {
		t.Fatal("初始应判超限")
	}

	var kicked []string
	got := kickOverQuota(m.onlineUsernames(), m.userQuota,
		func(u string) error { kicked = append(kicked, u); return nil },
		func(string, ...any) {})
	if len(got) != 1 {
		t.Fatalf("超限用户应被踢，实际 %v", got)
	}

	// 管理员重置（模拟面板「重置流量」按钮 → store.ResetTraffic）
	if _, err := st.ResetTraffic("alice"); err != nil {
		t.Fatalf("ResetTraffic: %v", err)
	}
	if m.userQuota("alice").OverQuota() {
		t.Fatal("重置后不应再判超限（否则用户永久连不上）")
	}

	kicked = nil
	if got := kickOverQuota(m.onlineUsernames(), m.userQuota,
		func(u string) error { kicked = append(kicked, u); return nil },
		func(string, ...any) {}); len(got) != 0 {
		t.Fatalf("重置后不应再踢，实际 %v", got)
	}
}

// TestCheckQuotaOnceWithoutDataServer 未运行时（dataServer 为 nil）复查不得 panic
func TestCheckQuotaOnceWithoutDataServer(t *testing.T) {
	m, st, state := newQuotaTestManager(t, time.Hour)
	addUser(t, st, "alice", 2000, 1000)
	state.OnConnect("192.168.30.11", "alice", "multi", "192.168.30.11", "1.2.3.4:1")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("未运行时复查不应 panic: %v", r)
		}
	}()
	if got := m.checkQuotaOnce(); len(got) != 0 {
		t.Fatalf("Kick 失败时不应把账号算作已踢，实际 %v", got)
	}
}
