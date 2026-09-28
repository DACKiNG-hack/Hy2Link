package store

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// TestSetAdminIfUninitializedIsAtomic 验证安全审计 S4：
// 并发抢注时**只能有一个**请求成功，从根上消除 TOCTOU。
//
// 用 `go test -race` 运行同样能验证没有数据竞争。
func TestSetAdminIfUninitializedIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	const goroutines = 64
	var success int32
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // 尽量同时冲进去
			if err := s.SetAdminIfUninitialized("admin", "password123"); err == nil {
				atomic.AddInt32(&success, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := atomic.LoadInt32(&success); got != 1 {
		t.Fatalf("应当只有 1 个请求初始化成功，实际 %d 个（存在 TOCTOU 抢注）", got)
	}
	if !s.HasAdmin() {
		t.Fatal("初始化后 HasAdmin() 应为 true")
	}
	if !s.VerifyAdmin("admin", "password123") {
		t.Fatal("刚初始化的凭据应当可以验证通过")
	}
}

// TestVerifyAdminRejectsWrongCredentials 基本回归
func TestVerifyAdminRejectsWrongCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.HasAdmin() {
		t.Fatal("新建的存储不应当已有管理员")
	}
	if s.VerifyAdmin("", "") {
		t.Fatal("空凭据必须被拒绝")
	}
	if err := s.SetAdminIfUninitialized("KiNG", "s3cret-pass"); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	if s.VerifyAdmin("KiNG", "wrong") {
		t.Fatal("错误口令必须被拒绝")
	}
	if s.VerifyAdmin("king", "s3cret-pass") {
		t.Fatal("用户名大小写不一致必须被拒绝")
	}
	if !s.VerifyAdmin("KiNG", "s3cret-pass") {
		t.Fatal("正确凭据必须通过")
	}
}

// TestResetTraffic 验证 P3 补丁要求的「恢复路径」：
// 用量是持久化的、且不会自动归零，所以必须有管理员重置入口。
//
// 覆盖：返回值、归零、**立即落盘**（重开 store 仍是 0）、幂等、不动其它字段、未知用户报错。
func TestResetTraffic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s.Create(&User{
		Username: "alice", Password: "p", Enabled: false,
		MaxBytes: 1000, UsedBytes: 0, Note: "备注",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// 用量累加（模拟中继转发计数）
	s.AddTraffic("alice", 700)
	s.AddTraffic("alice", 500) // 1200 > 1000，已超限

	if u, _ := s.Get("alice"); u.UsedBytes != 1200 {
		t.Fatalf("累加后 UsedBytes = %d，期望 1200", u.UsedBytes)
	}

	prev, err := s.ResetTraffic("alice")
	if err != nil {
		t.Fatalf("ResetTraffic: %v", err)
	}
	if prev != 1200 {
		t.Fatalf("应返回归零前的值 1200，实际 %d", prev)
	}

	u, _ := s.Get("alice")
	if u.UsedBytes != 0 {
		t.Fatalf("重置后 UsedBytes 应为 0，实际 %d", u.UsedBytes)
	}
	// 只清用量：配额 / 启用状态 / 备注 / 密码都不动
	if u.MaxBytes != 1000 || u.Enabled || u.Note != "备注" || u.Password != "p" {
		t.Fatalf("重置不应改动其它字段: %+v", u)
	}

	// 幂等
	if prev, err := s.ResetTraffic("alice"); err != nil || prev != 0 {
		t.Fatalf("重复重置应成功且 prev=0，实际 prev=%d err=%v", prev, err)
	}

	// ⭐ 立即落盘：不等 FlushLoop，重开 store 也必须是 0
	s2, err := NewStore(path)
	if err != nil {
		t.Fatalf("重新打开 store: %v", err)
	}
	if u2, ok := s2.Get("alice"); !ok || u2.UsedBytes != 0 {
		t.Fatalf("重置必须立即落盘（重开后 UsedBytes 应为 0），实际 %+v ok=%v", u2, ok)
	}

	// 未知用户
	if _, err := s.ResetTraffic("nobody"); err == nil {
		t.Fatal("未知用户必须返回错误")
	}
}
