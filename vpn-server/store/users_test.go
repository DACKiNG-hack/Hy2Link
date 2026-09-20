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
