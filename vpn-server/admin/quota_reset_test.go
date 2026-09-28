package admin

// vpn-server/admin/quota_reset_test.go
//
// ⭐ P3 补丁的「恢复路径」测试：管理员重置账号累计用量。
//
// 为什么值得单独测：`UsedBytes` 是**持久化**的、且**没有自动归零**，
// 而认证与运行期配额复查都以「已用 >= 配额」判用尽 ——
// 缺了这个入口，「按配额踢人」就等于把用户永久锁在门外。

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"vpn-server/config"
	"vpn-server/store"
)

func TestResetTrafficEndpoint(t *testing.T) {
	st, err := store.NewStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := st.SetAdminIfUninitialized("admin", "strong-password"); err != nil {
		t.Fatalf("SetAdminIfUninitialized: %v", err)
	}
	if err := st.Create(&store.User{
		Username: "alice", Password: "p", Enabled: true, MaxBytes: 1000,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	st.AddTraffic("alice", 4096) // 已超限

	srv := NewServer("127.0.0.1:0", NewAdminState("test"), st, &fakeManager{cfg: config.DefaultConfig()})
	h, err := srv.buildHandler()
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}

	do := func(method, path, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:8444"+path, nil)
		r.Host = "127.0.0.1:8444"
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	const path = "/api/users/reset-traffic?username=alice"

	// ① 未认证：这是敏感操作，必须 401
	if rec := do(http.MethodPost, path, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("未认证应 401，实际 %d", rec.Code)
	}

	token := srv.sessions.Create()

	// ② 方法限制
	if rec := do(http.MethodGet, path, token); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET 应 405，实际 %d", rec.Code)
	}

	// ③ 缺 username
	if rec := do(http.MethodPost, "/api/users/reset-traffic", token); rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 username 应 400，实际 %d", rec.Code)
	}

	// ④ 未知用户
	if rec := do(http.MethodPost, "/api/users/reset-traffic?username=nobody", token); rec.Code != http.StatusNotFound {
		t.Fatalf("未知用户应 404，实际 %d", rec.Code)
	}

	// ⑤ 正常重置：返回归零前的值，并且 store 里真的归零
	rec := do(http.MethodPost, path, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("正常重置应 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, `"previousUsedBytes":4096`) {
		t.Fatalf("应返回归零前的值 4096，实际 body=%s", body)
	}
	u, ok := st.Get("alice")
	if !ok || u.UsedBytes != 0 {
		t.Fatalf("store 里应已归零，实际 %+v ok=%v", u, ok)
	}
	// 只清用量：配额/启用状态不动
	if u.MaxBytes != 1000 || !u.Enabled {
		t.Fatalf("重置不应改动配额或启用状态: %+v", u)
	}

	// ⑥ 再次重置（幂等）
	if rec := do(http.MethodPost, path, token); rec.Code != http.StatusOK {
		t.Fatalf("重复重置应 200，实际 %d", rec.Code)
	}
}
