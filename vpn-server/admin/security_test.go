package admin

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"vpn-server/cert"
	"vpn-server/config"
	"vpn-server/store"
)

// fakeManager 满足 Manager 接口的最小实现（集成测试用，不接触真实网络/证书）
type fakeManager struct {
	cfg *config.ServerConfig
}

func (m *fakeManager) Start() error                              { return nil }
func (m *fakeManager) Stop() error                               { return nil }
func (m *fakeManager) Restart() error                            { return nil }
func (m *fakeManager) Status() config.ServerStatus               { return config.ServerStatus{} }
func (m *fakeManager) GetConfig() *config.ServerConfig           { return m.cfg }
func (m *fakeManager) UpdateConfig(c *config.ServerConfig) error { return nil }
func (m *fakeManager) Kick(username string) error                { return nil }
func (m *fakeManager) KickVIP(vip string) error                  { return nil }
func (m *fakeManager) CertManager() *cert.Manager                { return nil }

// TestPanelHTTPHardening 对真实的 handler 链做集成验证：
// 安全响应头、已移除的接口、未鉴权接口的边界。
func TestPanelHTTPHardening(t *testing.T) {
	st, err := store.NewStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := st.SetAdminIfUninitialized("KiNG", "strong-password"); err != nil {
		t.Fatalf("SetAdminIfUninitialized: %v", err)
	}

	srv := NewServer("127.0.0.1:0", NewAdminState("test"), st, &fakeManager{cfg: config.DefaultConfig()})
	h, err := srv.buildHandler()
	if err != nil {
		t.Fatalf("buildHandler: %v", err)
	}

	do := func(method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, "http://127.0.0.1:8444"+path, nil)
		} else {
			r = httptest.NewRequest(method, "http://127.0.0.1:8444"+path, strings.NewReader(body))
		}
		r.Host = "127.0.0.1:8444"
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	t.Run("安全响应头", func(t *testing.T) {
		rec := do(http.MethodGet, "/api/init-status", "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("状态码 = %d", rec.Code)
		}
		for _, k := range []string{
			"Content-Security-Policy", "X-Frame-Options",
			"X-Content-Type-Options", "Referrer-Policy",
		} {
			if rec.Header().Get(k) == "" {
				t.Fatalf("缺少安全响应头 %s", k)
			}
		}
		if xfo := rec.Header().Get("X-Frame-Options"); xfo != "DENY" {
			t.Fatalf("X-Frame-Options = %q，应为 DENY", xfo)
		}
	})

	// ⭐ CSP 与面板实际引用必须一致，否则会把面板打白。
	// 这条测试专门防止「加了 CSP 但没同步放行 CDN / unsafe-eval」这类回归。
	t.Run("CSP必须覆盖面板引用的所有脚本来源", func(t *testing.T) {
		rec := do(http.MethodGet, "/api/init-status", "", nil)
		csp := rec.Header().Get("Content-Security-Policy")

		// 从 index.html 里提取所有外部 <script src="https://...">
		idx, err := staticFiles.ReadFile("static/index.html")
		if err != nil {
			t.Fatalf("读取内嵌 index.html: %v", err)
		}
		hosts := map[string]bool{}
		for _, m := range regexp.MustCompile(`<script[^>]+src="https://([^/"]+)`).
			FindAllStringSubmatch(string(idx), -1) {
			hosts[m[1]] = true
		}
		if len(hosts) == 0 {
			t.Fatal("未在 index.html 中找到任何外部脚本？测试本身的假设已失效，请检查")
		}
		for host := range hosts {
			if !strings.Contains(csp, "https://"+host) {
				t.Fatalf("CSP 未放行面板实际引用的脚本来源 %s，会导致面板白屏。CSP=%s", host, csp)
			}
		}

		// 面板用 in-DOM 模板 + Vue 完整版，编译模板依赖 new Function
		if !strings.Contains(csp, "'unsafe-eval'") {
			t.Fatalf("CSP 缺少 'unsafe-eval'，Vue 运行时模板编译会被阻止，面板会白屏。CSP=%s", csp)
		}
		if !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("CSP 必须保留 frame-ancestors 'none' 以防点击劫持。CSP=%s", csp)
		}
	})

	t.Run("未鉴权接口", func(t *testing.T) {
		// /api/version 与 /api/init-status 无需鉴权
		if rec := do(http.MethodGet, "/api/version", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("/api/version 状态码 = %d", rec.Code)
		}
		// 受保护接口无令牌必须 401
		for _, p := range []string{"/api/users", "/api/server/status", "/api/metrics"} {
			if rec := do(http.MethodGet, p, "", nil); rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s 无令牌应为 401，实际 %d", p, rec.Code)
			}
		}
	})

	t.Run("全局密码接口已移除", func(t *testing.T) {
		// 该路由不再注册；由于注册了 "/" 静态文件处理器，
		// 未匹配的路径会落到文件服务（404），绝不会返回密码。
		rec := do(http.MethodGet, "/api/global-password", "",
			map[string]string{"Authorization": "Bearer 无效令牌"})
		if rec.Code == http.StatusOK {
			t.Fatalf("/api/global-password 不应存在，实际返回 200")
		}
		if strings.Contains(rec.Body.String(), "password") {
			t.Fatalf("响应体不应含 password 字段: %s", rec.Body.String())
		}
	})

	t.Run("已初始化时 setup 被拒", func(t *testing.T) {
		rec := do(http.MethodPost, "/api/setup",
			`{"username":"attacker","password":"hacked123"}`,
			map[string]string{"Content-Type": "application/json"})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("/api/setup 应返回 403，实际 %d（body=%s）", rec.Code, rec.Body.String())
		}
		if st.VerifyAdmin("attacker", "hacked123") {
			t.Fatal("攻击者账户不应被创建")
		}
	})

	t.Run("登录限流生效", func(t *testing.T) {
		// 同一 IP 连续失败 5 次后应被限流（XFF 已不再被信任，
		// 因此伪造 XFF 也无法绕过）
		var last *httptest.ResponseRecorder
		for i := 0; i < 7; i++ {
			last = do(http.MethodPost, "/api/login",
				`{"username":"KiNG","password":"wrong"}`,
				map[string]string{
					"Content-Type":    "application/json",
					"X-Forwarded-For": "127.0.0." + string(rune('1'+i)), // 试图绕过
				})
		}
		if last.Code != http.StatusTooManyRequests {
			t.Fatalf("连续失败后应返回 429，实际 %d", last.Code)
		}
	})
}

// TestClientIPIgnoresForwardedHeadersByDefault 验证安全审计 S5：
// 未配置受信代理时，X-Forwarded-For / X-Real-IP 必须被完全忽略。
//
// 修复前：攻击者发 `X-Forwarded-For: 127.0.0.1` 就能被判定为 loopback
// 而绕过地理围栏；每次换一个值即可绕过登录失败限流。
func TestClientIPIgnoresForwardedHeadersByDefault(t *testing.T) {
	r := newIPResolver("")

	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	req.RemoteAddr = "203.0.113.7:51234"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")

	if got := r.ClientIP(req); got != "203.0.113.7" {
		t.Fatalf("默认必须忽略转发头，得到 %q，期望 203.0.113.7", got)
	}
}

// TestClientIPUsesXFFBehindTrustedProxy 验证配置了受信代理后仍能正常工作，
// 并且取的是「从右往左第一个非受信地址」而不是最左边（可伪造的）那个。
func TestClientIPUsesXFFBehindTrustedProxy(t *testing.T) {
	r := newIPResolver("10.0.0.0/8, 192.168.1.1")

	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	req.RemoteAddr = "10.0.0.5:4433"
	// 最左边是客户端可随意伪造的；真实客户端是 198.51.100.9
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.9, 10.0.0.5")

	if got := r.ClientIP(req); got != "198.51.100.9" {
		t.Fatalf("受信代理后应取最右侧非受信地址，得到 %q，期望 198.51.100.9", got)
	}

	// 对端不是受信代理时，转发头依然必须被忽略
	req2 := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	req2.RemoteAddr = "203.0.113.7:1111"
	req2.Header.Set("X-Forwarded-For", "127.0.0.1")
	if got := r.ClientIP(req2); got != "203.0.113.7" {
		t.Fatalf("非受信对端的转发头必须被忽略，得到 %q", got)
	}
}

// TestSessionAbsoluteLifetime 验证安全审计 S13：
// 即使持续访问（滑动续期），会话也不能越过绝对上限。
func TestSessionAbsoluteLifetime(t *testing.T) {
	sm := NewSessionManager(60 * time.Millisecond)
	sm.MaxLifetime = 150 * time.Millisecond

	token := sm.Create()
	if !sm.Validate(token) {
		t.Fatal("新建会话应当有效")
	}

	// 持续续期，直到超过绝对上限
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		sm.Validate(token)
	}

	if sm.Validate(token) {
		t.Fatal("超过 MaxLifetime 后会话必须失效（修复前可无限续期）")
	}
}

// TestSessionDeleteAllRevokesEverything 验证改密码后旧令牌全部失效
func TestSessionDeleteAllRevokesEverything(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	tokens := []string{sm.Create(), sm.Create(), sm.Create()}

	sm.DeleteAll()

	for i, tok := range tokens {
		if sm.Validate(tok) {
			t.Fatalf("DeleteAll 之后第 %d 个令牌仍然有效", i)
		}
	}
	if n := sm.Count(); n != 0 {
		t.Fatalf("DeleteAll 之后会话数应为 0，实际 %d", n)
	}
}

// TestGuardWriteRejectsCSRFishRequests 验证安全审计 S4 的写请求护栏
func TestGuardWriteRejectsCSRFishRequests(t *testing.T) {
	s := &Server{extraHosts: map[string]bool{}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.guardWriteRequests(next)

	cases := []struct {
		name       string
		method     string
		host       string
		origin     string
		ct         string
		bodyLen    int64
		wantStatus int
	}{
		{"正常面板请求", http.MethodPost, "127.0.0.1:8444", "http://127.0.0.1:8444", "application/json", 10, http.StatusOK},
		{"表单式跨站(纯文本)", http.MethodPost, "127.0.0.1:8444", "", "text/plain", 10, http.StatusUnsupportedMediaType},
		{"跨源请求被拒", http.MethodPost, "127.0.0.1:8444", "http://evil.example", "application/json", 10, http.StatusForbidden},
		{"DNS rebinding(域名 Host)", http.MethodPost, "evil.example:8444", "", "application/json", 10, http.StatusForbidden},
		{"无 body 的登出", http.MethodPost, "127.0.0.1:8444", "", "", 0, http.StatusOK},
		{"IP 字面量 Host 放行", http.MethodPost, "192.168.1.5:8444", "", "application/json", 5, http.StatusOK},
		{"GET 不受影响", http.MethodGet, "evil.example:8444", "", "", 0, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://"+tc.host+"/api/x", nil)
			req.Host = tc.host
			req.ContentLength = tc.bodyLen
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.ct != "" {
				req.Header.Set("Content-Type", tc.ct)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("状态码 = %d，期望 %d", rec.Code, tc.wantStatus)
			}
		})
	}
}
