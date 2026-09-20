package admin

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"vpn-server/cert"

	"vpn-server/config"
	"vpn-server/store"
)

//go:embed static
var staticFiles embed.FS

var devMode = os.Getenv("HY_DEV") == "1"

type Manager interface {
	Start() error
	Stop() error
	Restart() error
	Status() config.ServerStatus
	GetConfig() *config.ServerConfig
	UpdateConfig(*config.ServerConfig) error
	Kick(username string) error
	// KickVIP 只踢掉某个 VIP 对应的那一个连接 ——
	// 同一账号被多个客户端共用时，面板需要能按连接精确踢出。
	KickVIP(vip string) error
	CertManager() *cert.Manager
}

type Server struct {
	addr    string
	state   *AdminState
	users   *store.Store
	mgr     Manager
	httpSrv *http.Server

	sessions *SessionManager
	limiter  *loginLimiter

	// ⭐ 安全审计 S4：/api/setup 单独限流（原来是完全不限流的未鉴权接口）
	setupLimiter *loginLimiter

	// ⭐ 安全审计 S5：客户端 IP 解析策略（默认不信任任何转发头）
	ipResolver *ipResolver

	// ⭐ 安全审计 S4：允许的 Host 白名单（防 DNS rebinding）
	// key 为小写主机名（不含端口）
	extraHosts map[string]bool

	geoFilter *GeoFilter

	// ⭐ 新增
	metrics *MetricsCollector

	logControl      func(bool)
	priorityControl func(bool)
}

func NewServer(addr string, state *AdminState, users *store.Store, mgr Manager) *Server {
	resolver := newIPResolver(os.Getenv("HY_TRUSTED_PROXIES"))
	if len(resolver.trusted) > 0 {
		log.Printf("🔐 [安全] 已配置受信反向代理 %d 条，仅对这些来源解析 X-Forwarded-For", len(resolver.trusted))
	} else {
		log.Printf("🔐 [安全] 未配置 HY_TRUSTED_PROXIES，将忽略所有转发头（使用 TCP 对端地址）")
	}

	extraHosts := make(map[string]bool)
	for _, h := range strings.Split(os.Getenv("HY_ADMIN_HOSTS"), ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			extraHosts[h] = true
		}
	}

	s := &Server{
		addr:         addr,
		state:        state,
		users:        users,
		mgr:          mgr,
		sessions:     NewSessionManager(24 * time.Hour),
		limiter:      newLoginLimiter(),
		setupLimiter: newLoginLimiter(),
		ipResolver:   resolver,
		extraHosts:   extraHosts,
		metrics:      NewMetricsCollector(720), // ⭐ 1 小时 = 720 个点
	}
	s.refreshGeoFilter()
	s.metrics.Start(state) // ⭐ 启动采样
	return s
}

func (s *Server) SetLogControl(fn func(bool)) {
	s.logControl = fn
}

// ⭐ 设置优先级回调
func (s *Server) SetPriorityControl(fn func(bool)) {
	s.priorityControl = fn
}

func (s *Server) refreshGeoFilter() {
	mode, countries, blockPrivate := s.users.GetGeoConfig()
	// ⭐ 安全审计 S5：把不可伪造的 IP 解析策略注入地理围栏
	s.geoFilter = NewGeoFilterWithResolver(mode, countries, blockPrivate, s.ipResolver)
}

// buildHandler 构造完整的 HTTP 处理链。
// 抽成独立方法是为了让测试可以直接拿到 handler（Start 只会 ListenAndServe）。
func (s *Server) buildHandler() (http.Handler, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/init-status", s.handleInitStatus)
	mux.HandleFunc("/api/setup", s.handleSetup)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.auth(s.handleLogout))
	mux.HandleFunc("/api/me", s.auth(s.handleMe))
	mux.HandleFunc("/api/change-password", s.auth(s.handleChangePassword))

	mux.HandleFunc("/api/server/status", s.auth(s.handleServerStatus))
	mux.HandleFunc("/api/server/config", s.auth(s.handleServerConfig))
	mux.HandleFunc("/api/server/start", s.auth(s.handleServerStart))
	mux.HandleFunc("/api/server/stop", s.auth(s.handleServerStop))
	mux.HandleFunc("/api/server/restart", s.auth(s.handleServerRestart))

	mux.HandleFunc("/api/users", s.auth(s.handleUsers))
	mux.HandleFunc("/api/users/", s.auth(s.handleUserByName))
	mux.HandleFunc("/api/clients", s.auth(s.handleClients))
	mux.HandleFunc("/api/clients/kick", s.auth(s.handleKick))
	mux.HandleFunc("/api/events", s.auth(s.handleEvents))
	// ⚠️ /api/global-password 已移除：全局密码（单用户模式）不再支持，
	//    所有客户端必须以「用户名:密码」认证，与「用户管理」一一对应。
	mux.HandleFunc("/api/panel/geo", s.auth(s.handlePanelGeo))
	mux.HandleFunc("/api/panel/performance", s.auth(s.handlePanelPerformance))
	mux.HandleFunc("/api/metrics", s.auth(s.handleMetrics))
	mux.HandleFunc("/api/cert/status", s.auth(s.handleCertStatus))
	mux.HandleFunc("/api/cert/config", s.auth(s.handleCertConfig))
	mux.HandleFunc("/api/cert/regenerate", s.auth(s.handleCertRegenerate))
	if devMode {
		dir := getStaticDir()
		log.Printf("🔧 [DEV] 静态资源从磁盘读取: %s", dir)
		mux.Handle("/", http.FileServer(http.Dir(dir)))
	} else {
		staticSub, err := fs.Sub(staticFiles, "static")
		if err != nil {
			return nil, fmt.Errorf("embed static: %w", err)
		}
		mux.Handle("/", http.FileServer(http.FS(staticSub)))
	}

	var handler http.Handler = mux
	if s.geoFilter != nil && s.geoFilter.mode != "off" {
		handler = s.geoFilter.Middleware(handler)
		log.Printf("🛡️ [地理围栏] %s", s.geoFilter.Describe())
	} else {
		log.Printf("🛡️ [地理围栏] 已关闭")
	}

	// ⭐ 安全审计 S4：
	//   最外层是「写请求护栏」（Content-Type / Origin / Host 校验），
	//   再外层是安全响应头 —— 即使请求被拒绝也会带上安全头。
	handler = s.guardWriteRequests(handler)
	handler = s.securityHeaders(handler)

	return handler, nil
}

func (s *Server) Start() error {
	handler, err := s.buildHandler()
	if err != nil {
		return err
	}

	s.httpSrv = &http.Server{
		Addr:              s.addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	// ⭐ 安全审计 S4：面板监听在非回环地址时给出明确的安全提示
	if !isLoopbackAddr(s.addr) {
		log.Printf("⚠️ [安全] 管理面板绑定在 %s（非回环地址）。", s.addr)
		log.Printf("     请确保它不暴露在公网；建议通过 SSH 隧道 / VPN 访问，")
		log.Printf("     并考虑设置 HY_ADMIN_HOSTS 限定允许的访问域名。")
	}

	log.Printf("┌──────────────────────────────────────────┐")
	log.Printf("│ 🖥️  Web 管理后台已启动                     │")
	log.Printf("│    地址: http://%s", s.addr)
	log.Printf("│    账户: %s", s.users.GetAdminUsername())
	log.Printf("│    会话有效期: 24 小时（硬上限，不再无限续期）│")
	log.Printf("└──────────────────────────────────────────┘")

	return s.httpSrv.ListenAndServe()
}

// isLoopbackAddr 判断监听地址是否为回环地址
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" || host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}

// securityHeaders ⭐ 安全审计 S4/S13：
// 面板原来没有任何安全响应头，缺失 CSP 与 X-Frame-Options
// 意味着页面可被 iframe 套嵌（点击劫持），且没有纵深防御。
//
// ⚠️ CSP 必须与面板**当前的技术形态**匹配，否则会把面板打白：
//
//  1. admin/static/index.html 通过 CDN 加载 Vue / vue-i18n / Chart.js
//     （unpkg.com、cdn.jsdelivr.net），所以 script-src 必须列出这两个来源。
//     → 建议后续把这三个库**放到本地**（vendor），即可去掉外部来源；
//     顺带解决「无外网时面板打不开」的问题，并消除 CDN 供应链风险
//     （当前没有 SRI 校验）。
//  2. 面板用的是 **in-DOM 模板 + Vue 完整版（含运行时编译器）**，
//     Vue 编译模板与 vue-i18n 编译消息都依赖 `new Function`，
//     因此 script-src 必须包含 'unsafe-eval'。
//     → 想彻底去掉 'unsafe-eval'，需要改成预编译的 SFC 构建
//     （即客户端那样的 Vite 管线 + 本地产物）。
//
// 其余指令保持收紧：default-src/connect-src 限 'self'，
// frame-ancestors 'none' 防套嵌，base-uri 'none' 防 base 注入。
// 这条 CSP 现在仍能挡住的：内联 <script> 注入、未列出的第三方脚本来源、
// 数据外带（connect-src）、点击劫持。
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"font-src 'self' data:; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'none'; "+
				"form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// hostAllowed ⭐ 安全审计 S4：防止 DNS rebinding。
//
// 面板不校验 Host，攻击者页面可以把一个域名解析到 127.0.0.1，
// 之后浏览器就认为它与面板「同源」，可以自由调用面板 API。
// DNS rebinding 必须依赖一个域名，所以这里放行 IP 字面量与 localhost，
// 域名则必须由 HY_ADMIN_HOSTS 显式声明（供反向代理场景使用）。
func (s *Server) hostAllowed(r *http.Request) bool {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "" {
		return false
	}
	if host == "localhost" || s.extraHosts[host] {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return false
}

// sameOrigin 判断 Origin 是否与 Host 同源
func sameOrigin(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// guardWriteRequests ⭐ 安全审计 S4：保护所有写操作，阻断 CSRF 与 DNS rebinding。
//
// 两道检查：
//  1. 带 body 的请求必须是 application/json。浏览器不允许跨站「简单请求」
//     使用 application/json（会触发预检，而这里不返回任何 CORS 头），
//     因此这一条就挡住了表单/跨站 fetch 的 CSRF。
//  2. 若带 Origin，必须与 Host 同源；Host 本身也必须是 IP 字面量、
//     localhost 或白名单域名，从而阻断 DNS rebinding。
func (s *Server) guardWriteRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if !s.hostAllowed(r) {
				log.Printf("🚫 [安全] 拒绝 Host=%q 的写请求（疑似 DNS rebinding）", r.Host)
				http.Error(w, `{"error":"invalid host"}`, http.StatusForbidden)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && !sameOrigin(origin, r.Host) {
				log.Printf("🚫 [安全] 拒绝跨源写请求: Origin=%q Host=%q", origin, r.Host)
				http.Error(w, `{"error":"cross-origin request rejected"}`, http.StatusForbidden)
				return
			}
			if r.ContentLength != 0 {
				ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
				if !strings.HasPrefix(ct, "application/json") {
					http.Error(w, `{"error":"Content-Type must be application/json"}`,
						http.StatusUnsupportedMediaType)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) Stop() error {
	if s.httpSrv != nil {
		return s.httpSrv.Close()
	}
	return nil
}

// tokenFrom 提取会话令牌。
//
// ⭐ 安全审计 S13：除 SSE（EventSource 无法设置 Authorization 头）外，
// 一律只从请求头取令牌 —— 把长期令牌放进 URL 会经日志、Referer、
// 浏览器历史泄露出去。
func (s *Server) tokenFrom(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if r.URL.Path == "/api/events" {
		// EventSource 不支持自定义头，这是唯一的例外
		return r.URL.Query().Get("token")
	}
	return ""
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.sessions.Validate(s.tokenFrom(r)) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) clientIP(r *http.Request) string {
	// ⭐ 安全审计 S5：默认只用 TCP 对端地址，不再无条件信任 XFF
	return s.ipResolver.ClientIP(r)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := s.clientIP(r)
	if !s.limiter.Allow(ip) {
		http.Error(w, `{"error":"登录失败次数过多，请 5 分钟后再试"}`, http.StatusTooManyRequests)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	if !s.users.VerifyAdmin(body.Username, body.Password) {
		s.limiter.RecordFail(ip)
		log.Printf("🚫 [管理] 登录失败: user=%q from %s", body.Username, ip)
		http.Error(w, `{"error":"用户名或密码错误"}`, http.StatusUnauthorized)
		return
	}

	s.limiter.Reset(ip)
	token := s.sessions.Create()
	log.Printf("✅ [管理] 登录成功: user=%s from %s（当前会话数 %d）",
		body.Username, ip, s.sessions.Count())

	writeJSON(w, map[string]interface{}{
		"token":     token,
		"username":  body.Username,
		"expiresIn": int(s.sessions.TTL.Seconds()),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessions.Delete(s.tokenFrom(r))
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{
		"username": s.users.GetAdminUsername(),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"version": ServerVersion})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 防止用已登录会话离线爆破原密码
	ip := s.clientIP(r)
	if !s.limiter.Allow(ip) {
		http.Error(w, `{"error":"尝试次数过多，请 5 分钟后再试"}`, http.StatusTooManyRequests)
		return
	}

	var body struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if len(body.NewPassword) < 6 {
		http.Error(w, `{"error":"新密码至少 6 位"}`, http.StatusBadRequest)
		return
	}
	if err := s.users.ChangeAdminPassword(body.OldPassword, body.NewPassword); err != nil {
		s.limiter.RecordFail(ip)
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	s.limiter.Reset(ip)

	// ⭐ 安全审计 S13：改密码通常意味着「怀疑凭证泄露」，
	//    旧令牌必须立即全部失效。前端本来就会在改密后主动登出
	//    （javascript.js 的 changePassword → doLogout），
	//    所以这里不签发新令牌，避免留下一个没人使用的有效会话。
	s.sessions.DeleteAll()
	log.Printf("🔑 [管理] 管理员密码已修改，已吊销全部会话（from %s）", ip)

	writeJSON(w, map[string]string{"status": "ok"})
}

// ---------- 性能与日志 ----------

func (s *Server) handlePanelPerformance(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		lowPerf, logEnabled, highPriority, latencyMode := s.users.GetPerformanceConfig()
		writeJSON(w, map[string]interface{}{
			"lowPerformanceMode": lowPerf,
			"logEnabled":         logEnabled,
			"highPriority":       highPriority,
			"latencyMode":        latencyMode,
		})

	case http.MethodPut:
		var body struct {
			LowPerformanceMode bool   `json:"lowPerformanceMode"`
			LogEnabled         bool   `json:"logEnabled"`
			HighPriority       bool   `json:"highPriority"`
			LatencyMode        string `json:"latencyMode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if err := s.users.SetPerformanceConfig(body.LowPerformanceMode, body.LogEnabled, body.HighPriority, body.LatencyMode); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}

		if s.logControl != nil {
			s.logControl(body.LogEnabled)
		}
		if s.priorityControl != nil {
			s.priorityControl(body.HighPriority)
		}

		if body.LogEnabled {
			log.Printf("📝 日志已开启")
		}

		log.Printf("⚙️ 性能配置已更新: lowPerformanceMode=%v, logEnabled=%v, highPriority=%v, latencyMode=%s",
			body.LowPerformanceMode, body.LogEnabled, body.HighPriority, body.LatencyMode)
		writeJSON(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------- 地理围栏 ----------

func (s *Server) handlePanelGeo(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		mode, countries, blockPrivate := s.users.GetGeoConfig()
		writeJSON(w, map[string]interface{}{
			"mode":         mode,
			"countries":    countries,
			"blockPrivate": blockPrivate,
		})
	case http.MethodPut:
		var body struct {
			Mode         string   `json:"mode"`
			Countries    []string `json:"countries"`
			BlockPrivate bool     `json:"blockPrivate"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if err := s.users.SetGeoConfig(body.Mode, body.Countries, body.BlockPrivate); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		s.refreshGeoFilter()
		log.Printf("🛡️ [地理围栏] 已更新: %s", s.geoFilter.Describe())
		writeJSON(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------- 服务端管理 ----------

func (s *Server) handleServerStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.mgr.Status())
}

func (s *Server) handleServerConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.mgr.GetConfig())
	case http.MethodPut:
		var cfg config.ServerConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if err := s.mgr.UpdateConfig(&cfg); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleServerStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.mgr.Start(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleServerStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.mgr.Stop(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) handleServerRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.mgr.Restart(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// ---------- 用户与客户端 ----------

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.state.Snapshot().Clients)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.users.List())
	case http.MethodPost:
		var u store.User
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if u.Username == "" || u.Password == "" {
			http.Error(w, `{"error":"username and password required"}`, http.StatusBadRequest)
			return
		}
		if err := s.users.Create(&u); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, u)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUserByName(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if username == "" {
		http.Error(w, "missing username", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		u, ok := s.users.Get(username)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, u)
	case http.MethodPut:
		var updates store.User
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		err := s.users.Update(username, func(u *store.User) {
			if updates.Password != "" {
				u.Password = updates.Password
			}
			u.Enabled = updates.Enabled
			u.MaxBytes = updates.MaxBytes
			u.Note = updates.Note
			u.ExpireAt = updates.ExpireAt
		})
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	case http.MethodDelete:
		if err := s.users.Delete(username); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusNotFound)
			return
		}
		_ = s.mgr.Kick(username)
		writeJSON(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleKick 踢出在线连接。
//
// ⭐ 一个账号允许被多个客户端共用，所以支持两种粒度：
//   - 带 vip 参数：只踢掉这一个连接（面板在线列表每行一个连接）
//   - 只带 username：踢掉该账号的全部连接
func (s *Server) handleKick(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.URL.Query().Get("username")
	vip := r.URL.Query().Get("vip")

	if vip != "" {
		if err := s.mgr.KickVIP(vip); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "ok", "vip": vip, "username": username})
		return
	}

	if username == "" {
		http.Error(w, "missing username or vip", http.StatusBadRequest)
		return
	}
	if err := s.mgr.Kick(username); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "username": username})
}

// handleGlobalPassword 已随「全局密码（单用户模式）」一起移除。
// 现在所有客户端都必须在面板的「用户管理」里有对应账户，
// 并使用「用户名 + 密码」认证。

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	push := func() bool {
		snap := s.state.Snapshot()
		payload := map[string]interface{}{
			"clients": snap.Clients,
			"server":  s.mgr.Status(),
		}
		data, _ := json.Marshal(payload)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if !push() {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !push() {
				return
			}
		}
	}
}

func getStaticDir() string {
	if dir := os.Getenv("HY_STATIC_DIR"); dir != "" {
		return dir
	}
	candidates := []string{
		"admin/static",
		"./static",
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "index.html")); err == nil {
			return c
		}
	}
	return "admin/static"
}

var _ = net.ParseIP

// ⭐ 新增
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.metrics.Snapshot())
}

// ⭐ 查询初始化状态（不鉴权）
func (s *Server) handleInitStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"initialized": s.users.HasAdmin(),
	})
}

// ⭐ 首次初始化（不鉴权，但已初始化时拒绝）
//
// ⭐ 安全审计 S4：这是唯一一个未鉴权的写接口，必须格外小心：
//   - 检查与写入必须是**原子**的（原实现是 HasAdmin() 后 SetAdmin()，存在 TOCTOU 抢注）；
//   - 必须有独立限流（原来完全不限流）；
//   - 依赖 guardWriteRequests 的 Content-Type / Origin / Host 校验阻断 CSRF 与 DNS rebinding。
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := s.clientIP(r)
	if !s.setupLimiter.Allow(ip) {
		http.Error(w, `{"error":"尝试次数过多，请稍后再试"}`, http.StatusTooManyRequests)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	body.Username = strings.TrimSpace(body.Username)
	if len(body.Username) < 3 {
		s.setupLimiter.RecordFail(ip)
		http.Error(w, `{"error":"用户名至少 3 位"}`, http.StatusBadRequest)
		return
	}
	if len(body.Password) < 6 {
		s.setupLimiter.RecordFail(ip)
		http.Error(w, `{"error":"密码至少 6 位"}`, http.StatusBadRequest)
		return
	}

	// 用户名不能与已存在的多用户重名（避免后续认证/踢人逻辑混淆）
	if _, exists := s.users.Get(body.Username); exists {
		s.setupLimiter.RecordFail(ip)
		http.Error(w, `{"error":"用户名已被占用"}`, http.StatusConflict)
		return
	}

	// ⭐ 原子化：检查「是否已初始化」与写入在同一把锁内完成
	if err := s.users.SetAdminIfUninitialized(body.Username, body.Password); err != nil {
		if errors.Is(err, store.ErrAlreadyInitialized) {
			log.Printf("🚫 [安全] 拒绝重复初始化请求 (from %s)", ip)
			http.Error(w, `{"error":"服务端已初始化"}`, http.StatusForbidden)
			return
		}
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	log.Printf("✅ [管理] 管理员已通过 Web 面板初始化: %s (from %s)", body.Username, ip)
	writeJSON(w, map[string]string{"status": "ok"})
}

// ⭐ 证书状态
func (s *Server) handleCertStatus(w http.ResponseWriter, r *http.Request) {
	mgr := s.mgr.(interface{ CertManager() *cert.Manager })
	info, err := mgr.CertManager().Info()
	if err != nil {
		writeJSON(w, map[string]interface{}{
			"ok":    false,
			"error": err.Error(),
			"mode":  string(mgr.CertManager().Mode()),
		})
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok":   true,
		"info": info,
	})
}

// ⭐ 证书配置读写
func (s *Server) handleCertConfig(w http.ResponseWriter, r *http.Request) {
	mgr := s.mgr.(interface{ CertManager() *cert.Manager })
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, mgr.CertManager().Config())
	case http.MethodPut:
		var req cert.Config
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
			return
		}
		if err := mgr.CertManager().UpdateConfig(&req); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ⭐ 重新生成自签证书
func (s *Server) handleCertRegenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mgr := s.mgr.(interface{ CertManager() *cert.Manager })
	if err := mgr.CertManager().Regenerate(); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}
