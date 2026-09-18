package admin

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
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

	geoFilter *GeoFilter

	// ⭐ 新增
	metrics *MetricsCollector

	logControl      func(bool)
	priorityControl func(bool)
}

func NewServer(addr string, state *AdminState, users *store.Store, mgr Manager) *Server {
	s := &Server{
		addr:     addr,
		state:    state,
		users:    users,
		mgr:      mgr,
		sessions: NewSessionManager(24 * time.Hour),
		limiter:  newLoginLimiter(),
		metrics:  NewMetricsCollector(720), // ⭐ 1 小时 = 720 个点
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
	s.geoFilter = NewGeoFilter(mode, countries, blockPrivate)
}

func (s *Server) Start() error {
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
	mux.HandleFunc("/api/global-password", s.auth(s.handleGlobalPassword))
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
			return fmt.Errorf("embed static: %w", err)
		}
		mux.Handle("/", http.FileServer(http.FS(staticSub)))
	}

	var handler http.Handler = mux
	if s.geoFilter != nil && s.geoFilter.mode != "off" {
		handler = s.geoFilter.Middleware(mux)
		log.Printf("🛡️ [地理围栏] %s", s.geoFilter.Describe())
	} else {
		log.Printf("🛡️ [地理围栏] 已关闭")
	}

	s.httpSrv = &http.Server{
		Addr:              s.addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("┌──────────────────────────────────────────┐")
	log.Printf("│ 🖥️  Web 管理后台已启动                     │")
	log.Printf("│    地址: http://%s", s.addr)
	log.Printf("│    账户: %s", s.users.GetAdminUsername())
	log.Printf("│    会话有效期: 24 小时                     │")
	log.Printf("└──────────────────────────────────────────┘")

	return s.httpSrv.ListenAndServe()
}

func (s *Server) Stop() error {
	if s.httpSrv != nil {
		return s.httpSrv.Close()
	}
	return nil
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if !s.sessions.Validate(token) {
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

func clientIP(r *http.Request) string {
	return extractClientIP(r)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
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
	log.Printf("✅ [管理] 登录成功: user=%s from %s", body.Username, ip)

	writeJSON(w, map[string]interface{}{
		"token":     token,
		"username":  body.Username,
		"expiresIn": int(s.sessions.TTL.Seconds()),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	s.sessions.Delete(token)
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
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
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

func (s *Server) handleKick(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "missing username", http.StatusBadRequest)
		return
	}
	if err := s.mgr.Kick(username); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"status": "ok", "username": username})
}

func (s *Server) handleGlobalPassword(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]string{"password": s.users.GetGlobalPassword()})
	case http.MethodPut:
		var body struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
			http.Error(w, `{"error":"invalid password"}`, http.StatusBadRequest)
			return
		}
		if err := s.users.SetGlobalPassword(body.Password); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

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
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 已初始化 → 拒绝
	if s.users.HasAdmin() {
		http.Error(w, `{"error":"服务端已初始化"}`, http.StatusForbidden)
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

	body.Username = strings.TrimSpace(body.Username)
	if len(body.Username) < 3 {
		http.Error(w, `{"error":"用户名至少 3 位"}`, http.StatusBadRequest)
		return
	}
	if len(body.Password) < 6 {
		http.Error(w, `{"error":"密码至少 6 位"}`, http.StatusBadRequest)
		return
	}

	// 检查用户名是否和已存在的用户冲突（多用户模式）
	if _, exists := s.users.Get(body.Username); exists {
		http.Error(w, `{"error":"用户名已被占用"}`, http.StatusConflict)
		return
	}

	if err := s.users.SetAdmin(body.Username, body.Password); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	log.Printf("✅ [管理] 管理员已通过 Web 面板初始化: %s", body.Username)
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
