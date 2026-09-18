package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ErrUserExists   = errors.New("用户已存在")
	ErrUserNotFound = errors.New("用户不存在")
)

type User struct {
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Enabled   bool      `json:"enabled"`
	MaxBytes  uint64    `json:"maxBytes"`
	UsedBytes uint64    `json:"usedBytes"`
	CreatedAt time.Time `json:"createdAt"`
	ExpireAt  time.Time `json:"expireAt"`
	Note      string    `json:"note"`
}

type Config struct {
	GlobalPassword string  `json:"globalPassword"`
	AdminUsername  string  `json:"adminUsername"`
	AdminPassword  string  `json:"adminPassword"`
	Users          []*User `json:"users"`

	// 地理围栏
	GeoMode         string   `json:"geoMode"`
	GeoCountries    []string `json:"geoCountries"`
	GeoBlockPrivate bool     `json:"geoBlockPrivate"`

	// 性能与日志
	LowPerformanceMode *bool   `json:"lowPerformanceMode,omitempty"`
	LogEnabled         *bool   `json:"logEnabled,omitempty"`
	HighPriority       *bool   `json:"highPriority,omitempty"`
	LatencyMode        *string `json:"latencyMode,omitempty"` // ⭐ "low" / "balanced" / "throughput"
}

type Store struct {
	mu       sync.RWMutex
	filePath string
	cfg      *Config
	userMap  map[string]*User
	dirty    bool
}

func NewStore(filePath string) (*Store, error) {
	s := &Store{
		filePath: filePath,
		cfg: &Config{
			GlobalPassword: "test123",
			Users:          []*User{},
			GeoMode:        "off",
			GeoCountries:   []string{},
		},
		userMap: make(map[string]*User),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.filePath)
	if os.IsNotExist(err) {
		return s.saveLocked()
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, s.cfg); err != nil {
		return err
	}
	for _, u := range s.cfg.Users {
		s.userMap[u.Username] = u
	}
	if s.cfg.GeoMode == "" {
		s.cfg.GeoMode = "off"
	}
	s.cfg.GeoCountries = normalizeCountries(s.cfg.GeoCountries)
	return nil
}

func (s *Store) saveLocked() error {
	s.cfg.Users = make([]*User, 0, len(s.userMap))
	for _, u := range s.userMap {
		s.cfg.Users = append(s.cfg.Users, u)
	}
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.filePath)
}

// ---------- 全局密码 ----------

func (s *Store) GetGlobalPassword() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.GlobalPassword
}

func (s *Store) SetGlobalPassword(pwd string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.GlobalPassword = pwd
	return s.saveLocked()
}

// ---------- 管理员账户 ----------

func hashPassword(pwd string) string {
	h := sha256.Sum256([]byte(pwd))
	return hex.EncodeToString(h[:])
}

func (s *Store) HasAdmin() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.AdminUsername != "" && s.cfg.AdminPassword != ""
}

func (s *Store) SetAdmin(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.AdminUsername = username
	s.cfg.AdminPassword = hashPassword(password)
	return s.saveLocked()
}

func (s *Store) VerifyAdmin(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg.AdminUsername == "" {
		return false
	}
	return s.cfg.AdminUsername == username &&
		s.cfg.AdminPassword == hashPassword(password)
}

func (s *Store) GetAdminUsername() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.AdminUsername
}

func (s *Store) ChangeAdminPassword(oldPwd, newPwd string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.AdminPassword != hashPassword(oldPwd) {
		return errors.New("原密码错误")
	}
	s.cfg.AdminPassword = hashPassword(newPwd)
	return s.saveLocked()
}

// ---------- 地理围栏 ----------

func (s *Store) GetGeoConfig() (mode string, countries []string, blockPrivate bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]string, len(s.cfg.GeoCountries))
	copy(cp, s.cfg.GeoCountries)
	return s.cfg.GeoMode, cp, s.cfg.GeoBlockPrivate
}

func (s *Store) SetGeoConfig(mode string, countries []string, blockPrivate bool) error {
	switch mode {
	case "off", "block", "allow":
	default:
		return fmt.Errorf("模式无效: %s", mode)
	}
	normalized := normalizeCountries(countries)
	if mode != "off" {
		if len(normalized) == 0 {
			return fmt.Errorf("地理围栏模式下国家/地区列表不能为空")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.GeoMode = mode
	s.cfg.GeoCountries = normalized
	s.cfg.GeoBlockPrivate = blockPrivate
	return s.saveLocked()
}

// ---------- 性能与日志 ----------

// GetPerformanceConfig 返回 (低性能模式, 日志开启, 高优先级, 延迟模式)
func (s *Store) GetPerformanceConfig() (lowPerf bool, logEnabled bool, highPriority bool, latencyMode string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	lowPerf = false
	if s.cfg.LowPerformanceMode != nil {
		lowPerf = *s.cfg.LowPerformanceMode
	}

	logEnabled = true
	if s.cfg.LogEnabled != nil {
		logEnabled = *s.cfg.LogEnabled
	}

	highPriority = false
	if s.cfg.HighPriority != nil {
		highPriority = *s.cfg.HighPriority
	}

	latencyMode = "low" // ⭐ 默认低延迟
	if s.cfg.LatencyMode != nil {
		latencyMode = *s.cfg.LatencyMode
	}
	switch latencyMode {
	case "low", "balanced", "throughput":
	default:
		latencyMode = "low"
	}

	return
}

func (s *Store) SetPerformanceConfig(lowPerf, logEnabled, highPriority bool, latencyMode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch latencyMode {
	case "low", "balanced", "throughput":
	default:
		latencyMode = "low"
	}

	lp := lowPerf
	le := logEnabled
	hp := highPriority
	lm := latencyMode
	s.cfg.LowPerformanceMode = &lp
	s.cfg.LogEnabled = &le
	s.cfg.HighPriority = &hp
	s.cfg.LatencyMode = &lm
	return s.saveLocked()
}

// ---------- 用户 CRUD ----------

func (s *Store) Get(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.userMap[username]
	if !ok {
		return nil, false
	}
	cp := *u
	return &cp, true
}

func (s *Store) List() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*User, 0, len(s.userMap))
	for _, u := range s.userMap {
		cp := *u
		result = append(result, &cp)
	}
	return result
}

func (s *Store) Create(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.userMap[u.Username]; exists {
		return ErrUserExists
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	s.userMap[u.Username] = u
	return s.saveLocked()
}

func (s *Store) Update(username string, fn func(*User)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.userMap[username]
	if !ok {
		return ErrUserNotFound
	}
	fn(u)
	return s.saveLocked()
}

func (s *Store) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.userMap[username]; !ok {
		return ErrUserNotFound
	}
	delete(s.userMap, username)
	return s.saveLocked()
}

func (s *Store) AddTraffic(username string, delta uint64) {
	if delta == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.userMap[username]; ok {
		u.UsedBytes += delta
		s.dirty = true
	}
}

func (s *Store) FlushLoop(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			s.mu.Lock()
			_ = s.saveLocked()
			s.mu.Unlock()
			return
		case <-ticker.C:
			s.mu.Lock()
			if s.dirty {
				_ = s.saveLocked()
				s.dirty = false
			}
			s.mu.Unlock()
		}
	}
}

func normalizeCountries(list []string) []string {
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, c := range list {
		c = strings.ToUpper(strings.TrimSpace(c))
		if len(c) != 2 || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}
