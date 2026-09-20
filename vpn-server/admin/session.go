package admin

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// session 单个管理会话。
//
// ⭐ 安全审计 S13：原来只有滑动过期的 expireAt，
// 每次请求都会把 TTL 重置为 24 小时 —— 只要攻击者保持轮询，
// 一个泄露的令牌就能**无限期**使用。这里增加不可续期的绝对上限。
type session struct {
	expireAt     time.Time // 空闲过期（可滑动续期）
	hardDeadline time.Time // 绝对上限，任何情况下都不得超过
}

// SessionManager 内存会话表
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*session

	// TTL 空闲过期时间
	TTL time.Duration
	// MaxLifetime 会话绝对上限（从创建时刻算起）
	MaxLifetime time.Duration
}

func NewSessionManager(ttl time.Duration) *SessionManager {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	sm := &SessionManager{
		sessions:    make(map[string]*session),
		TTL:         ttl,
		MaxLifetime: ttl, // 默认：与广告的「会话有效期」一致，不再无限续期
	}
	go sm.cleanupLoop()
	return sm
}

func generateSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// ⭐ 安全审计 S13：原实现用 `_, _ = rand.Read(b)` 忽略错误，
		// 一旦 crypto/rand 失败就会发出全零令牌 —— 那是任何人都能猜到的管理员凭证。
		// 生成不出不可预测的令牌时，让进程退出远好于发出弱令牌。
		panic("crypto/rand 不可用，拒绝生成会话令牌: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func (sm *SessionManager) Create() string {
	token := generateSessionToken()
	now := time.Now()
	sm.mu.Lock()
	sm.sessions[token] = &session{
		expireAt:     now.Add(sm.TTL),
		hardDeadline: now.Add(sm.MaxLifetime),
	}
	sm.mu.Unlock()
	return token
}

func (sm *SessionManager) Validate(token string) bool {
	if token == "" {
		return false
	}
	now := time.Now()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	s, ok := sm.sessions[token]
	if !ok {
		return false
	}
	if now.After(s.expireAt) || now.After(s.hardDeadline) {
		delete(sm.sessions, token)
		return false
	}

	// 滑动续期，但绝不越过绝对上限
	next := now.Add(sm.TTL)
	if next.After(s.hardDeadline) {
		next = s.hardDeadline
	}
	s.expireAt = next
	return true
}

func (sm *SessionManager) Delete(token string) {
	sm.mu.Lock()
	delete(sm.sessions, token)
	sm.mu.Unlock()
}

// DeleteAll 吊销全部会话。
// ⭐ 安全审计 S13：修改管理员密码后必须调用 ——
// 用户改密码的动机通常就是「怀疑凭证泄露」，此时旧令牌必须立即失效。
func (sm *SessionManager) DeleteAll() {
	sm.mu.Lock()
	sm.sessions = make(map[string]*session)
	sm.mu.Unlock()
}

// Count 返回当前会话数（用于日志与监控）
func (sm *SessionManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		sm.mu.Lock()
		for token, s := range sm.sessions {
			if now.After(s.expireAt) || now.After(s.hardDeadline) {
				delete(sm.sessions, token)
			}
		}
		sm.mu.Unlock()
	}
}

// ---------- 简单登录限流 ----------

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*attemptInfo
}

type attemptInfo struct {
	count   int
	lastTry time.Time
}

func newLoginLimiter() *loginLimiter {
	l := &loginLimiter{attempts: make(map[string]*attemptInfo)}
	go l.cleanupLoop()
	return l
}

const (
	maxLoginAttempts = 5
	loginWindow      = 5 * time.Minute
	// ⭐ 安全审计 S5：修好 XFF 之后 IP 不再可伪造，
	// 但仍要防止「大量真实来源 IP」把这张表撑爆。
	maxLimiterEntries = 20000
)

// Allow 返回该 IP 当前是否还允许尝试登录
func (l *loginLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	info, ok := l.attempts[ip]
	if !ok {
		return true
	}
	if time.Since(info.lastTry) > loginWindow {
		delete(l.attempts, ip)
		return true
	}
	return info.count < maxLoginAttempts
}

func (l *loginLimiter) RecordFail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if info, ok := l.attempts[ip]; ok {
		info.count++
		info.lastTry = time.Now()
		return
	}

	// 表满时先清理过期项；仍然满则拒绝新增（等价于对该新 IP 限流）
	if len(l.attempts) >= maxLimiterEntries {
		now := time.Now()
		for k, v := range l.attempts {
			if now.Sub(v.lastTry) > loginWindow {
				delete(l.attempts, k)
			}
		}
		if len(l.attempts) >= maxLimiterEntries {
			return
		}
	}

	l.attempts[ip] = &attemptInfo{count: 1, lastTry: time.Now()}
}

func (l *loginLimiter) Reset(ip string) {
	l.mu.Lock()
	delete(l.attempts, ip)
	l.mu.Unlock()
}

// cleanupLoop 定期清理过期记录，避免长时间运行后内存只增不减
func (l *loginLimiter) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		l.mu.Lock()
		for k, v := range l.attempts {
			if now.Sub(v.lastTry) > loginWindow {
				delete(l.attempts, k)
			}
		}
		l.mu.Unlock()
	}
}
