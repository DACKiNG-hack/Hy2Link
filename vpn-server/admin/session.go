package admin

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// SessionManager 内存会话表
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]time.Time // token -> expireAt
	TTL      time.Duration
}

func NewSessionManager(ttl time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]time.Time),
		TTL:      ttl,
	}
	go sm.cleanupLoop()
	return sm
}

func generateSessionToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (sm *SessionManager) Create() string {
	token := generateSessionToken()
	sm.mu.Lock()
	sm.sessions[token] = time.Now().Add(sm.TTL)
	sm.mu.Unlock()
	return token
}

func (sm *SessionManager) Validate(token string) bool {
	if token == "" {
		return false
	}
	sm.mu.RLock()
	expire, ok := sm.sessions[token]
	sm.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(expire) {
		sm.Delete(token)
		return false
	}
	// 滑动续期：每次访问延长 TTL
	sm.mu.Lock()
	sm.sessions[token] = time.Now().Add(sm.TTL)
	sm.mu.Unlock()
	return true
}

func (sm *SessionManager) Delete(token string) {
	sm.mu.Lock()
	delete(sm.sessions, token)
	sm.mu.Unlock()
}

func (sm *SessionManager) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		sm.mu.Lock()
		for token, expire := range sm.sessions {
			if now.After(expire) {
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
	return &loginLimiter{attempts: make(map[string]*attemptInfo)}
}

const (
	maxLoginAttempts = 5
	loginWindow      = 5 * time.Minute
)

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
	info, ok := l.attempts[ip]
	if !ok {
		info = &attemptInfo{}
		l.attempts[ip] = info
	}
	info.count++
	info.lastTry = time.Now()
}

func (l *loginLimiter) Reset(ip string) {
	l.mu.Lock()
	delete(l.attempts, ip)
	l.mu.Unlock()
}
