package admin

import (
	"sync"
	"time"
)

type ClientInfo struct {
	Username  string    `json:"username"`
	Mode      string    `json:"mode"`
	VirtualIP string    `json:"virtualIP"`
	RealAddr  string    `json:"realAddr"`
	Connected time.Time `json:"connected"`
	LastSeen  time.Time `json:"lastSeen"`
	BytesIn   uint64    `json:"bytesIn"`
	BytesOut  uint64    `json:"bytesOut"`
	// ⭐ 新增：客户端上报的 RTT（毫秒），0 表示未知
	LatencyMs int32 `json:"latencyMs"`
}

type AdminState struct {
	mu        sync.RWMutex
	startedAt time.Time
	version   string
	clients   map[string]*ClientInfo
	totalIn   uint64
	totalOut  uint64
}

func NewAdminState(version string) *AdminState {
	return &AdminState{
		startedAt: time.Now(),
		version:   version,
		clients:   make(map[string]*ClientInfo),
	}
}

// ⭐ 5 个参数
func (s *AdminState) OnConnect(key, username, mode, vip, realAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.clients[key] = &ClientInfo{
		Username:  username,
		Mode:      mode,
		VirtualIP: vip,
		RealAddr:  realAddr,
		Connected: now,
		LastSeen:  now,
		LatencyMs: 0,
	}
}

func (s *AdminState) OnDisconnect(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, key)
}

// ⭐ 新增：客户端上报心跳 RTT 时调用
func (s *AdminState) SetClientLatency(key string, ms int32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clients[key]; ok {
		if ms < 0 {
			ms = 0
		}
		c.LatencyMs = ms
	}
}

func (s *AdminState) AddTraffic(key string, in, out uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clients[key]; ok {
		c.BytesIn += in
		c.BytesOut += out
		c.LastSeen = time.Now()
	}
	s.totalIn += in
	s.totalOut += out
}

type Snapshot struct {
	Version     string        `json:"version"`
	Uptime      float64       `json:"uptime"`
	ClientCount int           `json:"clientCount"`
	TotalIn     uint64        `json:"totalIn"`
	TotalOut    uint64        `json:"totalOut"`
	Clients     []*ClientInfo `json:"clients"`
	Time        int64         `json:"time"`
}

func (s *AdminState) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clients := make([]*ClientInfo, 0, len(s.clients))
	for _, c := range s.clients {
		cp := *c
		clients = append(clients, &cp)
	}
	return Snapshot{
		Version:     s.version,
		Uptime:      time.Since(s.startedAt).Seconds(),
		ClientCount: len(clients),
		TotalIn:     s.totalIn,
		TotalOut:    s.totalOut,
		Clients:     clients,
		Time:        time.Now().Unix(),
	}
}
