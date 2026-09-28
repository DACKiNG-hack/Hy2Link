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

	// trafficMisses 「每客户端」计数因 key 不存在而被丢弃的**次数**（只增，可查询）。
	//
	// ⚠️ 为什么需要它（2026-09-28 面板趋势图 bug）：`AddTraffic` 查不到 key 时**静默丢弃**，
	//	而趋势图读的正是「Σ 每客户端字节」⇒ 一旦该 VIP 不在表里，趋势图恒 0 而
	//	`totalIn/totalOut`（无条件累加）仍在涨 ⇒ 现象难以归因、潜伏多年。
	//	本条即《工程纪律》**§3 第 17 条**（"不可见分支"必须可见化）的落地：
	//	**正常不该发生**的分支 ⇒ 至少"可查询计数器"（并配限频日志）。
	//	判据：该值长期为 0 才是正常；非 0 ⇒ 有客户端在"未登记"状态下产生了流量。
	trafficMisses uint64
}

func NewAdminState(version string) *AdminState {
	return &AdminState{
		startedAt: time.Now(),
		version:   version,
		clients:   make(map[string]*ClientInfo),
	}
}

// OnConnect 登记一个在线客户端。
//
// key 必须是**每连接唯一**的值（调用方传的是虚拟 IP）。
// ⚠️ 不要用用户名作 key：一个账号允许被多个客户端共用，
// 用用户名会互相覆盖，也会导致断开其中一个就把另一个从列表里删掉。
func (s *AdminState) OnConnect(key, username, mode, vip, realAddr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	old, exists := s.clients[key]
	if !exists {
		s.clients[key] = &ClientInfo{
			Username:  username,
			Mode:      mode,
			VirtualIP: vip,
			RealAddr:  realAddr,
			Connected: now,
			LastSeen:  now,
			LatencyMs: 0,
		}
		return
	}

	// ⭐ 2026-09-28（面板趋势图 bug · 修法 2）：**upsert 语义** —— 同一 key 再次登记（接管/重连）时
	//	**不得无条件重建** `ClientInfo`，否则 `BytesIn/BytesOut` 归零 ⇒ 面板数字倒退，
	//	且（见下）会让"趋势图读 Σ 每客户端"这种口径更加脆弱。
	//
	//	语义定稿：
	//	 · **同一身份**（`Username` 相同）⇒ 视为**同一条在线会话**：**保留计数**、刷新元数据与 `LastSeen`、
	//	   **不刷新 `Connected`**（它表示"首次上线时刻"，接管不算新会话）。
	//	 · **身份变了**（`Username` 不同 ⇒ 该 VIP 已被回收给别的设备）⇒ **视为新会话**：
	//	   计数归零、`Connected` 重置。它同时是"修法 1（陈旧收尾不得删条目）"的**兜底**：
	//	   即便上层漏了身份判定，这里也不会把两个客户端的数据混在一起。
	sameIdentity := old.Username == username
	old.Mode = mode
	old.VirtualIP = vip
	old.RealAddr = realAddr
	old.LastSeen = now
	if !sameIdentity {
		old.Username = username
		old.BytesIn = 0
		old.BytesOut = 0
		old.LatencyMs = 0
		old.Connected = now
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
	} else {
		// ⚠️ 正常**不该**发生（数据面建立时必 `OnConnect`）⇒ 计入可查询计数（§3 第 17 条）。
		//	静默丢弃 = 趋势图恒 0 而无人知晓（2026-09-28 的面板 bug 正是此形态）。
		s.trafficMisses++
	}
	s.totalIn += in
	s.totalOut += out
}

// TrafficMisses 返回「每客户端计数被丢弃」的累计次数（= 未知 key 的 AddTraffic 次数）。
//
// 排障用法：**长期应为 0**；非 0 ⇒ 有客户端在"未登记"状态下产生了流量
// （典型成因：接管/重连路径未维护在线状态，见 `admin_state_reconnect_test.go` 的说明）。
func (s *AdminState) TrafficMisses() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.trafficMisses
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
