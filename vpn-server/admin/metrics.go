package admin

import (
	"sync"
	"time"
)

type MetricSample struct {
	Time     int64  `json:"time"`
	Online   int    `json:"online"`
	TotalIn  uint64 `json:"totalIn"`
	TotalOut uint64 `json:"totalOut"`
}

type MetricsCollector struct {
	mu      sync.RWMutex
	samples []MetricSample
	max     int
}

func NewMetricsCollector(max int) *MetricsCollector {
	return &MetricsCollector{
		samples: make([]MetricSample, 0, max),
		max:     max,
	}
}

func (m *MetricsCollector) Add(s MetricSample) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.samples) >= m.max {
		copy(m.samples, m.samples[1:])
		m.samples[len(m.samples)-1] = s
	} else {
		m.samples = append(m.samples, s)
	}
}

func (m *MetricsCollector) Snapshot() []MetricSample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]MetricSample, len(m.samples))
	copy(out, m.samples)
	return out
}

// Start 每 5 秒采样一次，保留 720 个点（1 小时）
func (m *MetricsCollector) Start(state *AdminState) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			snap := state.Snapshot()
			// ⭐ 2026-09-28（面板趋势图 bug · 修法 4）：**直接采用 `AdminState` 的权威总量**，
			//	不再自行 `Σ clients[i].BytesIn`。
			//
			//	为什么必须改：`Σ 每客户端` 只统计"在 `clients` 表里且计数曾被累加"的连接 ⇒
			//	一旦某 VIP 的条目缺失（接管/重连路径的历史缺陷），Σ 恒为 **0**；而
			//	`AdminState.totalIn/totalOut` 是**无条件累加**的（不依赖条目存在）⇒ 总量一直正确。
			//	⇒ 现象正是：面板「流量趋势图」显示 0，而"用户管理"（账号级计数）有值。
			//
			//	⚠️ 必须与修法 X′/1/2 **同批发布**：本条只让"流量趋势"数字正确；`Online` 仍取
			//	  `snap.ClientCount`（= `len(clients)`）⇒ **条目缺失时在线数仍偏低**，那部分由
			//	  "恢复条目"的修法解决。仅发本条 = "图有了、在线数还错"的**假保护**（§4 第 9 条）。
			m.Add(MetricSample{
				Time:     time.Now().Unix(),
				Online:   snap.ClientCount,
				TotalIn:  snap.TotalIn,
				TotalOut: snap.TotalOut,
			})
		}
	}()
}
