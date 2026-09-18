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
			var totalIn, totalOut uint64
			for _, c := range snap.Clients {
				totalIn += c.BytesIn
				totalOut += c.BytesOut
			}
			m.Add(MetricSample{
				Time:     time.Now().Unix(),
				Online:   snap.ClientCount,
				TotalIn:  totalIn,
				TotalOut: totalOut,
			})
		}
	}()
}
