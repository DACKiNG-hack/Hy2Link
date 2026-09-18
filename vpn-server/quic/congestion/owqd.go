package congestion

//owqd.go

import (
	"sync"
	"time"
)

// DefaultOWQDThreshold 初始 OWQD 阈值，第一次采样前使用，会被自适应逻辑覆盖
var DefaultOWQDThreshold = 24 * time.Millisecond

const (
	// ⭐ 自适应比例：阈值 = minRTT × 0.5
	owqdThresholdRatio = 0.5

	// ⭐ 阈值下限：防止 minRTT 太小（本机回环）导致阈值过严
	owqdThresholdMin = 15 * time.Millisecond

	// ⭐ 阈值上限：防止 minRTT 异常大（链路故障）导致阈值过松
	owqdThresholdMax = 100 * time.Millisecond

	// ⭐ minRTT 滑动窗口时长：只看最近 60 秒的样本
	rttWindowDuration = 60 * time.Second

	// ⭐ 环形缓冲大小：60 秒内最多保留这么多 RTT 样本
	// 假设采样率约 100/s，60s × 100 = 6000，8192 留余量
	rttRingSize = 8192

	// ⭐ minRTT 重算间隔：每 200ms 扫一次窗口
	rttRecalcInterval = 200 * time.Millisecond
)

type rttSample struct {
	t   time.Time
	rtt time.Duration
}

// OWQDEstimator 通过 RTT 样本估计单向排队延迟
//
// minRTT 使用 60 秒滑动窗口：
//   - 只取窗口内最小值作为 minRTT
//   - 高峰抖动时旧的低 RTT 样本会逐渐过期，minRTT 自然抬高
//   - 阈值 = minRTT × 0.5，夹在 [15ms, 100ms]
//
// 这样既能跟住链路 base RTT 的真实变化，又不会因一次瞬时低谷永久锁死阈值。
type OWQDEstimator struct {
	mu sync.Mutex

	minRTT time.Duration
	owqd   time.Duration
	owqdTh time.Duration
	alpha  float64

	sampleCount uint64
	resetCount  uint64
	lastSample  time.Duration

	// ⭐ 滑动窗口
	ring       [rttRingSize]rttSample
	ringIdx    int
	lastRecalc time.Time
}

func NewOWQDEstimator(owqdThreshold time.Duration) *OWQDEstimator {
	return &OWQDEstimator{
		minRTT: time.Hour,
		owqdTh: owqdThreshold,
		alpha:  0.125,
	}
}

func (e *OWQDEstimator) Update(rtt time.Duration) bool {
	if rtt <= 0 {
		return false
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	e.sampleCount++

	// 写入环形缓冲
	e.ring[e.ringIdx] = rttSample{t: now, rtt: rtt}
	e.ringIdx = (e.ringIdx + 1) % rttRingSize

	// 定期重算 minRTT（基于滑动窗口，让过期的低 RTT 样本失效）
	if now.Sub(e.lastRecalc) >= rttRecalcInterval {
		e.recomputeMinRTTLocked(now)
		e.lastRecalc = now
	}

	// 即时响应：新样本比当前 minRTT 更小，立刻更新
	if e.minRTT >= time.Hour {
		e.minRTT = rtt
		e.recomputeThresholdLocked()
	} else if rtt < e.minRTT {
		e.minRTT = rtt
		e.recomputeThresholdLocked()
	}

	sample := rtt - e.minRTT
	if sample < 0 {
		sample = 0
	}
	e.lastSample = sample

	if e.owqd == 0 {
		e.owqd = sample
	} else {
		e.owqd = time.Duration(
			float64(e.owqd)*(1-e.alpha) + float64(sample)*e.alpha,
		)
	}

	if e.owqd > e.owqdTh {
		e.resetCount++
		e.owqd = e.owqdTh / 2
		return true
	}
	return false
}

// recomputeMinRTTLocked 扫描环形缓冲，取窗口内最小 RTT
func (e *OWQDEstimator) recomputeMinRTTLocked(now time.Time) {
	cutoff := now.Add(-rttWindowDuration)
	minRTT := time.Hour
	found := false
	for i := 0; i < rttRingSize; i++ {
		s := e.ring[i]
		if s.t.IsZero() || s.t.Before(cutoff) {
			continue
		}
		if s.rtt < minRTT {
			minRTT = s.rtt
			found = true
		}
	}
	if !found {
		return
	}
	e.minRTT = minRTT
	e.recomputeThresholdLocked()
}

// recomputeThresholdLocked 根据 minRTT 重算阈值：minRTT × 0.5，夹在 [15ms, 100ms]
//
// 例：
//
//	minRTT=5ms   → 阈值 15ms（下限）
//	minRTT=43ms  → 阈值 21.5ms
//	minRTT=80ms  → 阈值 40ms
//	minRTT=150ms → 阈值 75ms
//	minRTT=300ms → 阈值 100ms（上限）
func (e *OWQDEstimator) recomputeThresholdLocked() {
	if e.minRTT <= 0 || e.minRTT >= time.Hour {
		return
	}
	th := time.Duration(float64(e.minRTT) * owqdThresholdRatio)
	if th < owqdThresholdMin {
		th = owqdThresholdMin
	}
	if th > owqdThresholdMax {
		th = owqdThresholdMax
	}
	e.owqdTh = th
}

func (e *OWQDEstimator) CurrentOWQD() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.owqd
}

func (e *OWQDEstimator) MinRTT() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.minRTT >= time.Hour {
		return 0
	}
	return e.minRTT
}

func (e *OWQDEstimator) Threshold() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.owqdTh
}

func (e *OWQDEstimator) SetThreshold(th time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.owqdTh = th
}

func (e *OWQDEstimator) Stats() (samples, resets uint64, currentOWQD, minRTT time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	mr := e.minRTT
	if mr >= time.Hour {
		mr = 0
	}
	return e.sampleCount, e.resetCount, e.owqd, mr
}

func (e *OWQDEstimator) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.minRTT = time.Hour
	e.owqd = 0
	e.sampleCount = 0
	e.resetCount = 0
	e.lastSample = 0
	e.owqdTh = DefaultOWQDThreshold
	for i := range e.ring {
		e.ring[i] = rttSample{}
	}
	e.ringIdx = 0
	e.lastRecalc = time.Time{}
}
