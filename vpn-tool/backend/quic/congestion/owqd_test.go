package congestion

import (
	"testing"
	"time"
)

func TestOWQD_StablePath(t *testing.T) {
	// 稳定 48ms 链路，OWQD 应该一直是 0，永不触发
	e := NewOWQDEstimator(24 * time.Millisecond)

	for i := 0; i < 100; i++ {
		if e.Update(48 * time.Millisecond) {
			t.Fatalf("稳定链路不应触发重置，第 %d 次", i)
		}
	}

	samples, resets, owqd, minRTT := e.Stats()
	if samples != 100 {
		t.Errorf("样本数应为 100，实际 %d", samples)
	}
	if resets != 0 {
		t.Errorf("重置次数应为 0，实际 %d", resets)
	}
	if minRTT != 48*time.Millisecond {
		t.Errorf("minRTT 应为 48ms，实际 %v", minRTT)
	}
	if owqd != 0 {
		t.Errorf("稳定链路 OWQD 应为 0，实际 %v", owqd)
	}
}

func TestOWQD_QueueBuildUp(t *testing.T) {
	// 模拟：48ms 稳定 → 逐渐队列积压 → 触发重置
	e := NewOWQDEstimator(24 * time.Millisecond)

	// 前 50 个样本：稳定 48ms
	for i := 0; i < 50; i++ {
		e.Update(48 * time.Millisecond)
	}

	// 后 100 个样本：RTT 逐渐爬升 48 → 120ms
	triggered := false
	triggerAt := -1
	for i := 0; i < 100; i++ {
		rtt := 48*time.Millisecond + time.Duration(float64(i)/100*72)*time.Millisecond
		if e.Update(rtt) && !triggered {
			triggered = true
			triggerAt = i
		}
	}

	if !triggered {
		t.Fatal("队列积压应该触发重置，但没有")
	}
	t.Logf("重置在第 %d 个爬升样本触发", triggerAt)

	_, resets, _, minRTT := e.Stats()
	if minRTT != 48*time.Millisecond {
		t.Errorf("minRTT 应保持 48ms，实际 %v", minRTT)
	}
	t.Logf("总重置次数: %d", resets)
}

func TestOWQD_HKBNPattern(t *testing.T) {
	// 模拟 HKBN 场景：48ms 基线，偶发跳到 120-180ms
	e := NewOWQDEstimator(24 * time.Millisecond)

	pattern := []time.Duration{
		// 稳定期
		48, 48, 48, 49, 48, 47, 48, 48, 48, 48,
		// 第一次跳动
		120, 150, 180, 140, 100, 60, 48, 48, 48, 48,
		// 稳定
		48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
		// 第二次跳动
		130, 160, 180, 120, 90, 55, 48, 48, 48, 48,
	}

	resets := 0
	for i, ms := range pattern {
		rtt := ms * time.Millisecond
		if e.Update(rtt) {
			resets++
			t.Logf("样本 %d: RTT=%dms 触发重置 (OWQD=%v)",
				i, ms, e.CurrentOWQD())
		}
	}

	if resets == 0 {
		t.Fatal("HKBN 抖动模式应该触发重置，但没有")
	}
	t.Logf("HKBN 模式总重置次数: %d", resets)
	t.Logf("最终 OWQD: %v, minRTT: %v",
		e.CurrentOWQD(), e.MinRTT())
}

func TestOWQD_ThresholdTuning(t *testing.T) {
	// 对比不同阈值对同一序列的反应
	pattern := []time.Duration{
		48, 48, 48, 48, 48,
		60, 70, 80, 90, 100, 110, 120, 120, 120,
		110, 100, 90, 80, 70, 60, 55, 48, 48, 48,
	}

	for _, thMs := range []int{12, 24, 36, 48} {
		e := NewOWQDEstimator(time.Duration(thMs) * time.Millisecond)
		resets := 0
		for _, ms := range pattern {
			if e.Update(ms * time.Millisecond) {
				resets++
			}
		}
		t.Logf("阈值=%dms → 重置 %d 次", thMs, resets)
	}
}

func TestOWQD_NoFalsePositive(t *testing.T) {
	// 即使 RTT 抖动 ±5ms，只要不超过阈值就不应触发
	e := NewOWQDEstimator(20 * time.Millisecond)

	// 48ms ± 5ms 抖动
	jitter := []int64{48, 50, 46, 52, 47, 51, 45, 53, 49, 48}
	for i := 0; i < 100; i++ {
		rtt := time.Duration(jitter[i%len(jitter)]) * time.Millisecond
		if e.Update(rtt) {
			t.Fatalf("±5ms 抖动不应触发，第 %d 次", i)
		}
	}
}
