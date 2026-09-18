package congestion

import (
	"testing"
	"time"

	quiccong "github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

// fakeRTT 模拟 RTTStatsProvider
type fakeRTT struct {
	latest   time.Duration
	smoothed time.Duration
	min      time.Duration
}

func (f *fakeRTT) MinRTT() time.Duration          { return f.min }
func (f *fakeRTT) LatestRTT() time.Duration       { return f.latest }
func (f *fakeRTT) SmoothedRTT() time.Duration     { return f.smoothed }
func (f *fakeRTT) MeanDeviation() time.Duration   { return 0 }
func (f *fakeRTT) MaxAckDelay() time.Duration     { return 0 }
func (f *fakeRTT) PTO(bool) time.Duration         { return 0 }
func (f *fakeRTT) UpdateRTT(_, _ time.Duration)   {}
func (f *fakeRTT) SetMaxAckDelay(_ time.Duration) {}
func (f *fakeRTT) SetInitialRTT(_ time.Duration)  {}

func TestQUICDC_NormalGrowth(t *testing.T) {
	cc := NewQUICDCController()
	rtt := &fakeRTT{latest: 48 * time.Millisecond, smoothed: 48 * time.Millisecond, min: 48 * time.Millisecond}
	cc.SetRTTStatsProvider(rtt)

	initial := cc.GetCongestionWindow()
	t.Logf("初始 cwnd: %d", initial)

	// 模拟 100 个 ACK，每个确认 1200 字节
	for i := 0; i < 100; i++ {
		cc.OnPacketAcked(quiccong.PacketNumber(i), 1200, initial, monotime.Now())
	}

	grown := cc.GetCongestionWindow()
	t.Logf("100 ACK 后 cwnd: %d", grown)

	if grown <= initial {
		t.Fatalf("cwnd 应该增长，初始=%d 现在=%d", initial, grown)
	}
	_, resets, _, _, _, _ := cc.Stats()
	if resets != 0 {
		t.Errorf("稳定链路不应触发 OWQD 重置，实际 %d 次", resets)
	}
}

func TestQUICDC_OWQDTriggersReset(t *testing.T) {
	cc := NewQUICDCController()
	rtt := &fakeRTT{latest: 48 * time.Millisecond, smoothed: 48 * time.Millisecond, min: 48 * time.Millisecond}
	cc.SetRTTStatsProvider(rtt)

	// 先跑 30 个 ACK 让 cwnd 增长
	for i := 0; i < 30; i++ {
		cc.OnPacketAcked(quiccong.PacketNumber(i), 1200, 0, monotime.Now())
	}
	before := cc.GetCongestionWindow()
	t.Logf("抖动前 cwnd: %d", before)

	// RTT 突然跳到 150ms
	rtt.latest = 150 * time.Millisecond
	rtt.smoothed = 150 * time.Millisecond

	// 再发 10 个 ACK
	for i := 30; i < 40; i++ {
		cc.OnPacketAcked(quiccong.PacketNumber(i), 1200, 0, monotime.Now())
	}

	after := cc.GetCongestionWindow()
	_, resets, _, _, _, _ := cc.Stats()
	t.Logf("抖动后 cwnd: %d, 重置次数: %d", after, resets)

	if resets == 0 {
		t.Fatal("RTT 跳升应该触发 OWQD 重置")
	}
	if after >= before {
		t.Fatalf("cwnd 应该下降，之前=%d 现在=%d", before, after)
	}
}

func TestQUICDC_LossReduction(t *testing.T) {
	cc := NewQUICDCController()
	rtt := &fakeRTT{latest: 48 * time.Millisecond, smoothed: 48 * time.Millisecond, min: 48 * time.Millisecond}
	cc.SetRTTStatsProvider(rtt)

	// 增长
	for i := 0; i < 50; i++ {
		cc.OnPacketAcked(quiccong.PacketNumber(i), 1200, 0, monotime.Now())
	}
	before := cc.GetCongestionWindow()

	// 触发丢包
	cc.OnCongestionEvent(quiccong.PacketNumber(51), 1200, before)

	after := cc.GetCongestionWindow()
	t.Logf("丢包前: %d, 丢包后: %d", before, after)

	// 应该降到 0.7 倍左右
	if after > before*7/10 {
		t.Errorf("cwnd 应降到 0.7 倍，实际 before=%d after=%d", before, after)
	}
	if !cc.InRecovery() {
		t.Error("丢包后应进入恢复状态")
	}
}

func TestQUICDC_MinimumCwnd(t *testing.T) {
	cc := NewQUICDCController()
	rtt := &fakeRTT{latest: 48 * time.Millisecond}
	cc.SetRTTStatsProvider(rtt)

	// 连续触发多次拥塞
	for i := 0; i < 10; i++ {
		cc.OnCongestionEvent(quiccong.PacketNumber(i*100+1), 1200, 0)
	}

	cwnd := cc.GetCongestionWindow()
	t.Logf("连续拥塞后 cwnd: %d", cwnd)

	// 不应低于最小窗口（2 个包 × 1200）
	minExpected := quiccong.ByteCount(2 * 1200)
	if cwnd < minExpected {
		t.Errorf("cwnd 不应低于最小窗口 %d，实际 %d", minExpected, cwnd)
	}
}
