package congestion

//quicdc.go

import (
	"sync"
	"time"

	quiccong "github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const (
	initialCwndPackets  = 10
	minCwndPackets      = 4
	lossReductionFactor = 0.85
)

// QUICDCController 基于 OWQD 感知的 QUIC 拥塞控制器
type QUICDCController struct {
	mu sync.Mutex

	cwnd            quiccong.ByteCount
	ssthresh        quiccong.ByteCount
	maxDatagramSize quiccong.ByteCount

	largestSentPacketNumber  quiccong.PacketNumber
	largestAckedPacketNumber quiccong.PacketNumber
	largestSentAtLastCutback quiccong.PacketNumber

	rttProvider quiccong.RTTStatsProvider
	owqd        *OWQDEstimator

	inRecovery bool

	resetCount uint64
	ackCount   uint64
	sentCount  uint64
}

func NewQUICDCController() *QUICDCController {
	maxSize := quiccong.ByteCount(quiccong.InitialPacketSize)
	return &QUICDCController{
		cwnd:            maxSize * initialCwndPackets,
		ssthresh:        maxSize * quiccong.ByteCount(quiccong.MaxCongestionWindowPackets),
		maxDatagramSize: maxSize,
		owqd:            NewOWQDEstimator(DefaultOWQDThreshold),
	}
}

func (c *QUICDCController) SetRTTStatsProvider(p quiccong.RTTStatsProvider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rttProvider = p
}

func (c *QUICDCController) SetMaxDatagramSize(s quiccong.ByteCount) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxDatagramSize = s
	if c.cwnd < c.minCwnd() {
		c.cwnd = c.minCwnd()
	}
}

func (c *QUICDCController) GetCongestionWindow() quiccong.ByteCount {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cwnd
}

func (c *QUICDCController) InSlowStart() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cwnd < c.ssthresh
}

func (c *QUICDCController) InRecovery() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inRecovery
}

func (c *QUICDCController) TimeUntilSend(bytesInFlight quiccong.ByteCount) monotime.Time {
	return monotime.Now()
}

func (c *QUICDCController) HasPacingBudget(now monotime.Time) bool {
	return true
}

func (c *QUICDCController) CanSend(bytesInFlight quiccong.ByteCount) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytesInFlight < c.cwnd
}

func (c *QUICDCController) OnPacketSent(
	sentTime monotime.Time,
	bytesInFlight quiccong.ByteCount,
	packetNumber quiccong.PacketNumber,
	bytes quiccong.ByteCount,
	isRetransmittable bool,
) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sentCount++
	if isRetransmittable {
		c.largestSentPacketNumber = packetNumber
	}
}

func (c *QUICDCController) OnPacketAcked(
	number quiccong.PacketNumber,
	ackedBytes quiccong.ByteCount,
	priorInFlight quiccong.ByteCount,
	eventTime monotime.Time,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ackCount++
	if number > c.largestAckedPacketNumber {
		c.largestAckedPacketNumber = number
	}

	if c.inRecovery {
		if c.largestAckedPacketNumber > c.largestSentAtLastCutback {
			c.inRecovery = false
		} else {
			return
		}
	}

	if c.rttProvider != nil {
		rtt := c.rttProvider.LatestRTT()
		if rtt <= 0 {
			rtt = c.rttProvider.SmoothedRTT()
		}
		if rtt > 0 && c.owqd.Update(rtt) {
			c.resetCwndLocked()
			return
		}
	}

	if c.cwnd < c.ssthresh {
		c.cwnd += ackedBytes
	} else {
		if c.cwnd > 0 {
			c.cwnd += c.maxDatagramSize * ackedBytes / c.cwnd
		}
	}

	maxCwnd := c.maxDatagramSize * quiccong.ByteCount(quiccong.MaxCongestionWindowPackets)
	if c.cwnd > maxCwnd {
		c.cwnd = maxCwnd
	}
}

func (c *QUICDCController) MaybeExitSlowStart() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.rttProvider == nil || !(c.cwnd < c.ssthresh) {
		return
	}
	srtt := c.rttProvider.SmoothedRTT()
	minRTT := c.rttProvider.MinRTT()
	if srtt > 0 && minRTT > 0 && srtt > 2*minRTT {
		c.ssthresh = c.cwnd
	}
}

func (c *QUICDCController) OnCongestionEvent(
	packetNumber quiccong.PacketNumber,
	lostBytes quiccong.ByteCount,
	priorInFlight quiccong.ByteCount,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if packetNumber <= c.largestSentAtLastCutback {
		return
	}

	c.inRecovery = true
	c.ssthresh = quiccong.ByteCount(float64(c.cwnd) * lossReductionFactor)
	if c.ssthresh < c.minCwnd() {
		c.ssthresh = c.minCwnd()
	}
	c.cwnd = c.ssthresh
	c.largestSentAtLastCutback = c.largestSentPacketNumber
}

func (c *QUICDCController) OnRetransmissionTimeout(packetsRetransmitted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.largestSentAtLastCutback = 0
	if !packetsRetransmitted {
		return
	}

	c.owqd.Reset()
	c.ssthresh = c.cwnd / 2
	if c.ssthresh < c.minCwnd() {
		c.ssthresh = c.minCwnd()
	}
	c.cwnd = c.minCwnd()
	c.inRecovery = true
}

func (c *QUICDCController) minCwnd() quiccong.ByteCount {
	return c.maxDatagramSize * minCwndPackets
}

func (c *QUICDCController) resetCwndLocked() {
	c.resetCount++
	newCwnd := c.cwnd / 2
	if newCwnd < c.minCwnd() {
		newCwnd = c.minCwnd()
	}
	c.cwnd = c.minCwnd()
	c.ssthresh = c.minCwnd()
	c.inRecovery = true
}

func (c *QUICDCController) Stats() (acks, resets uint64, cwnd, ssthresh quiccong.ByteCount, owqd, minRTT time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var owqdDur, minRTTDur time.Duration
	if c.owqd != nil {
		owqdDur = c.owqd.CurrentOWQD()
		minRTTDur = c.owqd.MinRTT()
	}
	return c.ackCount, c.resetCount, c.cwnd, c.ssthresh, owqdDur, minRTTDur
}

func (c *QUICDCController) ResetStats() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resetCount = 0
	c.ackCount = 0
	c.sentCount = 0
}
