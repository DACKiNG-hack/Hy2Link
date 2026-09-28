package quic

// trial_sample_phase_test.go —— **B2 切片**：采样点相位（真机 2026-09-28 B 侧只采到 1 个样本）
//
// ⚠️ 本文件是 B2 新增的用例文件。
//
// 【真机现象】B 侧 05:32:14 进试用期（质量好：直连 39ms / 中继 54ms），只采到 **1 个样本**
// （05:32:24 才「好样本 1/1」）⇒ `samples(1) < need(2)` ⇒ 判负 ⇒ 半双工（对端装表、本侧不装表）。
//
// 【机制（**实测**，非推导：见本文件时间轴与 `zz_b2_probe_test.go` 的探针输出）】
//
//	采样点机会 = 看门狗节拍（`checkInterval`=1s）里"距上次采样 ≥ `probeInterval`(5s)"的那些拍
//	⇒ 15s 窗口内**共 5 个机会**（t≈5、10、15 各一个，其余被闸门挡回）。
//	「无新回显 ⇒ 不落样本」这一条本身是对的（防"探针刚发出"白吃样本），**但它把闸门推到 `now`**
//	（注释写"顺延到下一拍"，实际是"顺延到下一个 `probeInterval` 相位"）⇒
//	**如果新回显恰好落在"采样点之后、下一个机会之前"的空隙里，这个采样机会就永久丢失**。
//
//	真机时间轴（回显在采样点之后几十~几百 ms 到）：
//
//	t= 5s  SAMPLE（用掉的是 T 前的旧回显）⇒ 闸门 → 5s
//	t= 5.5s 探针 #1 的回显到达 ← **没有任何机会能看到它**（下一次机会在 t=10s）
//	t= 10s 闸门合格但"无新回显"⇒ **跳过**，闸门 → 10s
//	t=10.5s 探针 #2 的回显到达 ← 同上，永久丢失
//	t= 15s 闸门合格但"无新回显"⇒ **跳过**，闸门 → 15s（窗口结束）
//	⇒ **samples = 1** < need(2) ⇒ 判负
//
// 【修法 P5（本切片）】"无新回显"时**不推进闸门**（只在**落样本**时推进）：
//
//	t= 5s 闸门合格但无新回显 ⇒ 跳过且闸门仍 = T ⇒
//	t= 6s 下一拍立刻重试：此时 t=5.5s 的回显已在 ⇒ **落样本 1**
//	t=11s 落样本 2 ⇒ 窗口内 2 个 = need ⇒ 通过
//
//	⇒ 语义 = "**每个采样机会都必须被真正用掉**（要么落样本、要么立刻重试），
//	   不允许因为'这一拍恰好没回显'就丢掉整整一个 `probeInterval` 的机会"。
//
// 【断言口径】**语义层**：给定"探针节奏 + 回显到达时刻"，窗口内能落下几个样本。
// 写法沿用 `trial_backoff_test.go` 的**手工时间轴**（直接喂 `trialSampleStep(now)`）⇒ 零 flaky。

import (
	"testing"
	"time"
)

// b2Phases 描述一条"真机形态"的回显时间轴：在给定的偏移处交付第 N 个回显。
type b2Echo struct {
	at time.Duration // 相对试用期起点的偏移
}

// driveTrialSampling 按 `checkInterval` 节拍驱动 `trialSampleStep`，在指定偏移交付回显，
// 返回落样本的偏移序列（确定性：纯手工时间轴）。
func driveTrialSampling(pm *pathManager, p *directPath, T time.Time, until time.Duration, echoes []b2Echo) []time.Duration {
	tick := pm.checkInterval
	if tick <= 0 {
		tick = defaultCheckInterval
	}
	ei := 0
	var sampleTimes []time.Duration
	for el := tick; el <= until; el += tick {
		now := T.Add(el)
		for ei < len(echoes) && echoes[ei].at <= el { // 到点即交付回显
			p.lastEcho.Store(now.UnixMilli())
			ei++
		}
		before := p.trialSamples.Load()
		p.trialSampleStep(now)
		if p.trialSamples.Load() > before {
			sampleTimes = append(sampleTimes, el)
		}
	}
	return sampleTimes
}

// newB2TrialPath 建一条"停留在试用期、参数为生产值"的纯采样路径（不需要真实连接/信令）。
func newB2TrialPath(t *testing.T) (*pathManager, *directPath, time.Time) {
	t.Helper()
	host := newFakeHost()
	pm := newPathManager(host)
	pm.probeInterval = defaultProbeInterval // 钉住 5s，避免默认值变动让用例悄悄失去覆盖
	p := &directPath{mgr: pm, peer: ip4("192.168.30.12")}
	T := time.Now()
	p.trialStartedAt.Store(T.UnixMilli())
	// A1 口径：基线 = 进入试用期那一刻的 lastEcho。取 T 前最后一次回显（T-1s）。
	p.lastEcho.Store(T.Add(-time.Second).UnixMilli())
	p.trialLastEcho.Store(T.Add(-time.Second).UnixMilli())
	p.trialLastSampleAt.Store(T.UnixMilli())
	// 真机实测质量（39/54ms ⇒ 样本必判「好」）
	p.rtt.Store(int64(39 * time.Millisecond))
	p.trialRelayRtt.Store(int64(54 * time.Millisecond))
	return pm, p, T
}

// TestTrialSampleGateDoesNotPhaseLock ⭐⭐ B2 主用例（**先红后绿**）。
//
//	真机形态：两次探针（T+5s / T+10s）的**回显紧跟在采样点之后**（+1s，真机"撞拍"形态）
//	⇒ 每一次回显都必须在**它到达之后的那一次采样机会**上被用掉（不允许被推后一个 probeInterval）。
//
// 判据（可复现、可解释）：
//   - 回显 1 在 T+6s 到达 ⇒ 最迟 T+7s 必须已落样本 1；
//   - 回显 2 在 T+11s 到达 ⇒ 最迟 T+12s 必须已落样本 2。
//
// ⚠️ **为什么用"最迟偏移"而不是"总数 ≥ need"**：实测旧实现在某些相位下**恰好也能凑到 2 个**
// （把回显推后一个 probeInterval 采到，见 `zz_b2_probe_test.go` 的场景 3 探针）⇒ 只数总数会**假绿**。
// 真机的"只采 1 个"正是"盲区把两次回显都吞掉"的形态 ⇒ 必须钉"回显 → 采样"的**时延**。
//
// ⚠️ 有牙（B2 修复前必红）：旧实现下 T+5s 的跳过把闸门推到 T+5s ⇒ 存在 5s 盲区；
// T+6.5s 到达的回显要等到 T+10s 才被采（超出"最迟 T+7s"），更晚的则整个丢失。
func TestTrialSampleGateDoesNotPhaseLock(t *testing.T) {
	pm, p, T := newB2TrialPath(t)

	need := p.trialNeedGood()
	win := p.trialWindow()
	if need != trialNeedGoodNormal {
		t.Fatalf("前置：生产 need 应为 %d，实际 %d", trialNeedGoodNormal, need)
	}
	if win != trialWindowNormal {
		t.Fatalf("前置：生产窗口应为 %v，实际 %v", trialWindowNormal, win)
	}

	// 两次探针的回显：T+6.5s / T+11.5s（= 采样点之后 1.5s；旧实现的盲区是"跳过点 +5s"）
	echoes := []b2Echo{
		{at: 6500 * time.Millisecond},
		{at: 11500 * time.Millisecond},
	}
	deadlines := []time.Duration{7500 * time.Millisecond, 12500 * time.Millisecond}
	got := driveTrialSampling(pm, p, T, win, echoes)

	samples := int(p.trialSamples.Load())
	good := int(p.trialGood.Load())

	if samples < need {
		t.Fatalf("B2 相位锁死：%v 窗口内只采到 %d 个样本（需要 %d）——\n"+
			"	真机形态：回显落在「跳过点之后」的盲区里（旧实现跳过时把闸门推走一个 probeInterval=%v）。\n"+
			"	样本落点：%v（good=%d）",
			win, samples, need, pm.probeInterval, got, good)
	}
	// ⭐ 判别性断言：每个回显都必须被"及时"用掉（一次采样机会的时延内）
	for i, dl := range deadlines {
		if i >= len(got) {
			t.Fatalf("第 %d 个回显（T+%v）没有被任何采样点用掉：样本落点 %v", i+1, echoes[i].at, got)
		}
		if got[i] > dl {
			t.Fatalf("采样被推后：第 %d 个样本落在 T+%v，但回显 T+%v 到达 ⇒ 最迟应 T+%v 落样本。\n"+
				"	这就是「跳过时推走一个 probeInterval(%v)」造成的相位锁死（样本落点：%v）",
				i+1, got[i], echoes[i].at, dl, pm.probeInterval, got)
		}
	}
	if good < need {
		t.Fatalf("样本数达标但好样本不足：samples=%d good=%d need=%d", samples, good, need)
	}
	if !p.trialGoodEnough() {
		t.Fatalf("按生产节奏 + 真机回显节奏，试用期应达到通过条件（good=%d samples=%d）", good, samples)
	}
}

// TestTrialSampleGateRetriesOnNextTick ⭐ B2 的**最小机制断言**（与主用例互补，失败信息更直接）：
//
//	钉住 P5 的语义：一次"无新回显"的跳过之后，**下一拍**必须能重试并落样本。
//
// ⚠️ 有牙：把 `trialSampleStep` 的"无新回显"分支恢复成 `Store(now)` ⇒ 本用例红
// （下一拍被闸门挡回，实际 samples=0）。
func TestTrialSampleGateRetriesOnNextTick(t *testing.T) {
	pm, p, T := newB2TrialPath(t)
	tick := pm.checkInterval
	if tick <= 0 {
		tick = defaultCheckInterval
	}

	// ① T+probeInterval：闸门首次合格，但**本窗内没有新回显** ⇒ 不落样本
	p.trialSampleStep(T.Add(pm.probeInterval))
	if n := p.trialSamples.Load(); n != 0 {
		t.Fatalf("无新回显时不得落样本（事实驱动判据），实际 samples=%d", n)
	}

	// ② 回显到达（采样点之后 500ms —— 真机"撞拍"形态）
	p.lastEcho.Store(T.Add(pm.probeInterval + 500*time.Millisecond).UnixMilli())

	// ③ **下一拍**（checkInterval 之后）必须能落样本 —— 这就是 P5 的语义
	p.trialSampleStep(T.Add(pm.probeInterval + tick))
	if n := p.trialSamples.Load(); n != 1 {
		t.Fatalf("跳过之后**下一拍**（+%v）应能落样本；实际 samples=%d ——\n"+
			"	若为 0，说明「无新回显」时把闸门推进了一个 probeInterval(%v)（相位锁死）",
			tick, n, pm.probeInterval)
	}
}
