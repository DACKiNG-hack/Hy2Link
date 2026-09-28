package quic

// vpn-tool/backend/quic/peertable_test.go
//
// ⭐ 1b-4 第 2 步-A（I1）：对端质量表的单元用例。
//
// 覆盖（对应实施计划 §5 + §4.1.1 的窗口扫描表）：
//   - 三档语义：好 ⇒ HasGoodQuality；差 ⇒ **不跳过**；不可打洞 ⇒ Unpunchable
//   - TTL 分层：好/差 45min；nat-symmetric 30min；punch-timeout 10min；到点即 miss
//   - **重连不清空**（由构造保证，见 §9.2.1）：这里测「同一实例跨管理器重建仍有效」的语义前提
//   - **TTL 不延长**：同结论重复写 ⇒ Expire 不变；结论变了 ⇒ 重算 + 清强制重试标记
//   - **强制重试原子性**（W-1）：并发 N 个 TryConsumeForcedRetry ⇒ 恰 1 个 true
//   - **消费不双罚**（§9.3）：同结论重复写后 ForcedRetryUsed 仍为 true 且 Expire 不变
//   - 容量上限 + LRU（§9.2.3）：满表时淘汰 LastTouch 最旧；Lookup 不改 At
//   - 惰性清理（§9.2.4）：过期项在 ≤64 次调用后被清、**零新 goroutine**

import (
	"sync"
	"testing"
	"time"
)

// fakeClock 可手动推进的时钟
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// newTestPeerTable 造一个用假时钟驱动的表（注入后不再改时钟函数本身）
func newTestPeerTable() (*peerTable, *fakeClock) {
	tbl := newPeerTable()
	clk := newFakeClock()
	tbl.setClock(clk.now) // 在并发使用之前注入（文件头契约）
	return tbl, clk
}

func vip(s string) [4]byte { return ip4(s) }

// TestPeerTablePeekDoesNotTouchLRU ⭐ 第 2 步-B review 追问 1：
//
//	`Peek` 必须**纯读**（不刷新 `LastTouch`），`Lookup` 必须刷新（服务 LRU）。
//	这条分工是对外契约：预打洞靠 `Peek` 读「最近通信时刻」做加权排序，
//	若它用了 `Lookup`，看一眼就把该对端刷成「刚刚通信过」⇒ 排序失真 + LRU 被读取干扰。
//
// ⚠️ 有牙：把 `Peek` 的实现改成 `return t.Lookup(vip)` ⇒ 第一段立刻红。
//
// ⭐⭐ A1 收尾（2026-09-27，review 追问 2 落地）：**测试侧读法纪律** ——
//
//	`Lookup` 有副作用（刷 `LastTouch`），所以「只是读个值」的断言一律用 `Peek`，
//	否则测试自己会污染同包内的 LRU/排序类断言（这正是本条用例守的契约）。
//	**只有**下面 3 类测试可以（且必须）用 `Lookup`：
//
//	| 测试 | 为什么必须 `Lookup` |
//	|---|---|
//	| `TestPeerTablePeekDoesNotTouchLRU` 第 ② 段 | 断言的就是「`Lookup` 会刷 `LastTouch`」这条契约本身 |
//	| `TestPeerTableCapacityLRU` | LRU 淘汰需要「读一下就变最近使用」；且断言 `Lookup` 不改 `At` |
//	| `TestPeerTableLazyPruneNoGoroutine` | 惰性清理由 `Lookup`/`Record` 触发，改用 `Peek` 就测不到 prune |
//
//	其余读取（Kind/TTL/ForcedRetryUsed/miss 判定）**全部**用 `Peek`；`Unpunchable()` 是
//
//	生产软跳过判据，用例照原样调用（它内部走 `Lookup` 属既有行为，不在测试侧改写）。
func TestPeerTablePeekDoesNotTouchLRU(t *testing.T) {
	tbl, clk := newTestPeerTable()
	peer := vip("192.168.30.12")
	tbl.Record(peer, peerOutcome{Kind: peerGood, Reason: P2PReasonOKDirect})

	base, ok := tbl.Peek(peer)
	if !ok {
		t.Fatal("前置：应有记录")
	}
	clk.advance(time.Minute)

	// ① Peek：值不变（LastTouch 仍是写入时刻）
	p1, _ := tbl.Peek(peer)
	if !p1.LastTouch.Equal(base.LastTouch) {
		t.Fatalf("`Peek` **不得**刷新 LastTouch：期望 %v，实际 %v", base.LastTouch, p1.LastTouch)
	}
	// 再 Peek 一次也一样（纯读 ⇒ 幂等）
	p2, _ := tbl.Peek(peer)
	if !p2.LastTouch.Equal(base.LastTouch) {
		t.Fatalf("`Peek` 必须幂等，实际 %v", p2.LastTouch)
	}

	// ② Lookup：必须刷新到「现在」（这是 LRU 的唯一动力，行为**逐字未改**）
	l1, _ := tbl.Lookup(peer)
	if !l1.LastTouch.After(base.LastTouch) {
		t.Fatalf("`Lookup` 必须刷新 LastTouch（LRU 依赖它）：期望 > %v，实际 %v",
			base.LastTouch, l1.LastTouch)
	}
	if !l1.LastTouch.Equal(clk.now()) {
		t.Fatalf("`Lookup` 应刷成当前时刻 %v，实际 %v", clk.now(), l1.LastTouch)
	}
	// ③ 过期项在 Peek 里同样是 miss（与 Lookup 一致）
	clk.advance(peerTTLGood + time.Minute)
	if _, ok := tbl.Peek(peer); ok {
		t.Fatal("过期记录在 `Peek` 里必须是 miss（与 Lookup 口径一致）")
	}
}

// TestPeerTableThreeKinds ⭐ 三档语义（差 = 降优先级但**不跳过**）
func TestPeerTableThreeKinds(t *testing.T) {
	tbl, _ := newTestPeerTable()

	tbl.Record(vip("192.168.30.11"), peerOutcome{Kind: peerGood, Reason: P2PReasonOKDirect, RTTMs: 12})
	tbl.Record(vip("192.168.30.12"), peerOutcome{Kind: peerPoor, Reason: P2PReasonProbeTimeout})
	tbl.Record(vip("192.168.30.13"), peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonNATSymmetric})

	// 好记录：用 `Peek` + `Kind`（A1 起 `HasGoodQuality` 已删除；判据只有一处真相源）
	//
	//	⚠️ 读法纪律：本用例只**看结论**、不看「最近通信时刻」⇒ 必须用 `Peek`（纯读）。
	//	用 `Lookup` 会把 3 个对端的 `LastTouch` 一起刷成现在，污染本包内 LRU 排序类断言。
	if q, ok := tbl.Peek(vip("192.168.30.11")); !ok || q.Kind != peerGood {
		t.Fatalf("好记录应命中 Kind==peerGood，实际 ok=%v kind=%v", ok, q.Kind)
	}
	// 差：既不是「好」，也**不是**「不可打洞」⇒ 不会跳过打洞（只是降优先级）
	if q, ok := tbl.Peek(vip("192.168.30.12")); ok && q.Kind == peerGood {
		t.Fatal("差记录不得算「质量好」")
	}
	if _, ok := tbl.Unpunchable(vip("192.168.30.12")); ok {
		t.Fatal("差记录**不得**被当成「不可打洞」（用户拍板：降优先级但不跳过）")
	}
	// 不可打洞
	if _, ok := tbl.Unpunchable(vip("192.168.30.13")); !ok {
		t.Fatal("nat-symmetric 应命中 Unpunchable")
	}
	if q, ok := tbl.Peek(vip("192.168.30.13")); ok && q.Kind == peerGood {
		t.Fatal("不可打洞不得算「质量好」")
	}
	// 无记录
	if q, ok := tbl.Peek(vip("192.168.30.99")); ok && q.Kind == peerGood {
		t.Fatal("无记录的地址不得命中")
	}
	if _, ok := tbl.Peek(vip("192.168.30.99")); ok {
		t.Fatal("无记录的地址 Peek 应 miss")
	}
}

// TestPeerTableTTLTiersAndExpiry ⭐ TTL 分层 + 到点即 miss
func TestPeerTableTTLTiersAndExpiry(t *testing.T) {
	tbl, clk := newTestPeerTable()
	now := clk.now()

	tbl.Record(vip("192.168.30.11"), peerOutcome{Kind: peerGood, Reason: P2PReasonOKDirect})
	tbl.Record(vip("192.168.30.12"), peerOutcome{Kind: peerPoor, Reason: P2PReasonProbeTimeout})
	tbl.Record(vip("192.168.30.13"), peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonNATSymmetric})
	tbl.Record(vip("192.168.30.14"), peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonPunchTimeout})

	want := map[string]time.Duration{
		"192.168.30.11": peerTTLGood,
		"192.168.30.12": peerTTLPoor,
		"192.168.30.13": peerTTLUnpunchableSticky,    // nat-symmetric ⇒ 取长
		"192.168.30.14": peerTTLUnpunchableTransient, // punch-timeout ⇒ 取短
	}
	for s, d := range want {
		q, ok := tbl.Peek(vip(s))
		if !ok {
			t.Fatalf("%s 应有记录", s)
		}
		if got := q.Expire.Sub(now); got != d {
			t.Fatalf("%s 的 TTL 应为 %v，实际 %v", s, d, got)
		}
	}
	// 分层断言本身（防止「两档写反了」）
	if peerTTLUnpunchableSticky <= peerTTLUnpunchableTransient {
		t.Fatal("nat-symmetric 的 TTL 必须长于 punch-timeout（粘性 vs 瞬时）")
	}

	// 推进 40min：超过「不可打洞」短档（10min）与粘性档（30min），但**未满**好/差档（45min）
	clk.advance(40 * time.Minute)
	if _, ok := tbl.Peek(vip("192.168.30.14")); ok {
		t.Fatal("punch-timeout 档（10min）过期应 miss")
	}
	if _, ok := tbl.Peek(vip("192.168.30.13")); ok {
		t.Fatal("nat-symmetric 档（30min）过期应 miss")
	}
	if q, ok := tbl.Peek(vip("192.168.30.11")); !ok || q.Kind != peerGood {
		t.Fatal("好记录此时（40min < 45min）仍未过期且应为 peerGood")
	}
	if _, ok := tbl.Peek(vip("192.168.30.12")); !ok {
		t.Fatal("差记录此时（40min < 45min）仍未过期")
	}
	// 再推进 6min（总 46min > 45min）⇒ 好/差也过期
	clk.advance(6 * time.Minute)
	for _, s := range []string{"192.168.30.11", "192.168.30.12"} {
		if _, ok := tbl.Peek(vip(s)); ok {
			t.Fatalf("%s 已过期应 miss", s)
		}
	}
}

// TestPeerTableTTLNotExtendedOnSameKind ⭐ 拍板项「TTL 不延长」+ §9.3「强制重试不双罚」
func TestPeerTableTTLNotExtendedOnSameKind(t *testing.T) {
	tbl, clk := newTestPeerTable()

	tbl.Record(vip("192.168.30.13"), peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonNATSymmetric})
	first, _ := tbl.Peek(vip("192.168.30.13"))
	// 先用掉那 1 次强制重试
	if !tbl.TryConsumeForcedRetry(vip("192.168.30.13")) {
		t.Fatal("第一次应放行")
	}

	// 时间推进一半 TTL，然后**同结论**重复写（= 强制重试失败/又观测到一次打不通）
	clk.advance(peerTTLUnpunchableSticky / 2)
	tbl.Record(vip("192.168.30.13"), peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonNATSymmetric, RTTMs: 99})
	second, ok := tbl.Peek(vip("192.168.30.13"))
	if !ok {
		t.Fatal("记录应仍在")
	}
	if !second.Expire.Equal(first.Expire) {
		t.Fatalf("同结论重复写**不得**延长 TTL：首次 %v，现在 %v", first.Expire, second.Expire)
	}
	if !second.At.Equal(first.At) {
		t.Fatalf("同结论重复写不得改动观测时刻 At：首次 %v，现在 %v", first.At, second.At)
	}
	if !second.ForcedRetryUsed {
		t.Fatal("同结论重复写不得清零 ForcedRetryUsed（否则会再放行一次 ⇒ 违反 D3 的「1 次」）")
	}
	if second.RTTMs != 99 {
		t.Fatalf("同结论重复写应刷新度量，实际 RTT=%d", second.RTTMs)
	}
	// 于是原 TTL 到点后记录消失（用户不用多等）
	clk.advance(peerTTLUnpunchableSticky) // 总时长已超一个 TTL
	if _, ok := tbl.Peek(vip("192.168.30.13")); ok {
		t.Fatal("原 TTL 到点后应 miss（不因重复写而延长）")
	}
}

// TestPeerTableKindChangeResetsTTLAndRetry ⭐ 结论变了 ⇒ 覆盖 + 重算 TTL + 清强制重试
func TestPeerTableKindChangeResetsTTLAndRetry(t *testing.T) {
	tbl, clk := newTestPeerTable()
	v := vip("192.168.30.13")

	tbl.Record(v, peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonNATSymmetric})
	old, _ := tbl.Peek(v)
	if !tbl.TryConsumeForcedRetry(v) {
		t.Fatal("第一次应放行")
	}
	clk.advance(time.Minute)

	// 强制重试**成功** ⇒ 结论变成「好」
	tbl.Record(v, peerOutcome{Kind: peerGood, Reason: P2PReasonOKDirect, RTTMs: 8})
	q, ok := tbl.Peek(v)
	if !ok || q.Kind != peerGood {
		t.Fatalf("结论应被覆盖为「好」，实际 %+v ok=%v", q, ok)
	}
	if q.ForcedRetryUsed {
		t.Fatal("结论变化必须清零 ForcedRetryUsed（新记录是新 TTL、新额度）")
	}
	if !q.Expire.After(old.Expire) {
		t.Fatalf("结论变化应重算 TTL（新过期时刻晚于旧的），旧的 %v 新的 %v", old.Expire, q.Expire)
	}
	if got := q.Expire.Sub(clk.now()); got != peerTTLGood {
		t.Fatalf("新结论应按自己的档取 TTL（%v），实际 %v", peerTTLGood, got)
	}
	if q2, ok := tbl.Peek(v); !ok || q2.Kind != peerGood {
		t.Fatal("覆盖为「好」后应命中 Kind==peerGood")
	}
	if _, ok := tbl.Unpunchable(v); ok {
		t.Fatal("覆盖后不得再算「不可打洞」")
	}
}

// TestPeerTableForcedRetryIsAtomic ⭐ W-1：并发消费只放行 1 个
func TestPeerTableForcedRetryIsAtomic(t *testing.T) {
	tbl, _ := newTestPeerTable()
	v := vip("192.168.30.13")
	tbl.Record(v, peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonNATSymmetric})

	const n = 20
	var wg sync.WaitGroup
	var granted int32
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tbl.TryConsumeForcedRetry(v) {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if granted != 1 {
		t.Fatalf("并发 %d 次消费应**恰好 1 次**放行，实际 %d（非原子 ⇒ TTL 内多次重试）", n, granted)
	}

	// 过期后重新放行（记录消失 ⇒ 不参与机制 ⇒ 返回 true）
	_, clk := tbl, (*fakeClock)(nil)
	_ = clk
	if !tbl.TryConsumeForcedRetry(vip("192.168.30.99")) {
		t.Fatal("无记录时应返回 true（不涉及该机制，由其它判据决定）")
	}
	// 「好」记录也不参与强制重试机制
	tbl.Record(vip("192.168.30.11"), peerOutcome{Kind: peerGood, Reason: P2PReasonOKDirect})
	if !tbl.TryConsumeForcedRetry(vip("192.168.30.11")) {
		t.Fatal("「好」记录不涉及强制重试 ⇒ 应返回 true")
	}
}

// TestPeerTableCapacityLRU ⭐ §9.2.3：容量上限 + LRU 淘汰；Lookup 不改 At
func TestPeerTableCapacityLRU(t *testing.T) {
	tbl, clk := newTestPeerTable()

	// 填满（用 10.0.x.y 造够 1024 个不同键）。
	// ⚠️ 逐条推进时钟 1s ⇒ 让每个键的 LastTouch **严格递增**，
	//    否则「谁是 LRU」会依赖 map 的随机遍历顺序（第一版就是这么写的 ⇒ 用例假红）。
	for i := 0; i < peerTableMaxEntries; i++ {
		clk.advance(time.Second)
		v := [4]byte{10, byte(i >> 8), byte(i & 0xFF), 1}
		tbl.Record(v, peerOutcome{Kind: peerGood, Reason: P2PReasonOKDirect})
	}
	if got := tbl.Len(); got != peerTableMaxEntries {
		t.Fatalf("应恰好填满 %d 条，实际 %d", peerTableMaxEntries, got)
	}

	// 让**第一条**成为最久未使用（推进时钟后再读第二条 ⇒ 第二条的 LastTouch 更新）
	clk.advance(time.Minute)
	second := [4]byte{10, 0, 1, 1}
	if _, ok := tbl.Lookup(second); !ok {
		t.Fatal("第二条应存在")
	}
	atBefore, _ := tbl.Lookup(second)

	// 再写入一条新键 ⇒ 必须淘汰 LastTouch 最旧的那条（第一条）
	third := [4]byte{10, 9, 9, 9}
	tbl.Record(third, peerOutcome{Kind: peerGood, Reason: P2PReasonOKDirect})
	if got := tbl.Len(); got != peerTableMaxEntries {
		t.Fatalf("淘汰后仍应保持 %d 条（不是无限增长），实际 %d", peerTableMaxEntries, got)
	}
	first := [4]byte{10, 0, 0, 1}
	if _, ok := tbl.Lookup(first); ok {
		t.Fatal("最久未使用的一条应被淘汰")
	}
	if _, ok := tbl.Lookup(second); !ok {
		t.Fatal("被读过的记录不得被淘汰（LRU 应按 LastTouch）")
	}
	if _, ok := tbl.Lookup(third); !ok {
		t.Fatal("新写入的记录应在表里")
	}
	// Lookup 不得改动观测时刻 At（否则日志/诊断会说谎），但**应**推进 LastTouch
	clk.advance(time.Millisecond) // 假时钟不会自走 ⇒ 手动推进，否则两次 Lookup 同刻
	atAfter, _ := tbl.Lookup(second)
	if !atAfter.At.Equal(atBefore.At) {
		t.Fatalf("Lookup 不得改动 At：前 %v 后 %v", atBefore.At, atAfter.At)
	}
	if !atAfter.LastTouch.After(atBefore.LastTouch) {
		t.Fatalf("Lookup 应推进 LastTouch（LRU 判据），前 %v 后 %v", atBefore.LastTouch, atAfter.LastTouch)
	}
}

// TestPeerTableLazyPruneNoGoroutine ⭐ §9.2.4：惰性清理（零新 goroutine）
func TestPeerTableLazyPruneNoGoroutine(t *testing.T) {
	tbl, clk := newTestPeerTable()
	v := vip("192.168.30.13")
	tbl.Record(v, peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonPunchTimeout})

	// 让记录过期（但不调用任何「删除」接口）
	clk.advance(peerTTLUnpunchableTransient + time.Second)
	if _, ok := tbl.Lookup(v); ok {
		t.Fatal("过期后 Lookup 应 miss")
	}
	if got := tbl.Len(); got != 1 {
		t.Fatalf("Lookup **不得**顺手删除（判定与动作解耦），实际 %d 条", got)
	}

	// 惰性清理：再累计 peerTablePruneEvery 次调用后应被清掉
	for i := 0; i < peerTablePruneEvery+1; i++ {
		_, _ = tbl.Lookup(vip("192.168.30.99")) // 用一个不存在的键制造调用
	}
	if got := tbl.Len(); got != 0 {
		t.Fatalf("惰性清理应在 ≤%d 次调用后清掉过期项，实际仍有 %d 条", peerTablePruneEvery, got)
	}
}

// TestPeerTableReadWriteRaceClean 并发读写（`-race` 下必须干净；同时验证表可并发使用）
func TestPeerTableReadWriteRaceClean(t *testing.T) {
	tbl, clk := newTestPeerTable()
	v := vip("192.168.30.13")

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				switch i % 4 {
				case 0:
					tbl.Record(v, peerOutcome{Kind: peerUnpunchable, Reason: P2PReasonNATSymmetric})
				case 1:
					_, _ = tbl.Lookup(v)
				case 2:
					_, _ = tbl.Peek(v)
				case 3:
					_ = tbl.TryConsumeForcedRetry(v)
				}
				clk.advance(time.Millisecond)
			}
		}(i)
	}
	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()
}
