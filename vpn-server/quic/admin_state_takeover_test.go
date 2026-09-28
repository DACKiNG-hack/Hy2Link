package quic

// admin_state_takeover_test.go —— **面板趋势图 bug（独立小切片）** 的第二层用例（quic 包）
//
// 覆盖的是 **A″ 的完整触发链**（单元层覆盖不到）：
//
//	① 数据连接 1 建立 ⇒ 登记 + `ensureOnline`（生产函数）⇒ 条目存在、计数开始累积；
//	② 数据连接 2 **接管同一 VIP、身份相同（同账号同 peer）** ⇒ 走"复用分支"的语义
//	   （`cs.setBulkStreams(conn2, …)`，**同一个 `cs` 对象**；`shard.conns[vip]` 与连接 1 手里的 `cs` 是同一指针）
//	   ⇒ 随后**必须**再走一次 `ensureOnline`（这就是"复用分支也要维护在线状态"）；
//	③ 连接 1 的**陈旧收尾**随后执行（`cleanupDataConnVIP(..., conn1, ...)`）。
//
// 修复前：② 不维护在线状态（`OnConnect` 原先只在"新建"分支）⇒ 条目可能缺失；且 ③ 的判据是
//	`cur != cs`（同一对象 ⇒ 判据为假）⇒ **陈旧收尾会把条目删掉** ⇒ `AddTraffic` 静默丢弃
//	⇒ Σ 每客户端 = 0 ⇒ **面板趋势图恒 0**。
// 修复后：② 走 upsert（保留计数、刷新元数据）⇒ 条目在；③ 判据换成
//	`cur.getDataConn() != myDataConn`（conn1 ≠ conn2）⇒ **陈旧收尾无权清理** ⇒ 条目与计数都保留。
//
// ⚠️ 两条用例都**走生产函数**（`srv.ensureOnline(...)` / `srv.cleanupDataConnVIP(...)`），
//	不是"测试体自己模拟调用"——后者是**假守卫**（实测：注入"把 `ensureOnline` 退回新建分支"，它照样绿）。
//
// ⚠️ 有牙（均已实测）：
//   · 修法 1 判据改回"忽略 `dataConn`" ⇒ `TestStaleCleanupDoesNotDeleteNewEntry` 红；
//   · `ensureOnline` 不再更新已有条目（例如恢复成"无条件新建"）⇒ `TestTakeoverReuseRefreshesAdminEntry` 红。

import (
	"testing"
	"time"

	"vpn-server/admin"
)

// newTakeoverServer 造一个带 `AdminState` 的信号测试服务端（本文件两条用例共用）。
func newTakeoverServer(t *testing.T) *DataChannelServer {
	t.Helper()
	srv, _ := newSignalTestServer(t, true)
	srv.adminState = admin.NewAdminState("test")
	return srv
}

// TestTakeoverReuseRefreshesAdminEntry ⭐⭐ 修法 2 的**调用面**（复用分支必须维护条目）：
//
//	同一 VIP、**身份相同**的接管（= 生产里的"复用分支"）⇒
//	  · 条目必须存在；
//	  · `BytesIn/BytesOut` 必须**保留**（不得倒退）；
//	  · `RealAddr` / `LastSeen` 必须**刷新**（证明确实走了 upsert 而不是"什么都没做"）。
func TestTakeoverReuseRefreshesAdminEntry(t *testing.T) {
	srv := newTakeoverServer(t)
	const vip = "192.168.30.11"

	// ① 连接 1 建立（等价于 handleBulkDataConn 的"新建分支"：setBulkStreams → register → ensureOnline）
	cs := mkStream(vip, "alice")
	conn1 := testConn()
	cs.setBulkStreams(conn1, nil, nil)
	srv.register(cs.vipBytes, cs)
	srv.ensureOnline(cs, "1.2.3.4:1000") // ← **生产函数**（两条分支共用）
	srv.adminState.AddTraffic(vip, 111, 222)

	snap := srv.adminState.Snapshot()
	if len(snap.Clients) != 1 {
		t.Fatalf("前置：条目应存在，实际 %d 条", len(snap.Clients))
	}
	before := snap.Clients[0]
	if before.BytesIn != 111 || before.BytesOut != 222 {
		t.Fatalf("前置：计数应为 111/222，实际 %d/%d", before.BytesIn, before.BytesOut)
	}

	// ② 连接 2 接管同一 VIP、身份相同（复用既有 cs —— 与生产复用分支同形）
	time.Sleep(2 * time.Millisecond)
	conn2 := testConn()
	cs.setBulkStreams(conn2, nil, nil)
	// ⭐ **走生产函数**：这正是 handleBulkDataConn 在复用分支之后要做的事
	srv.ensureOnline(cs, "1.2.3.4:2000")

	after := srv.adminState.Snapshot()
	if len(after.Clients) != 1 {
		t.Fatalf("接管后条目数应仍为 1，实际 %d", len(after.Clients))
	}
	c := after.Clients[0]
	if c.BytesIn != 111 || c.BytesOut != 222 {
		t.Fatalf("接管后**不得清零计数**（面板数字会倒退）：期望 111/222，实际 %d/%d", c.BytesIn, c.BytesOut)
	}
	if c.RealAddr != "1.2.3.4:2000" {
		t.Fatalf("接管后应刷新元数据：期望 1.2.3.4:2000，实际 %q", c.RealAddr)
	}
	if !c.LastSeen.After(before.LastSeen) {
		t.Fatalf("接管后 LastSeen 应刷新：之前 %v，之后 %v", before.LastSeen, c.LastSeen)
	}
}

// TestStaleCleanupDoesNotDeleteNewEntry ⭐⭐ A″ 的**主链**（修法 1 的完整语义）：
//
//	连接 1 的**陈旧收尾**（在连接 2 接管之后才跑）⇒
//	  · `cleanupDataConnVIP` 必须返回 **false**（无权清理）；
//	  · 该 VIP 的登记必须**仍在**（连接 2 的）；
//	  · `AdminState` 条目与计数必须**原封不动**（不得被 `OnDisconnect` 删掉）。
func TestStaleCleanupDoesNotDeleteNewEntry(t *testing.T) {
	srv := newTakeoverServer(t)
	const vip = "192.168.30.11"

	// ① 连接 1 建立
	cs := mkStream(vip, "alice")
	conn1 := testConn()
	cs.setBulkStreams(conn1, nil, nil)
	srv.register(cs.vipBytes, cs)
	srv.ensureOnline(cs, "1.2.3.4:1000")
	srv.adminState.AddTraffic(vip, 4096, 8192)

	// ② 连接 2 接管（身份相同 ⇒ 复用同一个 cs，只换 dataConn）
	conn2 := testConn()
	cs.setBulkStreams(conn2, nil, nil)
	srv.ensureOnline(cs, "1.2.3.4:2000")

	// ③ 连接 1 的陈旧收尾（它手里的身份是 conn1，已不是当前登记）
	if cleaned := srv.cleanupDataConnVIP(cs.vipBytes, vip, conn1, "alice", "1.2.3.4:1000"); cleaned {
		t.Fatal("陈旧收尾**无权**清理（当前登记的数据连接已是连接 2）——判据应为 conn1 != cur.getDataConn()")
	}
	// 登记必须仍在（且仍是同一个 cs —— 接管复用的语义）
	if cur, ok := srv.lookup(cs.vipBytes); !ok || cur != cs {
		t.Fatalf("陈旧收尾不得摘掉连接 2 的登记：ok=%v cur=%p cs=%p", ok, cur, cs)
	}
	// ⭐ 核心断言：AdminState 条目与计数原封不动（这正是"趋势图恒 0"的直接成因）
	snap := srv.adminState.Snapshot()
	if len(snap.Clients) != 1 {
		t.Fatalf("陈旧收尾把在线条目删掉了（趋势图会因此恒 0）：条目数 %d", len(snap.Clients))
	}
	if got := snap.Clients[0].BytesIn; got != 4096 {
		t.Fatalf("条目计数被破坏：期望 BytesIn=4096，实际 %d", got)
	}
	if misses := srv.adminState.TrafficMisses(); misses != 0 {
		t.Fatalf("本次流程不应产生「未知 key」丢弃：TrafficMisses=%d", misses)
	}

	// ④ 连接 2 自己的收尾仍然要能正常清理（否则会"只进不出"）
	if cleaned := srv.cleanupDataConnVIP(cs.vipBytes, vip, conn2, "alice", "1.2.3.4:2000"); !cleaned {
		t.Fatal("当前占用者的收尾应能正常清理")
	}
	if _, ok := srv.lookup(cs.vipBytes); ok {
		t.Fatal("当前占用者收尾后登记应被摘除")
	}
	if got := len(srv.adminState.Snapshot().Clients); got != 0 {
		t.Fatalf("当前占用者收尾后在线条目应被删（OnDisconnect），实际 %d 条", got)
	}
}
