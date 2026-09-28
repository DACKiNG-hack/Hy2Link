package admin

// admin_state_reconnect_test.go —— **面板趋势图 bug（独立小切片）** 的先红用例（第一层）
//
// 背景（已定位，见交付说明）：客户端连着且流量在走，但服务端面板「流量趋势图」恒 0，
// 而「用户管理」的已用流量有值。根因链（两处缺陷，均与 P2P 无关 ⇒ 旧版也有）：
//
//	缺陷 ①（本文件覆盖）：`AdminState.OnConnect` 是"**重建**"语义（新建 `ClientInfo` ⇒ 计数从 0）
//	  ⇒ 任何"接管/重连后再次调用 OnConnect"的路径都会**清零累计**（面板数字倒退）；
//	  反之若不调用 ⇒ 条目可能缺失 ⇒ `AddTraffic` **静默丢弃** ⇒ Σ 每客户端 = 0 ⇒ 趋势图 0。
//	缺陷 ②（本文件覆盖）：`AddTraffic` 在 key 不存在时**静默丢弃**（`if c, ok := ...; ok` 无 else）
//	  ⇒ 该缺陷潜伏多年而无人发现（《工程纪律》§3 第 17 条：不可见分支必须可见化）。
//	缺陷 ③（第二层用例，quic 包，跟修法同批）：接管时 `shard.conns[vip]` 与"旧连接的 cs"是**同一对象**
//	  ⇒ 陈旧收尾（旧连接超时）仍会 `delete` 掉新流的条目（判据必须换成 **`dataConn` 身份**）。
//
// 断言原则（review 要求）：**每步断言"具体字段"**，不用 "clients 非空" 这种假绿判据。

import (
	"testing"
	"time"
)

// TestOnConnectIsUpsertAndKeepsCounters ⭐ 先红（修法 2 的内核）：
//
//	同一 VIP 再次 `OnConnect`（接管/重连）⇒ **必须保留 `BytesIn/BytesOut`**，并**刷新 `LastSeen`**。
//
// ⚠️ 现状必红：`OnConnect` 无条件 `s.clients[key] = &ClientInfo{...}` ⇒ 计数归零。
//
// ⚠️ 有牙（修完后的反向验证）：把 upsert 改回"无条件新建" ⇒ 本用例立刻红。
func TestOnConnectIsUpsertAndKeepsCounters(t *testing.T) {
	st := NewAdminState("test")
	const vip = "192.168.30.12"

	t0 := time.Now()
	st.OnConnect(vip, "alice", "multi", vip, "1.2.3.4:1000")
	st.AddTraffic(vip, 4096, 8192)

	before := st.Snapshot()
	if len(before.Clients) != 1 {
		t.Fatalf("前置：应恰好 1 个客户端，实际 %d", len(before.Clients))
	}
	c0 := before.Clients[0]
	if c0.BytesIn != 4096 || c0.BytesOut != 8192 {
		t.Fatalf("前置：计数应为 4096/8192，实际 %d/%d", c0.BytesIn, c0.BytesOut)
	}
	if c0.Username != "alice" {
		t.Fatalf("前置：用户名应为 alice，实际 %q", c0.Username)
	}

	// 模拟"接管/重连"：同一 VIP 再次 OnConnect（新 flow、新 realAddr）
	time.Sleep(2 * time.Millisecond) // 让 LastSeen 可区分
	st.OnConnect(vip, "alice", "multi", vip, "1.2.3.4:2000")

	after := st.Snapshot()
	if len(after.Clients) != 1 {
		t.Fatalf("接管后在线数应仍为 1（**不得**出现重复条目），实际 %d", len(after.Clients))
	}
	c1 := after.Clients[0]

	// ① 计数必须保留（不清零）
	if c1.BytesIn != 4096 || c1.BytesOut != 8192 {
		t.Fatalf("接管后**不得清零累计计数**（面板数字会倒退）：应为 4096/8192，实际 %d/%d",
			c1.BytesIn, c1.BytesOut)
	}
	// ② 元数据必须刷新（证明确实走了 upsert，而不是"什么都没做"）
	if c1.RealAddr != "1.2.3.4:2000" {
		t.Fatalf("接管后 RealAddr 应刷新为 1.2.3.4:2000，实际 %q（说明 OnConnect 没有更新元数据）", c1.RealAddr)
	}
	if !c1.LastSeen.After(c0.LastSeen) {
		t.Fatalf("接管后 LastSeen 应被刷新：接管前 %v，接管后 %v", c0.LastSeen, c1.LastSeen)
	}
	// ③ 首次连接时刻保留（它是"这条在线会话从何时开始"的语义，接管不算新会话）
	if !c1.Connected.Equal(c0.Connected) {
		t.Fatalf("接管不应改变 Connected（首连时刻）：之前 %v，之后 %v", c0.Connected, c1.Connected)
	}
	// ④ 计数继续累加（接管后新流量应叠加在保留值之上）
	st.AddTraffic(vip, 100, 200)
	final := st.Snapshot().Clients[0]
	if final.BytesIn != 4196 || final.BytesOut != 8392 {
		t.Fatalf("接管后新流量应叠加：期望 4196/8392，实际 %d/%d", final.BytesIn, final.BytesOut)
	}
	_ = t0
}

// TestOnConnectDifferentIdentityStartsFreshSession ⭐⭐ 身份不混合（review 追问 7 点名的守卫缺口）：
//
//	同一个 VIP 被**回收给别的账号**（`Username` 变化）时再次 `OnConnect` ⇒
//	**必须视为新会话**：计数归零、`Connected` 重置、元数据全部换成新账号。
//
// ⚠️ 为什么必须有这条：修法 2 引入 upsert（保留计数）后，若同一个 key 身份变了还保留计数，
//
//	就会把**上一个账号的流量**算到**新账号**头上（计费/配额串号）——这是比"面板显示 0"更严重的问题。
//
// ⚠️ 有牙：把 upsert 改成"只在 !exists 时才新建"（即忽略身份变化，永远保留）⇒ 本用例红。
func TestOnConnectDifferentIdentityStartsFreshSession(t *testing.T) {
	st := NewAdminState("test")
	const vip = "192.168.30.12"

	st.OnConnect(vip, "alice", "multi", vip, "1.2.3.4:1000")
	st.AddTraffic(vip, 4096, 8192)
	before := st.Snapshot().Clients[0]

	time.Sleep(2 * time.Millisecond)
	// 同一 VIP 换了客户端（alice → bob）
	st.OnConnect(vip, "bob", "multi", vip, "5.6.7.8:2000")

	after := st.Snapshot()
	if len(after.Clients) != 1 {
		t.Fatalf("同 VIP 换客户端后在线数应仍为 1，实际 %d", len(after.Clients))
	}
	c := after.Clients[0]

	if c.Username != "bob" {
		t.Fatalf("身份必须换成新账号：期望 bob，实际 %q", c.Username)
	}
	if c.BytesIn != 0 || c.BytesOut != 0 {
		t.Fatalf("换账号后计数必须归零（否则把 alice 的流量算到 bob 头上）：实际 %d/%d",
			c.BytesIn, c.BytesOut)
	}
	if !c.Connected.After(before.Connected) {
		t.Fatalf("换账号应视为新会话 ⇒ Connected 应重置为更晚时刻：之前 %v，之后 %v",
			before.Connected, c.Connected)
	}
	if c.RealAddr != "5.6.7.8:2000" {
		t.Fatalf("元数据应换成新连接：期望 5.6.7.8:2000，实际 %q", c.RealAddr)
	}
}

// TestAddTrafficMissIsCounted ⭐ 先红（修法 3 = 《工程纪律》§3 第 17 条）：
//
//	`AddTraffic` 遇到不存在的 key（= 正常不该发生）⇒ **必须可观测**：
//	至少有一个可查询计数器（本轮定：`AdminState.TrafficMisses()`）。
//
// ⚠️ 现状必红：查不到就静默丢弃，无任何信号 ⇒ 这正是"趋势图恒 0"能潜伏多年的原因。
//
// ⚠️ 有牙：把计数器改回不增 ⇒ 本用例红。注意本用例**不依赖日志文本**（§3 第 12 条）。
func TestAddTrafficMissIsCounted(t *testing.T) {
	st := NewAdminState("test")

	if got := st.TrafficMisses(); got != 0 {
		t.Fatalf("前置：新状态不应有丢失计数，实际 %d", got)
	}

	// ① 未知 key ⇒ 计入丢失（且**不 panic、不影响总量语义**）
	st.AddTraffic("192.168.30.99", 10, 20)
	if got := st.TrafficMisses(); got != 1 {
		t.Fatalf("未知 key 的 AddTraffic 必须计入丢失计数，期望 1，实际 %d", got)
	}
	// ② 已知 key ⇒ 不计入丢失
	st.OnConnect("192.168.30.12", "alice", "multi", "192.168.30.12", "1.2.3.4:1000")
	st.AddTraffic("192.168.30.12", 10, 20)
	if got := st.TrafficMisses(); got != 1 {
		t.Fatalf("已知 key 不应计入丢失，期望仍为 1，实际 %d", got)
	}
	// ③ 再次未知 ⇒ 继续累加（可观测的"漏记次数"）
	st.AddTraffic("192.168.30.98", 1, 1)
	if got := st.TrafficMisses(); got != 2 {
		t.Fatalf("丢失计数应累加，期望 2，实际 %d", got)
	}
}
