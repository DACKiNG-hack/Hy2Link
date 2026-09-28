package quic

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func newSignalTestClient() *Hysteria2Client {
	return NewHysteria2Client("1.2.3.4", 8443, 8444, "user", "pass", true, "", "", false)
}

// TestSignalQueryGuards 信令查询的前置条件必须给出清晰错误（且不 panic）
func TestSignalQueryGuards(t *testing.T) {
	c := newSignalTestClient()

	// ① 服务端开关没开（本机开关此时也默认为 false）
	if _, err := c.SignalQuery("192.168.30.12"); err == nil {
		t.Fatal("P2P 未启用时应当报错")
	}

	// ② 服务端开关打开，但 NAT 探测还没完成
	// ⚠️ 本机开关也要开：1b-2A 起 P2PEffective = 服务端 && 本机（两者缺一都算未启用）
	c.p2pServerEnabled = true
	c.p2pLocalEnabled = true
	if _, err := c.SignalQuery("192.168.30.12"); err == nil {
		t.Fatal("NAT 未完成时应当报错")
	}

	// ③ NAT 完成但没有公网地址（探测失败）
	c.natMu.Lock()
	c.natResult = NATProbeResult{Type: NATUnknown}
	c.natReady = true
	c.natMu.Unlock()
	if _, err := c.SignalQuery("192.168.30.12"); err == nil {
		t.Fatal("没有公网地址时应当报错")
	}

	// ④ NAT 完成且有地址，但 peerVIP 为空
	c.natMu.Lock()
	c.natResult = NATProbeResult{
		Type: NATFullCone, PublicAddr: "1.2.3.4:30001",
		ObservedPorts: []uint16{30001}, RespondedServers: 2, MappingIndependent: true,
	}
	c.natMu.Unlock()
	if _, err := c.SignalQuery("   "); err == nil {
		t.Fatal("空 peerVIP 应当报错")
	}

	// ⑤ 一切就绪但没有信令流：P2P 生效、也没有 ctrl 连接可开流
	_, err := c.SignalQuery("192.168.30.12")
	if err == nil || !strings.Contains(err.Error(), "信令流") {
		t.Fatalf("应报「无法建立信令流」，实际 %v", err)
	}

	// ⑥ ⭐ 1b-2A 起 P2PEffective = **服务端开关 && 本机开关**（本机否决已落地）
	if !c.P2PEffective() {
		t.Fatal("两个开关都开时 P2PEffective 应为 true")
	}
	if !c.P2PLocalEnabled() {
		t.Fatal("前置条件：本机开关已置为 true")
	}
	c.ApplyP2PLocal(false) // 本机否决
	if c.P2PEffective() {
		t.Fatal("本机禁用 P2P 时 P2PEffective 必须为 false（本机否决）")
	}
}

// TestSignalSelfInfo 本机上报信息的一致性
func TestSignalSelfInfo(t *testing.T) {
	c := newSignalTestClient()

	if _, _, ok := c.signalSelfInfo(); ok {
		t.Fatal("未探测完成时不应有可上报信息")
	}

	c.natMu.Lock()
	c.natResult = NATProbeResult{Type: NATSymmetric, PublicAddr: "5.6.7.8:40002"}
	c.natReady = true
	c.natMu.Unlock()

	addr, nat, ok := c.signalSelfInfo()
	if !ok || addr != "5.6.7.8:40002" || nat != "symmetric" {
		t.Fatalf("上报信息不对: addr=%q nat=%q ok=%v", addr, nat, ok)
	}

	// 类型为空时兜底成 unknown（服务端白名单里必须有值）
	c.natMu.Lock()
	c.natResult = NATProbeResult{PublicAddr: "5.6.7.8:40002"}
	c.natMu.Unlock()
	if _, nat, ok := c.signalSelfInfo(); !ok || nat != "unknown" {
		t.Fatalf("NAT 类型为空时应兜底为 unknown，实际 %q", nat)
	}
}

// TestSignalMessageJSONShape 锁定**线上字段名**。
//
// 客户端与服务端在各自模块里各有一份 signalMessage 结构，靠 JSON 字段名对齐。
// 这条测试把字段名写死，任何一边改名字都会在这里（或服务端对应测试里）暴露。
func TestSignalMessageJSONShape(t *testing.T) {
	reg, err := json.Marshal(signalMessage{
		Type:       signalMsgTypeRegister,
		PeerVIP:    "192.168.30.12",
		PublicAddr: "1.2.3.4:30001",
		NATType:    "full-cone",
		Metadata:   "ab",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wantReg := `{"type":"register","peerVIP":"192.168.30.12","publicAddr":"1.2.3.4:30001","natType":"full-cone","metadata":"ab"}`
	if string(reg) != wantReg {
		t.Fatalf("register 消息字段名/顺序变了：\n got=%s\nwant=%s", reg, wantReg)
	}

	// 服务端 → 客户端的 peer 响应
	var resp signalMessage
	raw := `{"type":"peer","peerOnline":true,"peerPublicAddr":"5.6.7.8:40002","peerNATType":"symmetric","peerMetadata":"cd"}`
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Type != signalMsgTypePeer || !resp.PeerOnline ||
		resp.PeerPublicAddr != "5.6.7.8:40002" || resp.PeerNATType != "symmetric" || resp.PeerMetadata != "cd" {
		t.Fatalf("peer 响应解析不对: %+v", resp)
	}

	// registered
	var okMsg signalMessage
	if err := json.Unmarshal([]byte(`{"type":"registered"}`), &okMsg); err != nil || okMsg.Type != signalMsgTypeRegistered {
		t.Fatalf("registered 解析不对: %+v err=%v", okMsg, err)
	}

	// error
	var errMsg signalMessage
	if err := json.Unmarshal([]byte(`{"type":"error","error":"boom"}`), &errMsg); err != nil ||
		errMsg.Type != signalMsgTypeError || errMsg.Error != "boom" {
		t.Fatalf("error 解析不对: %+v err=%v", errMsg, err)
	}

	// 消息类型常量必须与服务端一致
	for _, c := range []struct{ got, want string }{
		{signalMsgTypeRegister, "register"},
		{signalMsgTypeRegistered, "registered"},
		{signalMsgTypePeer, "peer"},
		{signalMsgTypeError, "error"},
	} {
		if c.got != c.want {
			t.Fatalf("消息类型常量不一致: got=%q want=%q", c.got, c.want)
		}
	}
}

// signalWireFieldNames 是本协议**全部** 19 个线上字段名
// （客户端与服务端各有一份 signalMessage 结构，靠这组名字对齐）。
//
// ⭐ 1b-2B：新增 `relayRttMs`（中继 RTT 估计，随 peer 应答下发）→ 15 → 16。
// ⭐ 1b-3（A1）：新增 `punchAddrs`（同 socket 的候选地址列表，供对称 NAT 端口预测）→ 16 → 17。
// ⭐ D1-a：新增 `peers`（在线对端列表）+ `peersTruncated`（是否被上限截断）→ 17 → 19。
var signalWireFieldNames = []string{
	"type",
	"peerVIP", "publicAddr", "natType", "metadata",
	"attemptId", "punchAddr", "directFingerprint", "windowMs",
	"punchAddrs",
	"peerOnline", "peerPublicAddr", "peerNATType", "peerMetadata", "peerSignalReady",
	"relayRttMs",
	// ⭐ D1-a
	"peers", "peersTruncated",
	"error",
}

// TestSignalMessageJSONFieldNamesExact 锁死**全部**字段名。
//
// 三重锁（缺一不可 —— 只比较「我设了值的字段」会漏掉新增字段，
// 因为新字段通常带 omitempty，不设值就不会出现在 JSON 里）：
//  1. 反射遍历结构体的每个字段，其 json tag 必须登记在 signalWireFieldNames 里；
//  2. 把名单里每个字段都设上值，序列化后的键集合必须**恰好**等于名单
//     （少一个=改名/漏 omitempty，多一个=有人偷偷加字段）；
//  3. 完整 JSON 字符串比对（连字段顺序一起钉住）+ 回读校验内容。
func TestSignalMessageJSONFieldNamesExact(t *testing.T) {
	typ := reflect.TypeOf(signalMessage{})
	if typ.NumField() != len(signalWireFieldNames) {
		t.Fatalf("结构体字段数(%d) ≠ 锁死的线上字段数(%d)：加了字段就必须同步更新这份名单",
			typ.NumField(), len(signalWireFieldNames))
	}
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			t.Fatalf("字段 %s 缺少可用的 json tag", typ.Field(i).Name)
		}
		found := false
		for _, want := range signalWireFieldNames {
			if want == name {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("字段 %s 的线上名 %q 没有登记在 signalWireFieldNames 里（新增字段必须登记）",
				typ.Field(i).Name, name)
		}
	}

	full := signalMessage{
		Type: "t",
		// register / 打洞 方向
		PeerVIP: "vip", PublicAddr: "1.2.3.4:1", NATType: "full-cone", Metadata: "ab",
		AttemptID: "0123456789abcdef", PunchAddr: "198.51.100.7:40001",
		DirectFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		WindowMs:          10000,
		// ⭐ 1b-3（A1）：候选列表
		PunchAddrs: []string{"198.51.100.7:40001", "198.51.100.7:40002"},
		// peer 方向
		PeerOnline: true, PeerPublicAddr: "5.6.7.8:2", PeerNATType: "symmetric",
		PeerMetadata: "cd", PeerSignalReady: true,
		// ⭐ 1b-2B：中继 RTT
		RelayRttMs: 25,
		// ⭐ D1-a：peers-list 应答
		Peers: []SignalPeerEntry{
			{VIP: "192.168.30.12", SignalReady: true},
			{VIP: "192.168.30.13"},
		},
		PeersTruncated: true,
		// error 方向
		Error: "boom",
	}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != len(signalWireFieldNames) {
		t.Fatalf("字段数不对：got=%d want=%d\n实际 JSON=%s", len(got), len(signalWireFieldNames), raw)
	}
	for _, name := range signalWireFieldNames {
		if _, ok := got[name]; !ok {
			t.Fatalf("缺少线上字段 %q（改名或漏了 omitempty？）\n实际 JSON=%s", name, raw)
		}
	}

	want := `{"type":"t","peerVIP":"vip","publicAddr":"1.2.3.4:1","natType":"full-cone",` +
		`"metadata":"ab","attemptId":"0123456789abcdef","punchAddr":"198.51.100.7:40001",` +
		`"directFingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",` +
		`"windowMs":10000,"punchAddrs":["198.51.100.7:40001","198.51.100.7:40002"],` +
		`"peerOnline":true,"peerPublicAddr":"5.6.7.8:2",` +
		`"peerNATType":"symmetric","peerMetadata":"cd","peerSignalReady":true,"relayRttMs":25,` +
		`"peers":[{"vip":"192.168.30.12","signalReady":true},{"vip":"192.168.30.13"}],` +
		`"peersTruncated":true,"error":"boom"}`
	if string(raw) != want {
		t.Fatalf("字段名/顺序变了：\n got=%s\nwant=%s", raw, want)
	}

	// 反向：这 15 个名字必须都能被解析回结构体
	var back signalMessage
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if back.Type != "t" || back.PeerVIP != "vip" || back.PublicAddr != "1.2.3.4:1" ||
		back.NATType != "full-cone" || back.Metadata != "ab" || !back.PeerOnline ||
		back.PeerPublicAddr != "5.6.7.8:2" || back.PeerNATType != "symmetric" ||
		back.PeerMetadata != "cd" || !back.PeerSignalReady || back.Error != "boom" ||
		back.AttemptID != "0123456789abcdef" || back.PunchAddr != "198.51.100.7:40001" ||
		back.WindowMs != 10000 || back.DirectFingerprint == "" {
		t.Fatalf("回读内容不对: %+v", back)
	}
}

// TestSignalPushTypeNotAResponseType（协议约束 1 的客户端侧锁）
//
//	推送 type 必须与应答类型 {registered, peer, error} 不相交。
//
// 这里直接验证分派行为：装一个等待槽之后，
//   - 推送类型（未知 type）**不能**动等待槽；
//   - 应答类型才会投递进去。
func TestSignalPushTypeNotAResponseType(t *testing.T) {
	responseTypes := []string{signalMsgTypeRegistered, signalMsgTypePeer, signalMsgTypeError}

	c := newSignalTestClient()

	// 已知应答类型集合必须恰好是这三个（多一个都会改变约束 1 的适用范围）
	if len(responseTypes) != 3 {
		t.Fatal("应答类型集合变了，必须重新评估协议约束 1")
	}

	// ① 推送类型不得消耗等待槽
	ch := make(chan signalMessage, 1)
	c.signalMu.Lock()
	c.signalPending = ch
	c.signalMu.Unlock()

	for _, pushType := range []string{"punch-request", "punch-result", "whatever"} {
		if c.isResponseType(pushType) {
			t.Fatalf("%q 被当成了应答类型 —— 推送会投错等待槽（约束 1 被破坏）", pushType)
		}
		c.dispatchSignalMessage(signalMessage{Type: pushType})

		c.signalMu.Lock()
		stillThere := c.signalPending == ch
		c.signalMu.Unlock()
		if !stillThere {
			t.Fatalf("推送 %q 消耗掉了等待槽（约束 1 被破坏）", pushType)
		}
		select {
		case got := <-ch:
			t.Fatalf("推送 %q 被投进了等待槽: %+v", pushType, got)
		default:
		}
	}

	// ② 应答类型必须投递进等待槽
	for _, respType := range responseTypes {
		ch2 := make(chan signalMessage, 1)
		c.signalMu.Lock()
		c.signalPending = ch2
		c.signalMu.Unlock()

		c.dispatchSignalMessage(signalMessage{Type: respType})
		select {
		case got := <-ch2:
			if got.Type != respType {
				t.Fatalf("投递内容不对: %+v", got)
			}
		default:
			t.Fatalf("应答类型 %q 没有被投进等待槽", respType)
		}
	}

	// ③ 无主应答不应 panic（正常丢弃）
	c.dispatchSignalMessage(signalMessage{Type: signalMsgTypePeer})
}

// TestSignalPushJSONShape 主动下行的结构（1b 用）也要锁字段名
func TestSignalPushJSONShape(t *testing.T) {
	raw, err := json.Marshal(SignalPush{
		Type: "punch-request", PeerVIP: "192.168.30.11", PublicAddr: "1.2.3.4:30001",
		NATType: "full-cone", Metadata: "ab", Error: "",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"type":"punch-request","peerVIP":"192.168.30.11","publicAddr":"1.2.3.4:30001","natType":"full-cone","metadata":"ab"}`
	if string(raw) != want {
		t.Fatalf("SignalPush 字段名/顺序变了：\n got=%s\nwant=%s", raw, want)
	}
}
