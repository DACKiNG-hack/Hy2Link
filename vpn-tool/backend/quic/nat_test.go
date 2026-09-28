package quic

import (
	"context"
	"net/netip"
	"os"
	"testing"
)

// TestDetectNATLive 真实调用一次 NAT 探测（需要能访问公网 STUN 服务器）。
//
// 沙箱/离线环境会自动 skip，因此可以安全地保留在测试集里。
// 想看真实结果就手动跑：
//
//	go test -run TestDetectNATLive -v ./backend/quic/
func TestDetectNATLive(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过真实网络测试")
	}
	if os.Getenv("HY_NAT_TEST") == "0" {
		t.Skip("HY_NAT_TEST=0")
	}

	res := detectNAT(context.Background(), nil)

	t.Logf("NAT 类型      = %s", res.Type)
	t.Logf("公网地址      = %q", res.PublicAddr)
	t.Logf("映射端口      = %v", res.ObservedPorts)
	t.Logf("响应的服务器  = %d", res.RespondedServers)
	t.Logf("映射与目的无关= %v", res.MappingIndependent)
	t.Logf("Err           = %v", res.Err)

	// 无论成功失败，类型都必须落在白名单内（不能是空串或非法值）
	if !IsValidNATType(string(res.Type)) {
		t.Fatalf("返回的 NAT 类型不在白名单内: %q", res.Type)
	}

	if res.Err != nil {
		// 网络不可达：只要求优雅降级，不判失败
		if res.Type != NATUnknown {
			t.Fatalf("探测失败时类型应为 unknown，实际 %s", res.Type)
		}
		t.Skipf("STUN 不可达（沙箱/离线环境），已优雅降级为 unknown: %v", res.Err)
	}

	// 探测成功时的一致性约束
	if res.RespondedServers < 2 {
		t.Fatalf("成功结果应至少有 2 台服务器参与，实际 %d", res.RespondedServers)
	}
	if res.PublicAddr == "" {
		t.Fatal("成功结果必须有公网地址")
	}
	if len(res.ObservedPorts) == 0 {
		t.Fatal("成功结果必须有观测端口")
	}
	if res.MappingIndependent && len(res.ObservedPorts) != 1 {
		t.Fatal("映射无关时应当只观测到一个端口")
	}
	if !res.MappingIndependent && res.Type != NATSymmetric {
		t.Fatalf("映射相关时应判定为 symmetric，实际 %s", res.Type)
	}
}

func mustAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	a, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("ParseAddrPort(%q): %v", s, err)
	}
	return a
}

// TestClassifyNAT 验证 NAT 分类逻辑（P2SP 阶段 0 的核心判定）。
//
// 判定规则：同一 socket 发往不同目的地时映射端口是否一致。
// 一致 → 端点无关映射（cone 类）；不一致 → Symmetric。
func TestClassifyNAT(t *testing.T) {
	t.Run("两台服务器观测到同一端口=cone", func(t *testing.T) {
		res := classifyNAT([]netip.AddrPort{
			mustAddrPort(t, "1.2.3.4:30001"),
			mustAddrPort(t, "1.2.3.4:30001"),
		}, 2)
		if res.Type != NATFullCone {
			t.Fatalf("类型应为 %s，实际 %s", NATFullCone, res.Type)
		}
		if !res.MappingIndependent {
			t.Fatal("映射应与目的地址无关")
		}
		if res.PublicAddr != "1.2.3.4:30001" {
			t.Fatalf("公网地址应为 1.2.3.4:30001，实际 %q", res.PublicAddr)
		}
		if len(res.ObservedPorts) != 1 || res.ObservedPorts[0] != 30001 {
			t.Fatalf("观测端口应为 [30001]，实际 %v", res.ObservedPorts)
		}
		if res.Err != nil {
			t.Fatalf("不应有错误: %v", res.Err)
		}
	})

	t.Run("不同端口=Symmetric", func(t *testing.T) {
		res := classifyNAT([]netip.AddrPort{
			mustAddrPort(t, "1.2.3.4:30001"),
			mustAddrPort(t, "1.2.3.4:41234"),
		}, 2)
		if res.Type != NATSymmetric {
			t.Fatalf("类型应为 %s，实际 %s", NATSymmetric, res.Type)
		}
		if res.MappingIndependent {
			t.Fatal("Symmetric 时映射不应与目的地址无关")
		}
		if len(res.ObservedPorts) != 2 {
			t.Fatalf("应观测到 2 个端口，实际 %v", res.ObservedPorts)
		}
		// 端口升序
		if res.ObservedPorts[0] != 30001 || res.ObservedPorts[1] != 41234 {
			t.Fatalf("端口应升序排列，实际 %v", res.ObservedPorts)
		}
	})

	t.Run("同一服务器的多个IP返回不同端口也算Symmetric", func(t *testing.T) {
		res := classifyNAT([]netip.AddrPort{
			mustAddrPort(t, "1.2.3.4:30001"),
			mustAddrPort(t, "5.6.7.8:30009"),
		}, 1)
		if res.Type != NATSymmetric || res.MappingIndependent {
			t.Fatalf("应为 Symmetric，实际 type=%s independent=%v", res.Type, res.MappingIndependent)
		}
	})

	t.Run("只有一台响应=unknown且不误判为cone", func(t *testing.T) {
		res := classifyNAT([]netip.AddrPort{mustAddrPort(t, "1.2.3.4:30001")}, 1)
		if res.Type != NATUnknown {
			t.Fatalf("样本不足时应为 unknown，实际 %s", res.Type)
		}
		if res.Err == nil {
			t.Fatal("样本不足时应有说明性错误")
		}
		// 但仍然保留公网地址（信令阶段仍可用）
		if res.PublicAddr != "1.2.3.4:30001" {
			t.Fatalf("应保留观测到的公网地址，实际 %q", res.PublicAddr)
		}
	})

	t.Run("完全没有响应=unknown", func(t *testing.T) {
		res := classifyNAT(nil, 0)
		if res.Type != NATUnknown {
			t.Fatalf("无响应时应为 unknown，实际 %s", res.Type)
		}
		if res.Err == nil {
			t.Fatal("无响应时应有错误说明")
		}
		if res.PublicAddr != "" {
			t.Fatalf("无响应时公网地址应为空，实际 %q", res.PublicAddr)
		}
		if res.MappingIndependent {
			t.Fatal("无响应时不能声称映射无关")
		}
	})
}

// TestNATTypeWhitelistMatchesServer 锁定白名单取值。
//
// ⚠️ 这份白名单必须与 vpn-server/admin/signal.go 里的 validNATTypes
// 逐字一致（两个模块无法互相 import，各有一份，改一处必须改另一处）。
// vpn-server 侧有对应的 TestValidNATTypeWhitelist 一起锁住。
func TestNATTypeWhitelistMatchesServer(t *testing.T) {
	want := map[string]bool{
		"full-cone":       true,
		"restricted-cone": true,
		"port-restricted": true,
		"symmetric":       true,
		"unknown":         true,
	}
	for k := range want {
		if !IsValidNATType(k) {
			t.Fatalf("白名单缺少 %q（客户端与服务端必须一致）", k)
		}
	}
	if len(validNATTypes) != len(want) {
		t.Fatalf("白名单项数应为 %d，实际 %d：%v", len(want), len(validNATTypes), validNATTypes)
	}
	for _, bad := range []string{"", "cone", "FULL-CONE", "fullcone", " unknown"} {
		if IsValidNATType(bad) {
			t.Fatalf("非法取值不应通过: %q", bad)
		}
	}
}

// TestParseP2PFlag 验证 DHCP 第 11 段的解析与向后兼容。
//
// 这是阶段 0 向后兼容的关键：旧服务端只发 10 段，客户端必须安全地
// 当作 false（不 panic、也不默认开启）。
func TestParseP2PFlag(t *testing.T) {
	base10 := []string{
		"192.168.30.11", "255.255.255.0", "off", "", "off", "", "off", "",
		"selfsigned", "hy2link.local",
	}

	// 旧服务端：只有 10 段
	if parseP2PFlag(base10) {
		t.Fatal("10 段（旧服务端）时必须为 false")
	}
	if parseP2PFlag(nil) {
		t.Fatal("nil 时必须为 false（不能 panic）")
	}
	if parseP2PFlag([]string{}) {
		t.Fatal("空切片时必须为 false")
	}
	if parseP2PFlag(base10[:3]) {
		t.Fatal("段数不足时必须为 false")
	}

	// 新服务端：11 段
	on := append(append([]string{}, base10...), "on")
	if !parseP2PFlag(on) {
		t.Fatal("第 11 段为 on 时应为 true")
	}
	for _, v := range []string{"ON", "On", " on "} {
		if !parseP2PFlag(append(append([]string{}, base10...), v)) {
			t.Fatalf("第 11 段 %q 应被识别为 on", v)
		}
	}
	for _, v := range []string{"off", "OFF", "", "garbage", "1", "true"} {
		if parseP2PFlag(append(append([]string{}, base10...), v)) {
			t.Fatalf("第 11 段 %q 不应被识别为 on", v)
		}
	}

	// 更多段（未来扩展）也不应影响第 11 段的解析
	more := append(append([]string{}, on...), "extra1", "extra2")
	if !parseP2PFlag(more) {
		t.Fatal("多余段不应影响第 11 段解析")
	}
}
