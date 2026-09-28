package quic

// vpn-tool/backend/quic/stun_list_test.go
//
// P2SP 阶段 1b-1 补丁（服务端内置 STUN 端点）的客户端侧测试：
//   - DHCP 第 12 段的解析（含向后兼容：旧服务端没有这一段）
//   - STUN 列表顺序：内置端点**在最前**，公共 STUN 作为备选且去重
//   - 验收要求：**首位不可达时能正确切到备选**，并且两个内置端点足以
//     让 classifyNAT 判定「映射是否与目的地址无关」（这才是国内能打洞的关键）
//
// ⚠️ 这里用一个**手写的最小 STUN 响应者**（40 行）而不是复用服务端实现：
//   - vpn-tool 与服务端是两个 module，无法互相 import；
//   - 客户端只有 pion/stun **v3**（而且是 indirect 依赖），在测试里直接 import
//     会把它变成直接依赖 → 动 go.mod，违反「0 新依赖」的边界约定。
//   手写响应同时也验证了「最小 STUN 响应就能被 realm 解析」这件事。

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestEnvironmentSwitchDisablesPublicSTUN（手工验证用的开关）
//
//	HY2_NO_PUBLIC_STUN=1 → 列表里只剩内置端点（模拟「国内公共 STUN 不可达」）
func TestEnvironmentSwitchDisablesPublicSTUN(t *testing.T) {
	t.Setenv("HY2_NO_PUBLIC_STUN", "1")
	c := newSignalTestClient()
	c.builtinSTUNPorts = []int{3478, 3479}

	list := c.stunServerList()
	if len(list) != 2 || list[0] != "1.2.3.4:3478" || list[1] != "1.2.3.4:3479" {
		t.Fatalf("开关打开时列表应只有内置端点，实际 %v", list)
	}

	// 开关关闭（默认）时公共 STUN 仍在
	t.Setenv("HY2_NO_PUBLIC_STUN", "0")
	list = c.stunServerList()
	if len(list) != 2+len(defaultSTUNServers) {
		t.Fatalf("开关关闭时应带上公共 STUN，实际 %v", list)
	}
}

// TestDetectNATWithOnlyBuiltinEndpoints（手工验证第 2 条的自动化近似）
//
//	「断开外部 STUN / 模拟国内环境」→ 只靠**服务端内置的两个端点**也能判定
//	full-cone + MappingIndependent → 1b-1 预检放行 → 打洞具备条件。
func TestDetectNATWithOnlyBuiltinEndpoints(t *testing.T) {
	t.Setenv("HY2_NO_PUBLIC_STUN", "1")
	startTestSTUN(t, 48064)
	startTestSTUN(t, 48065)

	c := newSignalTestClient()
	c.serverIP = "127.0.0.1"
	c.builtinSTUNPorts = []int{48064, 48065}

	old := stunPerServerTimeout
	stunPerServerTimeout = 400 * time.Millisecond
	defer func() { stunPerServerTimeout = old }()

	list := c.stunServerList()
	if len(list) != 2 {
		t.Fatalf("模拟国内环境时列表应只有内置端点，实际 %v", list)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := detectNAT(ctx, list)

	if res.RespondedServers != 2 {
		t.Fatalf("两个内置端点都应响应，实际 %d（err=%v）", res.RespondedServers, res.Err)
	}
	if res.Type != NATFullCone || !res.MappingIndependent {
		t.Fatalf("只靠内置端点应能判出 full-cone/映射与目标端口无关，实际 type=%s mappingIndependent=%v",
			res.Type, res.MappingIndependent)
	}
	if res.PublicAddr == "" || len(res.ObservedPorts) != 1 {
		t.Fatalf("应拿到公网地址与单一观测端口，实际 addr=%q ports=%v", res.PublicAddr, res.ObservedPorts)
	}
}

// TestNoPublicSTUNWithNoBuiltinFallsBackToPublicList
//
//	调试开关 + 服务端没开内置端点 → **回落公共 STUN**，不能把探测彻底关死。
func TestNoPublicSTUNWithNoBuiltinFallsBackToPublicList(t *testing.T) {
	t.Setenv("HY2_NO_PUBLIC_STUN", "1")
	c := newSignalTestClient()
	c.builtinSTUNPorts = nil // 服务端没开（旧服务端 / stunPort=0 / 只起来 0 个）

	list := c.stunServerList()
	if len(list) != len(defaultSTUNServers) {
		t.Fatalf("没有内置端点时应回落公共 STUN，实际 %v", list)
	}
	for i, s := range defaultSTUNServers {
		if list[i] != s {
			t.Fatalf("回落结果应与默认公共列表一致，实际 %v", list)
		}
	}
}

// TestNoPublicSTUNValueParsing 只有 1/true 才算开启（避免用户写 0/false 反而关掉备选）
func TestNoPublicSTUNValueParsing(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"1", true}, {"true", true}, {"TRUE", true}, {" true ", true},
		{"0", false}, {"false", false}, {"", false}, {"yes", false}, {"2", false},
	}
	for _, tc := range cases {
		t.Setenv("HY2_NO_PUBLIC_STUN", tc.val)
		if got := noPublicSTUN(); got != tc.want {
			t.Fatalf("HY2_NO_PUBLIC_STUN=%q 应为 %v，实际 %v", tc.val, tc.want, got)
		}
	}
}

// TestParseBuiltinSTUNPorts 第 12 段解析
func TestParseBuiltinSTUNPorts(t *testing.T) {
	cases := []struct {
		name  string
		parts []string
		want  []int
	}{
		{"两个端口", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "on", "3478|3479"}, []int{3478, 3479}},
		{"单个端口", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "on", "3479"}, []int{3479}},
		{"off", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "on", "off"}, nil},
		{"空串", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "on", ""}, nil},
		{"旧服务端（只有 11 段）", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "on"}, nil},
		{"旧服务端（只有 10 段）", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}, nil},
		{"忽略非法项", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "on", "abc|3478|0|70000|3479"}, []int{3478, 3479}},
		{"前后空白", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "on", " 3478 | 3479 "}, []int{3478, 3479}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseBuiltinSTUNPorts(tc.parts)
			if len(got) != len(tc.want) {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got=%v want=%v", got, tc.want)
				}
			}
		})
	}
}

// TestSTUNServerListPutsBuiltinFirstAndDedupes 内置端点排在首位 + 与公共列表去重
func TestSTUNServerListPutsBuiltinFirstAndDedupes(t *testing.T) {
	c := newSignalTestClient() // serverIP = 1.2.3.4
	c.builtinSTUNPorts = []int{3478, 3479}

	list := c.stunServerList()
	if len(list) < 3 {
		t.Fatalf("至少应有内置 2 个 + 公共备选，实际 %v", list)
	}
	if list[0] != "1.2.3.4:3478" || list[1] != "1.2.3.4:3479" {
		t.Fatalf("内置端点必须在最前（用客户端已知的 serverIP 拼），实际 %v", list[:2])
	}
	if list[2] != defaultSTUNServers[0] {
		t.Fatalf("第 3 项应是第一个公共 STUN，实际 %q", list[2])
	}

	// 去重：构造一个与第一个公共 STUN 完全相同的「内置」项 → 不应重复出现
	host, port, err := net.SplitHostPort(defaultSTUNServers[0])
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
		t.Fatalf("解析端口: %v", err)
	}
	c.serverIP = host
	c.builtinSTUNPorts = []int{p}

	list = c.stunServerList()
	seen := map[string]int{}
	for _, s := range list {
		seen[s]++
	}
	for s, n := range seen {
		if n > 1 {
			t.Fatalf("%q 重复出现 %d 次（去重失效）", s, n)
		}
	}
	if len(list) != len(defaultSTUNServers) {
		t.Fatalf("去重后应仍是 %d 项，实际 %d（%v）", len(defaultSTUNServers), len(list), list)
	}
	if list[0] != defaultSTUNServers[0] {
		t.Fatalf("去重后内置项仍应在最前，实际 %q", list[0])
	}
}

// ---------- 手写最小 STUN 响应者（测试用） ----------

const (
	testSTUNMagicCookie   = 0x2112A442
	testSTUNBindingReq    = 0x0001
	testSTUNBindingOK     = 0x0101
	testSTUNAttrXORMapped = 0x0020
)

type testSTUNServer struct {
	conn *net.UDPConn
}

func startTestSTUN(t *testing.T, port int) *testSTUNServer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Skipf("端口 %d 被占用，跳过：%v", port, err)
	}
	s := &testSTUNServer{conn: conn}
	go s.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return s
}

func (s *testSTUNServer) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 20 || binary.BigEndian.Uint16(buf[0:2]) != testSTUNBindingReq {
			continue // 只应答 Binding Request
		}
		var txid [12]byte
		copy(txid[:], buf[8:20])
		_, _ = s.conn.WriteToUDP(buildTestSTUNResponse(txid, from), from)
	}
}

// buildTestSTUNResponse 手工拼一个 Binding Success + XOR-MAPPED-ADDRESS
func buildTestSTUNResponse(txid [12]byte, from *net.UDPAddr) []byte {
	resp := make([]byte, 20+12)
	binary.BigEndian.PutUint16(resp[0:2], testSTUNBindingOK)
	binary.BigEndian.PutUint16(resp[2:4], 12) // 属性区长度
	binary.BigEndian.PutUint32(resp[4:8], testSTUNMagicCookie)
	copy(resp[8:20], txid[:])

	binary.BigEndian.PutUint16(resp[20:22], testSTUNAttrXORMapped)
	binary.BigEndian.PutUint16(resp[22:24], 8)
	resp[24] = 0x00 // reserved
	resp[25] = 0x01 // family = IPv4
	binary.BigEndian.PutUint16(resp[26:28], uint16(from.Port)^uint16(testSTUNMagicCookie>>16))
	ip4 := from.IP.To4()
	mc := uint32(testSTUNMagicCookie) // 变量化：避免 byte() 在常量表达式上做溢出检查
	for i := 0; i < 4; i++ {
		resp[28+i] = ip4[i] ^ byte(mc>>uint(8*(3-i)))
	}
	return resp
}

// TestDetectNATFallsBackWhenFirstUnreachable（验收要求之一）
//
//	STUN 列表首位不可达时，必须能切到备选；并且两个内置端点足以判定非对称 NAT
//
// 这条正是「国内公共 STUN 不可达也能打洞」的核心保障：
// 服务端内置的两个端点都在 → 客户端能判定「映射与目的地址无关」→ 预检放行。
func TestDetectNATFallsBackWhenFirstUnreachable(t *testing.T) {
	startTestSTUN(t, 48060)
	startTestSTUN(t, 48061)

	// 首位故意不可达：127.0.0.1 上一个没人监听的端口
	servers := []string{
		"127.0.0.1:48069",
		"127.0.0.1:48060",
		"127.0.0.1:48061",
	}

	old := stunPerServerTimeout
	stunPerServerTimeout = 300 * time.Millisecond
	defer func() { stunPerServerTimeout = old }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res := detectNAT(ctx, servers)

	if res.RespondedServers < 2 {
		t.Fatalf("首位不可达时必须继续问备选，应至少 2 台响应，实际 %d（err=%v）",
			res.RespondedServers, res.Err)
	}
	if res.PublicAddr == "" {
		t.Fatal("应拿到观测到的公网地址")
	}
	// ⭐ 两个端点观测到同一端口 → 判定为「映射与目的地址无关」
	if res.Type != NATFullCone || !res.MappingIndependent {
		t.Fatalf("两个内置端点应足以判定非对称 NAT，实际 type=%s mappingIndependent=%v（err=%v）",
			res.Type, res.MappingIndependent, res.Err)
	}
	if len(res.ObservedPorts) != 1 {
		t.Fatalf("应观测到同一个端口，实际 %v", res.ObservedPorts)
	}
}

// TestDetectNATAllUnreachableReportsUnknown 全不可达时必须如实上报（不能假装成功）
func TestDetectNATAllUnreachableReportsUnknown(t *testing.T) {
	old := stunPerServerTimeout
	stunPerServerTimeout = 200 * time.Millisecond
	defer func() { stunPerServerTimeout = old }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res := detectNAT(ctx, []string{"127.0.0.1:48070", "127.0.0.1:48071"})

	if res.Type != NATUnknown {
		t.Fatalf("全不可达时应为 unknown，实际 %s", res.Type)
	}
	if res.PublicAddr != "" {
		t.Fatalf("全不可达时不应有公网地址，实际 %q", res.PublicAddr)
	}
	if res.Err == nil {
		t.Fatal("应带上错误原因")
	}
	// 客户端据此会走 local-no-punch-addr / nat-unknown 回落中继（不做无谓打洞）
}
