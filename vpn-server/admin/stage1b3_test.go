package admin

// vpn-server/admin/stage1b3_test.go
//
// ⭐ 1b-3（A1）：punchAddrs 校验的单元测试。
//
// 为什么这块必须有测试：punchAddrs 是**对端会逐个发包的目标列表**，
// 是唯一会把「单地址反射」放大 32 倍的新增面。校验的每一条规则都要有牙。

import (
	"testing"
)

func TestValidatePunchAddrs(t *testing.T) {
	cases := []struct {
		name    string
		addrs   []string
		anchor  string
		wantErr bool
	}{
		{name: "空列表合法（旧客户端）", addrs: nil, anchor: "1.2.3.4", wantErr: false},
		{name: "两个同 IP 相邻端口", addrs: []string{"1.2.3.4:50001", "1.2.3.4:50002"}, anchor: "1.2.3.4", wantErr: false},
		{name: "无锚也接受", addrs: []string{"1.2.3.4:50001"}, anchor: "", wantErr: false},
		{name: "超上限 33 个", addrs: manyAddrs(33), anchor: "1.2.3.4", wantErr: true},
		{name: "恰好 32 个", addrs: manyAddrs(32), anchor: "1.2.3.4", wantErr: false},
		{name: "混入别的 IP", addrs: []string{"1.2.3.4:50001", "5.6.7.8:50002"}, anchor: "1.2.3.4", wantErr: true},
		{name: "锚定 IP 不一致", addrs: []string{"5.6.7.8:50001"}, anchor: "1.2.3.4", wantErr: true},
		{name: "重复项", addrs: []string{"1.2.3.4:50001", "1.2.3.4:50001"}, anchor: "1.2.3.4", wantErr: true},
		{name: "非法端口", addrs: []string{"1.2.3.4:0"}, anchor: "1.2.3.4", wantErr: true},
		{name: "私网地址（防 SSRF/内网探测）", addrs: []string{"10.0.0.1:50001"}, anchor: "10.0.0.1", wantErr: true},
		{name: "环回地址", addrs: []string{"127.0.0.1:50001"}, anchor: "127.0.0.1", wantErr: true},
		{name: "空串元素", addrs: []string{"1.2.3.4:50001", ""}, anchor: "1.2.3.4", wantErr: true},
		{name: "IPv4-mapped 与纯 IPv4 视为同一 IP", addrs: []string{"1.2.3.4:50001", "[::ffff:1.2.3.4]:50002"}, anchor: "1.2.3.4", wantErr: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePunchAddrs(tc.addrs, tc.anchor)
			if tc.wantErr && err == nil {
				t.Fatalf("应拒绝，实际通过（addrs=%v anchor=%q）", tc.addrs, tc.anchor)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("应通过，实际拒绝: %v（addrs=%v anchor=%q）", err, tc.addrs, tc.anchor)
			}
		})
	}
}

// TestMaxPunchAddrsMirrorsRealmCap 上限必须与 realm 的每 IP 扩展上限一致。
//
// ⚠️ 跨模块常量无法编译期互引（realm 的 symmetricNATMaxPortsPerHost 未导出），
//
//	所以这里锁死数字：改上限的人必须同步想清楚 realm 那边的窗口大小。
func TestMaxPunchAddrsMirrorsRealmCap(t *testing.T) {
	if MaxPunchAddrs != 32 {
		t.Fatalf("MaxPunchAddrs 应为 32（与 realm 每 IP 最多 32 个端口对齐），实际 %d", MaxPunchAddrs)
	}
}

// manyAddrs 造 n 个同 IP 不同端口的候选
func manyAddrs(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, "1.2.3.4:"+itoa(50000+i))
	}
	return out
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
