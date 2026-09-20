package quic

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestFingerprintPathHasNoTraversal 验证安全审计 S33。
//
// 修复前：fingerprintPath 只替换 ':' 和 '/'，而 filepath.Join 会做**词法**的
// ".." 归约，前缀 "fp_" 会被紧跟的第一个 ".." 抵消：
//
//	"..\..\..\..\..\..\..\Users\Public\secret"  ->  C:\Users\Public\secret.txt
//
// serverIP 直接来自 .hy2 文件，于是导入一个恶意 .hy2 就能对任意 *.txt
// 做存在性探测 / 删除 / 读取。
func TestFingerprintPathHasNoTraversal(t *testing.T) {
	dir, err := filepath.Abs(filepath.Dir(fingerprintPath("1.2.3.4")))
	if err != nil {
		t.Fatalf("解析指纹目录失败: %v", err)
	}

	evil := []string{
		`..\..\..\..\..\..\..\Users\Public\secret`,
		`../../../../etc/passwd`,
		`..\..\Windows\System32\drivers\etc\hosts`,
		`C:\Windows\win.ini`,
		`\\attacker\share\x`,
		`....//....//x`,
		`a/../../../../../../b`,
	}

	for _, in := range evil {
		got := fingerprintPath(in)
		abs, err := filepath.Abs(got)
		if err != nil {
			t.Fatalf("Abs(%q): %v", got, err)
		}
		// 必须仍然落在指纹目录内（允许指纹目录自身的子路径？
		// 不允许 —— 文件名就是 fp_<sha256>.txt，不能有子目录）
		rel, err := filepath.Rel(dir, abs)
		if err != nil {
			t.Fatalf("Rel(%q): %v", abs, err)
		}
		if strings.Contains(rel, "..") || filepath.IsAbs(rel) {
			t.Fatalf("输入 %q 逃出了指纹目录: %s", in, abs)
		}
		if filepath.Dir(abs) != dir {
			t.Fatalf("输入 %q 产生了子目录: %s", in, abs)
		}
		base := filepath.Base(abs)
		if !strings.HasPrefix(base, "fp_") || !strings.HasSuffix(base, ".txt") {
			t.Fatalf("文件名格式异常: %s", base)
		}
		// 文件名应当是 fp_ + 64 位十六进制 + .txt
		if len(base) != 3+64+4 {
			t.Fatalf("文件名长度异常（应为 fp_+64hex+.txt）: %s (%d)", base, len(base))
		}
	}
}

// TestFingerprintPathStableAndDistinct 同一输入必须稳定，不同输入必须不同
func TestFingerprintPathStableAndDistinct(t *testing.T) {
	a1 := fingerprintPath("1.2.3.4")
	a2 := fingerprintPath("1.2.3.4")
	b := fingerprintPath("1.2.3.5")
	if a1 != a2 {
		t.Fatal("同一 serverIP 必须映射到同一路径")
	}
	if a1 == b {
		t.Fatal("不同 serverIP 不应映射到同一路径")
	}
}

// TestValidateTunnelIPv4 验证安全审计 S34。
//
// 修复前只用 net.ParseIP 校验，mask=0.0.0.0 会让客户端自己装上
// 一条 0.0.0.0/0 默认路由指向隧道，整机流量改道。
func TestValidateTunnelIPv4(t *testing.T) {
	valid := [][2]string{
		{"192.168.30.11", "255.255.255.0"}, // /24
		{"10.0.0.100", "255.255.255.252"},  // /30，下界
		{"172.16.5.5", "255.255.0.0"},      // /16
		{"10.1.2.3", "255.0.0.0"},          // /8，上界
		{"10.1.2.3", "255.255.255.128"},    // /25
	}
	for _, c := range valid {
		if err := validateTunnelIPv4(c[0], c[1]); err != nil {
			t.Fatalf("合法输入被拒绝 %v/%v: %v", c[0], c[1], err)
		}
	}

	invalid := [][2]string{
		{"192.168.30.11", "0.0.0.0"},         // 会导致 0.0.0.0/0 默认路由
		{"192.168.30.11", "255.0.255.0"},     // 非连续掩码
		{"192.168.30.11", "255.255.255.255"}, // /32
		{"192.168.30.11", "255.255.255.254"}, // /31，点对点，不适合隧道
		{"192.168.30.11", "254.0.0.0"},       // 非连续且过小
		{"0.0.0.0", "255.255.255.0"},         // 未指定地址
		{"224.0.0.1", "255.255.255.0"},       // 组播地址
		{"255.255.255.255", "255.255.255.0"}, // 广播地址
		{"::1", "255.255.255.0"},             // IPv6
		{"192.168.30.11", "::1"},             // IPv6 掩码
		{"not-an-ip", "255.255.255.0"},
		{"192.168.30.11", "not-a-mask"},
		{"", ""},
	}
	for _, c := range invalid {
		if err := validateTunnelIPv4(c[0], c[1]); err == nil {
			t.Fatalf("非法输入被接受: %v / %v", c[0], c[1])
		}
	}
}
