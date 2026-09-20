package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidServerHost 验证安全审计 S32/S33 的第一道防线
func TestValidServerHost(t *testing.T) {
	good := []string{
		"1.2.3.4",
		"192.168.30.11",
		"2001:db8::1",
		"panel.example.com",
		"a-b.c-d.example",
	}
	for _, s := range good {
		if err := validServerHost(s); err != nil {
			t.Fatalf("合法地址被拒绝 %q: %v", s, err)
		}
	}

	bad := []string{
		"",
		`..\..\..\..\Users\Public\secret`,
		`../../../../etc/passwd`,
		`C:\Windows\win.ini`,
		`\\attacker\share\x`,
		"a/../../b",
		"host name",
		"host:8443",
		"..",
		".hidden",
		"trailing.",
		"a..b",
	}
	for _, s := range bad {
		if err := validServerHost(s); err == nil {
			t.Fatalf("非法地址被接受: %q", s)
		}
	}
}

// TestParseHyFileForcesCertVerification 验证安全审计 S32：
// .hy2 是**不受信任的输入**，其中的 skipCertVerify 必须被忽略。
//
// 修复前：文件里写 "skipCertVerify": true 会让客户端对服务端
// 不做任何证书校验（verifyPin / verifyPinOrCA 第一步就 return nil），
// 攻击者用自签证书即可完整中间人 —— 而 .hy2 关联是自动注册的，
// 诱导双击一个文件就能触发。
func TestParseHyFileForcesCertVerification(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "evil.hy2")

	payload := HY2File{
		V:              1,
		Type:           HyFileType,
		Name:           "x",
		Server:         "1.2.3.4",
		Port:           8443,
		Password:       "pw",
		SkipCertVerify: true, // ← 攻击者想要的效果
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := ParseHyFile(p)
	if err != nil {
		t.Fatalf("ParseHyFile: %v", err)
	}
	if cfg.SkipCertVerify {
		t.Fatal("来自 .hy2 的 skipCertVerify 必须被忽略（否则等于一键关闭全部证书校验）")
	}
	if cfg.IP != "1.2.3.4" || cfg.Port != 8443 || cfg.Password != "pw" {
		t.Fatalf("正常字段解析错误: %+v", cfg)
	}
}

// TestParseHyFileRejectsTraversalServer 验证 S32/S33 的端到端阻断
func TestParseHyFileRejectsTraversalServer(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "evil.hy2")

	payload := HY2File{
		V:        1,
		Type:     HyFileType,
		Server:   `..\..\..\..\..\..\..\Users\Public\secret`,
		Port:     8443,
		Password: "pw",
	}
	data, _ := json.Marshal(payload)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := ParseHyFile(p); err == nil {
		t.Fatal("带路径穿越的 server 字段必须被拒绝")
	}
}

// TestValidUsername 用户名不能破坏「用户名:密码:vn=X.Y.Z」的解析
func TestValidUsername(t *testing.T) {
	good := []string{"alice", "user-1", "a.b_c", "张三", "x"}
	for _, s := range good {
		if err := validUsername(s); err != nil {
			t.Fatalf("合法用户名被拒绝 %q: %v", s, err)
		}
	}
	// 空用户名在这里是「合法格式」——是否必填由调用方决定：
	// ParseHyFile 允许旧版 .hy2 缺失该字段（由 UI 提示补填），
	// 而 client.Connect 会强制要求非空。
	if err := validUsername(""); err != nil {
		t.Fatalf("validUsername 只校验格式，空值应由调用方判定，得到 %v", err)
	}

	bad := []string{" a", "a ", "a:b", "a\nb", "a\rb", "a\tb", strings.Repeat("x", 65)}
	for _, s := range bad {
		if err := validUsername(s); err == nil {
			t.Fatalf("非法用户名被接受: %q", s)
		}
	}
}

// TestParseHyFileCarriesUsername 用户名必须随 .hy2 一起分发
// （服务端已停用全局密码，客户端必须以「用户名:密码」认证）
func TestParseHyFileCarriesUsername(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.hy2")

	payload := HY2File{
		V:        1,
		Type:     HyFileType,
		Name:     "我的服务器",
		Server:   "1.2.3.4",
		Port:     8443,
		Username: "alice",
		Password: "pw",
	}
	data, _ := json.Marshal(payload)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := ParseHyFile(p)
	if err != nil {
		t.Fatalf("ParseHyFile: %v", err)
	}
	if cfg.Username != "alice" {
		t.Fatalf("用户名应被保留，得到 %q", cfg.Username)
	}
	if cfg.Name != "我的服务器" {
		t.Fatalf("连接名称应被保留，得到 %q", cfg.Name)
	}
}

// TestParseHyFileAllowsEmptyUsernameForLegacyFiles
// 旧版 .hy2 没有 username 字段：应当允许导入（UI 会提示补填），
// 而不是整个文件都失败。
func TestParseHyFileAllowsEmptyUsernameForLegacyFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "legacy.hy2")

	payload := HY2File{
		V:        1,
		Type:     HyFileType,
		Server:   "1.2.3.4",
		Port:     8443,
		Password: "pw",
	}
	data, _ := json.Marshal(payload)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := ParseHyFile(p)
	if err != nil {
		t.Fatalf("旧版配置（无用户名）应能导入: %v", err)
	}
	if cfg.Username != "" {
		t.Fatalf("用户名应为空，得到 %q", cfg.Username)
	}
}

// TestParseHyFileRejectsBadUsername 带分隔符的用户名必须被拒绝
func TestParseHyFileRejectsBadUsername(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"a:b", "a\nb", " alice"} {
		p := filepath.Join(dir, "bad.hy2")
		payload := HY2File{
			V: 1, Type: HyFileType, Server: "1.2.3.4", Port: 8443,
			Username: bad, Password: "pw",
		}
		data, _ := json.Marshal(payload)
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := ParseHyFile(p); err == nil {
			t.Fatalf("非法用户名 %q 应被拒绝", bad)
		}
	}
}

// TestParseHyFileRejectsBadFields 其他字段的边界
func TestParseHyFileRejectsBadFields(t *testing.T) {
	cases := []HY2File{
		{V: 1, Type: "not-hy2link", Server: "1.2.3.4", Port: 8443, Password: "pw"},
		{V: 99, Type: HyFileType, Server: "1.2.3.4", Port: 8443, Password: "pw"},
		{V: 1, Type: HyFileType, Server: "1.2.3.4", Port: 0, Password: "pw"},
		{V: 1, Type: HyFileType, Server: "1.2.3.4", Port: 70000, Password: "pw"},
		{V: 1, Type: HyFileType, Server: "1.2.3.4", Port: 8443, Password: ""},
		{V: 1, Type: HyFileType, Server: "1.2.3.4", Port: 8443, Password: "pw", ObfsEnabled: true, ObfsPassword: "abc"},
	}
	dir := t.TempDir()
	for i, c := range cases {
		p := filepath.Join(dir, "case.hy2")
		data, _ := json.Marshal(c)
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := ParseHyFile(p); err == nil {
			t.Fatalf("第 %d 个用例本应被拒绝: %+v", i, c)
		}
	}
}
