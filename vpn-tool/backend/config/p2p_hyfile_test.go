package config

// vpn-tool/backend/config/p2p_hyfile_test.go
//
// ⭐ 1b-4 第 3 步（§3.1）：`.hy2` 的 P2P 字段导出/导入 + 兼容性。
//
// 背景（实现时核实）：`.hy2` 的 DTO（`HY2File`）原先**根本没有 `p2pDisabled` 字段**
// ⇒ 导出丢字段、导入也不解析（导入后恒 false，恰好等于「默认不禁用」，所以向后兼容是"碰巧"成立的）。
//
// 本文件把四个要求 + 两个兼容性前提钉死：
//  1. 禁用 P2P → 导出 → 文件里有 `"p2pDisabled": true`
//  2. 导入该文件 → `P2PDisabled == true`（P2P 保持禁用）
//  3. 启用 P2P → 导出 → 文件里有 `"p2pDisabled": false`（**显式出现**，证明没被 omitempty 吃掉）
//  4. 旧导出文件（无字段）→ 导入后 `P2PDisabled == false`（默认启用）
//  5. 【前提】旧客户端读新版文件：无 `DisallowUnknownFields` ⇒ 忽略未知字段、不报错
//  6. 【安全】非法类型（`"yes"`）⇒ 导入报错（fail-closed，不静默取零值）

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeHyFile 写一个 .hy2 文件（内容为原始 JSON 字符串，便于测「缺字段」这类情形）
func writeHyFile(t *testing.T, name, raw string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// readFile 读回导出文件内容
func readHyFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// baseConfig 一个可导出的最小合法配置
func baseConfig() ClientConfig {
	return ClientConfig{
		Name: "srv", IP: "1.2.3.4", Port: 8443, Username: "alice", Password: "pw",
	}
}

// TestExportIncludesP2PDisabledExplicitly ⭐ 要求 1 + 3：
// 无论 true 还是 false，字段都必须**显式出现**（这就是「不带 omitempty」的验收）。
func TestExportIncludesP2PDisabledExplicitly(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		cfg := baseConfig()
		cfg.P2PDisabled = disabled

		path := filepath.Join(t.TempDir(), "out.hy2")
		if err := ExportToFile(cfg, path); err != nil {
			t.Fatalf("ExportToFile(disabled=%v): %v", disabled, err)
		}
		raw := readHyFile(t, path)

		if !strings.Contains(raw, `"p2pDisabled"`) {
			t.Fatalf("导出文件必须含 p2pDisabled 字段（disabled=%v），实际内容:\n%s", disabled, raw)
		}
		want := `"p2pDisabled": false`
		if disabled {
			want = `"p2pDisabled": true`
		}
		if !strings.Contains(raw, want) {
			t.Fatalf("导出文件应含 %s（disabled=%v），实际内容:\n%s", want, disabled, raw)
		}
	}
}

// TestImportRestoresP2PDisabled ⭐ 要求 2：导出（禁用）→ 导入 ⇒ 仍禁用
func TestImportRestoresP2PDisabled(t *testing.T) {
	cfg := baseConfig()
	cfg.P2PDisabled = true

	path := filepath.Join(t.TempDir(), "disabled.hy2")
	if err := ExportToFile(cfg, path); err != nil {
		t.Fatalf("ExportToFile: %v", err)
	}
	got, err := ParseHyFile(path)
	if err != nil {
		t.Fatalf("ParseHyFile: %v", err)
	}
	if !got.P2PDisabled {
		t.Fatal("禁用 P2P 的配置导入后必须仍然禁用（P2PDisabled=true）")
	}
}

// TestImportLegacyFileWithoutP2PFieldDefaultsToEnabled ⭐ 要求 4（向后兼容）：
// 旧版 .hy2 没有 p2pDisabled 字段 ⇒ 零值 false ⇒ **不禁用**（默认启用）。
func TestImportLegacyFileWithoutP2PFieldDefaultsToEnabled(t *testing.T) {
	// 手工构造「旧版文件」：只有 v1 时代的字段，**没有** p2pDisabled
	raw := `{
	  "v": 1,
	  "type": "hy2link",
	  "name": "legacy",
	  "server": "1.2.3.4",
	  "port": 8443,
	  "username": "alice",
	  "password": "pw",
	  "obfsEnabled": false,
	  "obfsPassword": "",
	  "skipCertVerify": false
	}`
	p := writeHyFile(t, "legacy.hy2", raw)

	cfg, err := ParseHyFile(p)
	if err != nil {
		t.Fatalf("旧版文件（无 p2pDisabled）必须能导入: %v", err)
	}
	if cfg.P2PDisabled {
		t.Fatal("旧版文件缺字段 ⇒ 必须是「不禁用 P2P」（否则旧配置升级后会静默禁用直连）")
	}
	// 同时确认旧文件的其他字段照常解析
	if cfg.IP != "1.2.3.4" || cfg.Port != 8443 || cfg.Username != "alice" {
		t.Fatalf("旧版文件其它字段解析错误: %+v", cfg)
	}
}

// TestRoundTripKeepsP2PDisabledFlags 往返：导出 → 导入 → 再导出，值稳定
func TestRoundTripKeepsP2PDisabledFlags(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		cfg := baseConfig()
		cfg.P2PDisabled = disabled
		p1 := filepath.Join(t.TempDir(), "a.hy2")
		if err := ExportToFile(cfg, p1); err != nil {
			t.Fatalf("export: %v", err)
		}
		got, err := ParseHyFile(p1)
		if err != nil {
			t.Fatalf("import: %v", err)
		}
		if got.P2PDisabled != disabled {
			t.Fatalf("往返后 P2PDisabled 应保持 %v，实际 %v", disabled, got.P2PDisabled)
		}
		p2 := filepath.Join(t.TempDir(), "b.hy2")
		if err := ExportToFile(*got, p2); err != nil {
			t.Fatalf("re-export: %v", err)
		}
		if readHyFile(t, p1) != readHyFile(t, p2) {
			t.Fatalf("两次导出的文件应完全一致（disabled=%v）\n第一次:\n%s\n第二次:\n%s",
				disabled, readHyFile(t, p1), readHyFile(t, p2))
		}
	}
}

// legacyHy2FileDTO 旧版 DTO（**测试内联定义**，只有 v1 时代的字段）。
//
// 用途：模拟「**旧客户端**读新版文件」。它把新版文件解析进这个**没有 p2pDisabled 的结构**——
// 只要解析不报错，就证明「向前兼容 = 忽略未知字段」成立。
//
// ⚠️ 这条用例是一道**前提守卫**：若将来有人给 `ParseHyFile` 加上
// `dec.DisallowUnknownFields()`，旧客户端就会**直接拒绝**新版文件，
// 而本用例（解析到旧结构）会立刻变红，提醒「这破坏了向前兼容」。
type legacyHy2FileDTO struct {
	V              int    `json:"v"`
	Type           string `json:"type"`
	Name           string `json:"name"`
	Server         string `json:"server"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	ObfsEnabled    bool   `json:"obfsEnabled"`
	ObfsPassword   string `json:"obfsPassword"`
	SkipCertVerify bool   `json:"skipCertVerify"`
}

// TestNewFileIsReadableByLegacyStruct ⭐ 兼容性前提 5（向前兼容）：
// 新版文件（含 p2pDisabled）解析进**旧版结构** ⇒ 不报错、旧字段正确。
func TestNewFileIsReadableByLegacyStruct(t *testing.T) {
	cfg := baseConfig()
	cfg.P2PDisabled = true
	path := filepath.Join(t.TempDir(), "new.hy2")
	if err := ExportToFile(cfg, path); err != nil {
		t.Fatalf("export: %v", err)
	}
	raw := readHyFile(t, path)
	if !strings.Contains(raw, `"p2pDisabled": true`) {
		t.Fatalf("前置条件：新文件应含 p2pDisabled=true，实际:\n%s", raw)
	}

	// 用**旧结构**解析（等价于旧客户端）
	var legacy legacyHy2FileDTO
	if err := json.Unmarshal([]byte(raw), &legacy); err != nil {
		t.Fatalf("旧版结构必须能读新版文件（未知字段应被忽略）: %v", err)
	}
	if legacy.Server != "1.2.3.4" || legacy.Username != "alice" || legacy.Password != "pw" {
		t.Fatalf("旧版结构解析出的旧字段不正确: %+v", legacy)
	}

	// 反向守卫：确认**全仓没有** DisallowUnknownFields 行为 ——
	// 用一个带「完全未知字段」的 JSON 走 ParseHyFile 的同一个解析路径（json.Unmarshal）
	// 也无法直接断言 API 用法，这里用「显式多一个未知键仍能解析」来体现。
	rawWithUnknown := strings.Replace(raw, `"p2pDisabled": true`,
		`"p2pDisabled": true, "someFutureField": 123`, 1)
	p2 := writeHyFile(t, "future.hy2", rawWithUnknown)
	if _, err := ParseHyFile(p2); err != nil {
		t.Fatalf("含未知未来字段的文件也必须能导入（当前实现无 DisallowUnknownFields）: %v", err)
	}
}

// TestImportRejectsWrongTypeForP2PDisabled ⭐ 兼容性前提 6（fail-closed）：
// 类型不匹配（`"yes"`）⇒ 解析报错，而**不是**静默取零值。
func TestImportRejectsWrongTypeForP2PDisabled(t *testing.T) {
	raw := `{
	  "v": 1, "type": "hy2link", "name": "x", "server": "1.2.3.4", "port": 8443,
	  "username": "alice", "password": "pw",
	  "p2pDisabled": "yes"
	}`
	p := writeHyFile(t, "badtype.hy2", raw)
	if _, err := ParseHyFile(p); err == nil {
		t.Fatal("p2pDisabled 类型非法（字符串）时必须报错（fail-closed），而不是静默当成 false")
	}
}
