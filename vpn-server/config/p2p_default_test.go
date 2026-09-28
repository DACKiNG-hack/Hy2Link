package config

// p2p_default_test.go —— **切片：服务端默认启用 HARP 直连（方案 A）** 的用例
//
// ⚠️ 本文件随切片新增。方案 A 的定义（用户 2026-09-28 拍板）：
//
//	**只改「新部署」的默认值**（`DefaultConfig()`）；**已部署服务端保持原样**。
//
// 为什么"已部署保持原样"是**自动成立**的，而不是靠额外逻辑（取证结论，本文件用例守住它）：
//
//	`Load()` 的实现是 `cfg := DefaultConfig()` → `json.Unmarshal(data, cfg)`
//	⇒ 文件里**显式**出现的键会**覆盖**默认值；只有**键缺失**时才继承新的默认值。
//	而 `Save()` 用 `json.MarshalIndent` 且 `P2PEnabled bool \`json:"p2pEnabled"\`` **没有 `omitempty`**
//	⇒ **旧部署磁盘上必然写着 `"p2pEnabled": false`（那是旧默认值填的，不是用户显式选择）**
//	⇒ 它在新版本下**仍是 false**（方案 A 的预期行为）。
//
// 三个断言（对应清单 §5 第 1 步）：
//  1. 新部署（无 config.json）⇒ `P2PEnabled == true`；
//  2. **显式 `false` 仍生效**（升级不改用户选择 / 已是方案 A 下"已部署保持原样"的机制保证）；
//  3. `String()` 默认含 `p2p=on`（启动日志/面板显示用）。
//
// ⚠️ 本文件同时**取代**旧的 `TestDefaultConfigP2PDisabled`（它断言"默认必须关闭"，与本切片方向相反）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultConfigP2PEnabledByDefault ⭐ 切片主用例（先红）：
//
//	新部署（无配置文件）⇒ P2P 默认**开启**。
func TestDefaultConfigP2PEnabledByDefault(t *testing.T) {
	if !DefaultConfig().P2PEnabled {
		t.Fatal("新部署的 P2P 默认必须是**开启**（本切片的行为变更）——" +
			"实际 DefaultConfig().P2PEnabled = false")
	}

	// 真实新部署路径：Load 一个**不存在**的文件 ⇒ 应写入默认配置并返回"开启"
	path := filepath.Join(t.TempDir(), "server.json")
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load（新部署路径）: %v", err)
	}
	if !c.P2PEnabled {
		t.Fatal("新部署（无 config.json）的 P2P 必须是开启")
	}

	// 落盘后应**写出显式键** `"p2pEnabled": true`（Save 无 omitempty ⇒ 避免隐式耦合；
	// 这样人眼可见、也让"已部署"在新版本下的语义明确）
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读回新配置: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("新配置不是合法 JSON: %v", err)
	}
	v, ok := m["p2pEnabled"]
	if !ok {
		t.Fatalf("新配置必须**显式写出** p2pEnabled 键（避免隐式默认耦合）；实际键缺失，内容=%s", raw)
	}
	if b, _ := v.(bool); !b {
		t.Fatalf("新配置的显式 p2pEnabled 应为 true，实际 %v", v)
	}
}

// TestExplicitP2PFalseIsPreserved ⭐ 切片关键守卫（先红里的"反向"那条：它应当**先绿**）：
//
//	**显式 `false` 必须被保留** —— 这既是"升级不改用户选择"的通用契约，
//	也正是方案 A 下"**已部署服务端保持原样**"的机制保证（旧配置里就写着 false）。
//
// ⚠️ 有牙：若把 `Load()` 改成"无条件用默认值覆盖文件值"（例如 `Unmarshal` 到
//
//	`&ServerConfig{}` 之外的错误做法，或先置 true 再解），本用例立刻红。
func TestExplicitP2PFalseIsPreserved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	// 模拟"已部署"的旧配置：显式写着 false（旧默认值写出的形态）
	if err := os.WriteFile(path, []byte(`{"port":8443,"p2pEnabled":false}`), 0o600); err != nil {
		t.Fatalf("写测试配置: %v", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.P2PEnabled {
		t.Fatal("配置里**显式**写着 p2pEnabled=false ⇒ 必须保留为 false（已部署服务端保持原样）——" +
			"若这里为 true，说明新默认值覆盖了文件里的显式值（方案 A 被破坏）")
	}

	// 再 Save/Load 一轮：显式 false 仍应保持（幂等）
	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatalf("重新 Load: %v", err)
	}
	if again.P2PEnabled {
		t.Fatal("显式 false 在 Save→Load 之后必须仍是 false")
	}
}

// TestDefaultConfigStringShowsP2POn ⭐ 可观测（先红）：
//
//	`String()`（启动日志用）默认应体现 `p2p=on`。
func TestDefaultConfigStringShowsP2POn(t *testing.T) {
	if s := DefaultConfig().String(); !strings.Contains(s, "p2p=on") {
		t.Fatalf("默认 String() 应包含 p2p=on（启动日志/排障要看），实际: %s", s)
	}
	// 显式关闭时仍应显示 off（开关是双向可见的）
	c := DefaultConfig()
	c.P2PEnabled = false
	if s := c.String(); !strings.Contains(s, "p2p=off") {
		t.Fatalf("显式关闭时 String() 应包含 p2p=off，实际: %s", s)
	}
}
