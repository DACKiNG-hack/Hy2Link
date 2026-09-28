package config

import (
	"reflect"
	"strings"
	"testing"
)

// jsonFieldName 取某个字段的线上 JSON 名（用反射锁定，防止改字段名忘了同步前端）
func jsonFieldName(t *testing.T, field string) string {
	t.Helper()
	f, ok := reflect.TypeOf(ClientConfig{}).FieldByName(field)
	if !ok {
		t.Fatalf("ClientConfig 里没有字段 %s", field)
	}
	return strings.Split(f.Tag.Get("json"), ",")[0]
}

// vpn-tool/backend/config/p2p_default_test.go
//
// ⭐ 1b-2A（UI 块）：本机「禁用 P2P」开关的**默认值守卫**。
//
// 为什么值得单独一条测试：这个字段的语义必须是「禁用」而不是「启用」——
// Go 的 bool 零值是 false，如果字段是「启用」，那么所有旧配置、旧 .hy2 导入、
// 以及任何只构造 `ClientConfig{...}` 的代码路径都会**静默变成禁用 P2P**
// （实现本块时踩过一次：既有 punch 测试全部因 p2pLocalEnabled=false 失败）。
func TestClientConfigP2PDefaultsToNotDisabled(t *testing.T) {
	var zero ClientConfig
	if zero.P2PDisabled {
		t.Fatal("零值 ClientConfig 必须是「不禁止 P2P」（否则旧配置升级后会静默禁用直连）")
	}
	// JSON 字段名锁定：前端持久化/传输用的就是这个键
	if got := jsonFieldName(t, "P2PDisabled"); got != "p2pDisabled" {
		t.Fatalf("字段线上名应为 p2pDisabled，实际 %q", got)
	}
}
