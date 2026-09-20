package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestDefaultConfigDisablesOptionalPlanes 验证「首次启动默认不启用」。
//
// TCP 连接拆分 / UDP 匹配（可靠）/ UDP 对战（不可靠）这三项都是低延迟优化，
// 不是必需功能，默认应当关闭：新装服务端先用最简单的单条 bulk 数据面跑通。
// 端口列表仍然保留，用户开启时无需重新填写。
func TestDefaultConfigDisablesOptionalPlanes(t *testing.T) {
	c := DefaultConfig()

	if c.TCPSplitEnabled {
		t.Error("TCP 连接拆分默认应为关闭")
	}
	if c.UDPReliableEnabled {
		t.Error("UDP 可靠（匹配端口）默认应为关闭")
	}
	if c.UDPUnreliableEnabled {
		t.Error("UDP 不可靠（对战端口）默认应为关闭")
	}

	// 端口列表要保留（开启时不用重填）
	if len(c.TCPSplitPorts) == 0 {
		t.Error("TCP 拆分端口列表应保留默认值")
	}
	if len(c.UDPReliablePorts) == 0 {
		t.Error("UDP 可靠端口列表应保留默认值")
	}
	if len(c.UDPUnreliablePorts) == 0 {
		t.Error("UDP 不可靠端口列表应保留默认值")
	}

	// 默认配置必须能通过校验（关闭时不要求端口列表非空）
	if err := c.Validate(); err != nil {
		t.Fatalf("默认配置未通过校验: %v", err)
	}
}

// TestLoadWritesDisabledDefaults server.json 不存在时，写出的默认配置里三项应为关闭
func TestLoadWritesDisabledDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.TCPSplitEnabled || c.UDPReliableEnabled || c.UDPUnreliableEnabled {
		t.Fatalf("新建配置三项都应为关闭，实际 tcp=%v udpRel=%v udpUnrel=%v",
			c.TCPSplitEnabled, c.UDPReliableEnabled, c.UDPUnreliableEnabled)
	}

	// 落盘内容也必须是关闭状态（下次启动读回来还是关闭）
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("重新 Load: %v", err)
	}
	if reloaded.TCPSplitEnabled || reloaded.UDPReliableEnabled || reloaded.UDPUnreliableEnabled {
		t.Fatal("重新读取后三项仍应为关闭")
	}
}

// TestLoadPreservesExplicitlyEnabled 关键：**已有部署不受默认值变更影响**。
// 用户自己存过 true 的配置必须原样保留，否则升级会悄悄改掉线上行为。
func TestLoadPreservesExplicitlyEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")

	raw := map[string]interface{}{
		"port":                 8443,
		"portVPN":              8444,
		"ipPoolStart":          "192.168.30.11",
		"ipPoolEnd":            "192.168.30.255",
		"subnetMask":           "255.255.255.0",
		"tcpSplitEnabled":      true,
		"tcpSplitPorts":        []int{22345, 443},
		"udpReliableEnabled":   true,
		"udpReliablePorts":     []string{"42300-42800"},
		"udpUnreliableEnabled": true,
		"udpUnreliablePorts":   []string{"50000-50550"},
	}
	data, _ := json.MarshalIndent(raw, "", "  ")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("写入测试配置: %v", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.TCPSplitEnabled {
		t.Error("配置文件里显式写 true 的 tcpSplitEnabled 必须保留")
	}
	if !c.UDPReliableEnabled {
		t.Error("配置文件里显式写 true 的 udpReliableEnabled 必须保留")
	}
	if !c.UDPUnreliableEnabled {
		t.Error("配置文件里显式写 true 的 udpUnreliableEnabled 必须保留")
	}
}

// TestValidateStillRequiresPortsWhenEnabled 开启时仍然必须填端口（行为未变）
func TestValidateStillRequiresPortsWhenEnabled(t *testing.T) {
	c := DefaultConfig()
	c.UDPReliableEnabled = true
	c.UDPReliablePorts = nil
	if err := c.Validate(); err == nil {
		t.Fatal("启用 UDP 可靠但端口列表为空时应校验失败")
	}

	c = DefaultConfig()
	c.TCPSplitEnabled = true
	c.TCPSplitPorts = nil
	if err := c.Validate(); err == nil {
		t.Fatal("启用 TCP 拆分但端口列表为空时应校验失败")
	}
}
