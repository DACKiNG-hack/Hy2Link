package quic

import (
	"strings"
	"testing"
)

// TestDHCPResponseP2PSegment 验证 DHCP 应答第 11 段（P2P 开关）与第 12 段（内置 STUN）。
//
// 验收要求：
//   - 开关打开时第 11 段为 "on"，关闭时为 "off"；
//   - 第 12 段为内置 STUN 端口列表（"3478|3479"）或 "off"；
//   - 必须是**向后兼容的追加**：前 10 段的内容与顺序完全不变，
//     这样旧客户端（只读到第 10 段）行为不受影响。
func TestDHCPResponseP2PSegment(t *testing.T) {
	const (
		wantIP   = "10.0.0.100"
		wantMask = "255.255.255.0"
	)

	build := func(p2p bool, stun string) []string {
		t.Helper()
		alloc := NewIPAllocator()
		out := NewDHCPOutbound(
			alloc,
			false, nil,
			false, nil,
			false, nil,
			"selfsigned", "hy2link.local",
			p2p,
			stun,
		)
		c := newDHCPConn(out)
		// 直接置位，避免 Read 阻塞在 cond.Wait() 上
		c.ip = wantIP
		c.mask = wantMask
		c.ready = true

		buf := make([]byte, 512)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		line := strings.TrimSpace(string(buf[:n]))
		return strings.Split(line, ",")
	}

	off := build(false, "off")
	on := build(true, "3478|3479")

	if len(off) != 12 || len(on) != 12 {
		t.Fatalf("应答都应为 12 段，实际 off=%d on=%d", len(off), len(on))
	}

	// 第 11 段就是 P2P 开关
	if off[10] != "off" {
		t.Fatalf("P2P 关闭时第 11 段应为 off，实际 %q", off[10])
	}
	if on[10] != "on" {
		t.Fatalf("P2P 打开时第 11 段应为 on，实际 %q", on[10])
	}

	// 第 12 段是内置 STUN 端口列表
	if off[11] != "off" {
		t.Fatalf("没有内置 STUN 时第 12 段应为 off，实际 %q", off[11])
	}
	if on[11] != "3478|3479" {
		t.Fatalf("第 12 段应为内置 STUN 端口列表，实际 %q", on[11])
	}
	// 空串也要落成 off（announce 反映现实）
	if got := build(true, "")[11]; got != "off" {
		t.Fatalf("空的内置 STUN 应落成 off，实际 %q", got)
	}

	// 前 10 段必须逐字不变（除了 P2P 开关，两者应完全一致）
	for i := 0; i < 10; i++ {
		if off[i] != on[i] {
			t.Fatalf("第 %d 段在两种开关下不一致: off=%q on=%q", i+1, off[i], on[i])
		}
	}

	// 固定段的位置与语义（旧客户端依赖这些位置）
	if off[0] != wantIP {
		t.Fatalf("第 1 段应为 IP，实际 %q", off[0])
	}
	if off[1] != wantMask {
		t.Fatalf("第 2 段应为掩码，实际 %q", off[1])
	}
	if off[8] != "selfsigned" {
		t.Fatalf("第 9 段应为证书模式，实际 %q", off[8])
	}
	if off[9] != "hy2link.local" {
		t.Fatalf("第 10 段应为 hostname，实际 %q", off[9])
	}

	// 旧客户端只读到第 10 段也不会越界（模拟 len(parts) >= N 的逐段判断）
	old := off[:10]
	if len(old) != 10 {
		t.Fatal("前 10 段必须完整可用")
	}
}
