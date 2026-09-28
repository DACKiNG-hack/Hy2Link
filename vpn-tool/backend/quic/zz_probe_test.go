package quic

// signal_stream_quic_semantics_test.go
//
// （文件名是调试期的历史遗留：一开始这里是临时探针 zz_probe_test.go，
//   验证完就地把结论固化成回归测试。沙箱不允许我删文件，
//   所以名字留成这样 —— 想改名/删除请随意，内容值得保留。）
//
// ⭐ 这里记录一个把信令通道设计推翻过一次的 QUIC 语义：
//
//	客户端 OpenStreamSync 出来的流，**在对端写入第一个字节之前，
//	对服务端完全不可见**（服务端 AcceptStream 不会返回）。
//
// 后果（如果不知道这一点）：
//   - 客户端「开完流等着」→ 服务端卡在 AcceptStream 直到 20 秒超时放弃；
//   - 服务端因此永远拿不到这条流，登记表里也就没有下行通道 →
//     **永远无法主动推送**，打洞直接废掉（拉取式之所以不成立的根本原因之一）。
//
// 所以客户端 ensureSignalStream 开完流必须立刻写一帧（见 signal.go）。
// 这条测试把这个前提钉住：哪天 fork 行为变了，这里会先失败。

import (
	"context"
	"testing"
	"time"
)

func TestQUICStreamInvisibleUntilFirstWrite(t *testing.T) {
	srv := newFakeSignalServer(t)
	defer srv.close()

	c := newSignalTestClientWithNAT("1.2.3.4:30001", string(NATFullCone))
	dialFakeSignal(t, c, srv)

	stream, err := c.ctrlConn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}

	// ① 只开流、不写：服务端不应该看见它
	time.Sleep(300 * time.Millisecond)
	if n := srv.streamCount(); n != 0 {
		t.Fatalf("未写入前服务端不应看见这条流，实际 %d 条"+
			"（若 fork 行为已变，请重新评估 ensureSignalStream 里的「开完立刻写」）", n)
	}

	// ② 写入第一帧之后：服务端立刻能看到
	if err := writeFrameToStream(stream, []byte(`{"type":"register"}`)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	waitStreamCount(t, srv, 1)
}
