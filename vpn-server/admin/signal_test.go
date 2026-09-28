package admin

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// TestValidNATTypeWhitelist 锁定白名单取值。
//
// ⚠️ 必须与 vpn-tool/backend/quic/nat.go 里的 validNATTypes 逐字一致
// （两个模块无法互相 import，各有一份，改一处必须改另一处）。
// 客户端侧有对应的 TestNATTypeWhitelistMatchesServer 一起锁住。
func TestValidNATTypeWhitelist(t *testing.T) {
	want := []string{"full-cone", "restricted-cone", "port-restricted", "symmetric", "unknown"}
	for _, k := range want {
		if !ValidNATType(k) {
			t.Fatalf("白名单缺少 %q（客户端与服务端必须一致）", k)
		}
	}
	if len(validNATTypes) != len(want) {
		t.Fatalf("白名单项数应为 %d，实际 %d", len(want), len(validNATTypes))
	}
	for _, bad := range []string{"", "cone", "FULL-CONE", "fullcone", " unknown"} {
		if ValidNATType(bad) {
			t.Fatalf("非法取值不应通过: %q", bad)
		}
	}
}

// TestValidatePublicAddr 校验外部地址格式
func TestValidatePublicAddr(t *testing.T) {
	good := []string{"1.2.3.4:30001", "203.0.113.9:1", "10.0.0.1:65535", "[2001:db8::1]:443"}
	for _, s := range good {
		if err := ValidatePublicAddr(s); err != nil {
			t.Fatalf("合法地址被拒绝 %q: %v", s, err)
		}
	}
	bad := []string{
		"", "1.2.3.4", "1.2.3.4:", ":30001", "1.2.3.4:0", "1.2.3.4:65536",
		"1.2.3.4:abc", "0.0.0.0:30001", "not-an-ip:80", "1.2.3.4:30001:extra",
	}
	for _, s := range bad {
		if err := ValidatePublicAddr(s); err == nil {
			t.Fatalf("非法地址被接受: %q", s)
		}
	}
}

// TestNormalizeMetadata 校验打洞 metadata（32 字节十六进制）
func TestNormalizeMetadata(t *testing.T) {
	// 空值合法：表示本次没有发起打洞
	if got, err := NormalizeMetadata(""); err != nil || got != "" {
		t.Fatalf("空 metadata 应合法，得到 %q / %v", got, err)
	}
	if got, err := NormalizeMetadata("   "); err != nil || got != "" {
		t.Fatalf("空白 metadata 应视为空，得到 %q / %v", got, err)
	}

	ok := strings.Repeat("ab", MetadataLen)
	for _, s := range []string{ok, strings.ToUpper(ok), "  " + ok + "  "} {
		got, err := NormalizeMetadata(s)
		if err != nil {
			t.Fatalf("合法 metadata 被拒绝: %v", err)
		}
		if got != ok {
			t.Fatalf("应统一为小写并去空白，得到 %q", got)
		}
	}

	bad := []string{
		"ab",                              // 太短
		strings.Repeat("ab", 16),          // 16 字节
		strings.Repeat("ab", 64),          // 64 字节
		strings.Repeat("zz", MetadataLen), // 非十六进制
		ok + "00",                         // 多一字节
	}
	for _, s := range bad {
		if _, err := NormalizeMetadata(s); err == nil {
			t.Fatalf("非法 metadata 被接受: %q", s)
		}
	}
}

// TestSignalRegistryUpdateValidation 登记时必须校验来自客户端的每一项
func TestSignalRegistryUpdateValidation(t *testing.T) {
	r := NewSignalRegistry(time.Minute)

	valid := func() (string, string, string) { return "1.2.3.4:30001", "full-cone", "" }

	// 合法
	a, n, m := valid()
	if err := r.Update("192.168.30.11", a, n, m); err != nil {
		t.Fatalf("合法登记被拒绝: %v", err)
	}

	// 各类非法输入
	cases := []struct {
		vip, addr, nat, meta string
	}{
		{"", a, n, m},                                     // vip 为空
		{"192.168.30.11", "", n, m},                       // 地址为空
		{"192.168.30.11", "1.2.3.4", n, m},                // 缺端口
		{"192.168.30.11", "0.0.0.0:80", n, m},             // 未指定地址
		{"192.168.30.11", "1.2.3.4:99999", n, m},          // 端口越界
		{"192.168.30.11", a, "cone", m},                   // NAT 类型不在白名单
		{"192.168.30.11", a, "", m},                       // NAT 类型为空
		{"192.168.30.11", a, n, "zz"},                     // metadata 非法
		{"192.168.30.11", a, n, strings.Repeat("ab", 16)}, // metadata 长度不对
	}
	for i, c := range cases {
		if err := r.Update(c.vip, c.addr, c.nat, c.meta); err == nil {
			t.Fatalf("第 %d 个非法输入被接受: %+v", i, c)
		}
	}

	// 非法输入不得覆盖已有登记
	got, ok := r.Get("192.168.30.11")
	if !ok {
		t.Fatal("已有登记不应被非法输入清掉")
	}
	if got.PublicAddr != a || got.NATType != n {
		t.Fatalf("已有登记被改写: %+v", got)
	}
}

// TestSignalRegistryMetadataNotWipedByAddrOnlyUpdate
// 只上报地址（metadata 传空）时不能把之前发起的打洞 metadata 抹掉
func TestSignalRegistryMetadataNotWipedByAddrOnlyUpdate(t *testing.T) {
	r := NewSignalRegistry(time.Minute)
	meta := strings.Repeat("cd", MetadataLen)

	if err := r.Update("192.168.30.11", "1.2.3.4:30001", "full-cone", meta); err != nil {
		t.Fatalf("Update: %v", err)
	}
	// 之后只刷新地址
	if err := r.Update("192.168.30.11", "1.2.3.4:30002", "full-cone", ""); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := r.Get("192.168.30.11")
	if got.Metadata != meta {
		t.Fatalf("metadata 不应被地址刷新抹掉，得到 %q", got.Metadata)
	}
	if got.PublicAddr != "1.2.3.4:30002" {
		t.Fatalf("地址应被刷新，得到 %q", got.PublicAddr)
	}
}

// TestSignalRegistryTTL 登记过期后应查不到
func TestSignalRegistryTTL(t *testing.T) {
	r := NewSignalRegistry(30 * time.Millisecond)
	if err := r.Update("192.168.30.11", "1.2.3.4:30001", "full-cone", ""); err != nil {
		t.Fatalf("Update: %v", err)
	}

	if _, ok := r.Get("192.168.30.11"); !ok {
		t.Fatal("刚登记应能查到")
	}
	time.Sleep(60 * time.Millisecond)
	if _, ok := r.Get("192.168.30.11"); ok {
		t.Fatal("超过 TTL 后不应再能查到")
	}
	if r.Count() != 0 {
		t.Fatalf("过期记录应被清掉，实际 %d", r.Count())
	}
}

// ---------- 下行通道（VIP → 信令流） ----------

type fakeSink struct {
	mu      sync.Mutex
	got     [][]byte
	closed  bool
	closeFn func()
}

func (f *fakeSink) SendSignal(payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, append([]byte(nil), payload...))
	return nil
}

func (f *fakeSink) CloseSignal() error {
	f.mu.Lock()
	f.closed = true
	fn := f.closeFn
	f.mu.Unlock()
	if fn != nil {
		fn()
	}
	return nil
}

func (f *fakeSink) sent() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func (f *fakeSink) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// TestSignalRegistrySinkDelivery 下行通道的基本投递
func TestSignalRegistrySinkDelivery(t *testing.T) {
	r := NewSignalRegistry(time.Minute)

	if r.SinkCount() != 0 {
		t.Fatalf("初始不应有下行通道，实际 %d", r.SinkCount())
	}
	if err := r.SendTo("192.168.30.11", []byte("x")); err == nil {
		t.Fatal("没有通道时 SendTo 应报错")
	}

	sink := &fakeSink{}
	r.AttachSink("192.168.30.11", sink)
	if !r.HasSink("192.168.30.11") || r.SinkCount() != 1 {
		t.Fatalf("挂载失败: has=%v count=%d", r.HasSink("192.168.30.11"), r.SinkCount())
	}
	if err := r.SendTo("192.168.30.11", []byte(`{"type":"ping"}`)); err != nil {
		t.Fatalf("SendTo: %v", err)
	}
	if sink.sent() != 1 {
		t.Fatalf("sink 应收到 1 条，实际 %d", sink.sent())
	}

	// 空 VIP / nil sink 不能被挂上
	r.AttachSink("", sink)
	r.AttachSink("192.168.30.99", nil)
	if r.SinkCount() != 1 {
		t.Fatalf("非法挂载不应生效，实际 %d", r.SinkCount())
	}
}

// TestSignalRegistrySinkReplaceOnReconnect 重连换流时：
//   - 新 sink 覆盖旧的（推送立刻走新流）
//   - **旧流的注销不能误伤新流**（这是 DetachSink 判据存在的理由）
func TestSignalRegistrySinkReplaceOnReconnect(t *testing.T) {
	r := NewSignalRegistry(time.Minute)
	oldSink := &fakeSink{}
	newSink := &fakeSink{}

	r.AttachSink("192.168.30.11", oldSink)
	r.AttachSink("192.168.30.11", newSink) // 客户端重连

	if err := r.SendTo("192.168.30.11", []byte("hello")); err != nil {
		t.Fatalf("SendTo: %v", err)
	}
	if newSink.sent() != 1 || oldSink.sent() != 0 {
		t.Fatalf("重连后应只往新流推送：new=%d old=%d", newSink.sent(), oldSink.sent())
	}

	// 旧流随后结束，它的 defer 来注销 —— 必须无效
	if r.DetachSink("192.168.30.11", oldSink) {
		t.Fatal("旧 sink 不该注销掉新挂上的通道")
	}
	if !r.HasSink("192.168.30.11") {
		t.Fatal("新通道被旧流的注销误删了")
	}

	// 自己注销才生效
	if !r.DetachSink("192.168.30.11", newSink) {
		t.Fatal("新 sink 自己注销应当生效")
	}
	if r.HasSink("192.168.30.11") || r.SinkCount() != 0 {
		t.Fatal("注销后不应还有通道")
	}
	if r.DetachSink("192.168.30.11", newSink) {
		t.Fatal("重复注销应返回 false")
	}
}

// TestSignalRegistrySinkNotTiedToTTL 下行通道跟「流」走，不跟条目 TTL 走。
//
// 客户端只要流还开着就随时能收推送，哪怕它 5 分钟没上报过。
func TestSignalRegistrySinkNotTiedToTTL(t *testing.T) {
	r := NewSignalRegistry(30 * time.Millisecond)
	if err := r.Update("192.168.30.11", "1.2.3.4:30001", "full-cone", ""); err != nil {
		t.Fatalf("Update: %v", err)
	}
	sink := &fakeSink{}
	r.AttachSink("192.168.30.11", sink)

	time.Sleep(60 * time.Millisecond) // 条目过期

	if _, ok := r.Get("192.168.30.11"); ok {
		t.Fatal("条目应已过期")
	}
	if !r.HasSink("192.168.30.11") {
		t.Fatal("下行通道不应随条目 TTL 一起消失（它跟流走）")
	}
	if err := r.SendTo("192.168.30.11", []byte("still-alive")); err != nil {
		t.Fatalf("过期条目仍应能推送: %v", err)
	}
}

// TestSignalRegistryCloseAllSinks 运行期关闭 P2P：全部关闭并清空
func TestSignalRegistryCloseAllSinks(t *testing.T) {
	r := NewSignalRegistry(time.Minute)
	a, b := &fakeSink{}, &fakeSink{}
	r.AttachSink("192.168.30.11", a)
	r.AttachSink("192.168.30.12", b)

	if n := r.CloseAllSinks("测试"); n != 2 {
		t.Fatalf("应关闭 2 条，实际 %d", n)
	}
	if !a.isClosed() || !b.isClosed() {
		t.Fatal("两个 sink 都应收到 CloseSignal")
	}
	if r.SinkCount() != 0 {
		t.Fatalf("关闭后应为空，实际 %d", r.SinkCount())
	}
	// 幂等
	if n := r.CloseAllSinks("再来一次"); n != 0 {
		t.Fatalf("重复关闭应为 0，实际 %d", n)
	}
}

// TestSignalRegistrySinkConcurrent 并发挂载/注销/推送/关闭所有通道。
//
// 这条测试是给 `go test -race` 用的（本机没有 cgo/gcc 跑不了 -race），
// 普通构建下也能抓出死锁与 map 并发写 panic。
func TestSignalRegistrySinkConcurrent(t *testing.T) {
	r := NewSignalRegistry(time.Minute)
	vips := []string{"192.168.30.11", "192.168.30.12", "192.168.30.13"}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sink := &fakeSink{}
			vip := vips[i%len(vips)]
			for j := 0; j < 50; j++ {
				r.AttachSink(vip, sink)
				_ = r.SendTo(vip, []byte("x"))
				r.DetachSink(vip, sink)
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				r.CloseAllSinks("压测")
				_ = r.SinkCount()
				_ = r.HasSink(vips[0])
			}
		}()
	}
	wg.Wait()

	// 收敛：压完之后表要么空、要么只剩压测最后一刻挂上的
	r.CloseAllSinks("收尾")
	if r.SinkCount() != 0 {
		t.Fatalf("收尾后应为空，实际 %d", r.SinkCount())
	}
}
