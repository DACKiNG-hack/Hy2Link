package quic

// vpn-tool/backend/quic/client_path.go
//
// ⭐ 1b-2A：把 `pathManager` 接到客户端上（`pathHost` 实现 + 写侧分流 + 热路径钩子）。
//
// 三件事：
//  1. `pathHost` 接口实现（窄接口，见 path.go）：NAT 状态、信令查询、打洞入口、NAT 重探测、下行投递、事件；
//  2. **写侧分流**：6 个平面的发送函数先问路径管理器「这个目的地址有直连吗」，
//     有就把包投进该路径自己的队列（非阻塞），没有就走中继（与 1b-1 逐字一致）；
//  3. **热路径钩子**：TUN 读循环里多一次 `Observe(dst)`（原子读 + map 查 + 非阻塞入队）。

import (
	"context"
	"fmt"
	"log"
	"time"
)

// ---------- pathHost 实现 ----------

// myVIP4 自己的隧道 IP（未连接/未分配时 ok=false）
func (c *Hysteria2Client) myVIP4() ([4]byte, bool) {
	var out [4]byte
	if c.assignedIP == "" {
		return out, false
	}
	return parseIPv4(c.assignedIP)
}

// p2pEnabled 服务端 P2P 开关（DHCP 第 11 段；运行期关闭由信令拒绝文本/踢人/重连三条路径收敛）
func (c *Hysteria2Client) p2pEnabled() bool { return c.P2PEffective() }

// natProbeReady 本机 NAT 探测是否已拿到公网地址（没拿到就先别触发，见 path.go handleTrigger）
//
// ⚠️ 名字不能叫 natReady：客户端已有同名字段（`natReady bool`，NATResult 的 Ready 标志）
func (c *Hysteria2Client) natProbeReady() bool {
	_, _, ok := c.signalSelfInfo()
	return ok
}

// signalQuery 信号门用的隧道内查询（会顺带重新登记自己）
func (c *Hysteria2Client) signalQuery(peerVIP string) (SignalPeer, error) {
	return c.SignalQuery(peerVIP)
}

// punchWithTrigger 触发式打洞（trigger 只用于状态事件/日志）
func (c *Hysteria2Client) punchWithTrigger(peerVIP, trigger string) (string, error) {
	c.punchMu.Lock()
	mgr := c.punchMgr
	c.punchMu.Unlock()
	if mgr == nil {
		return "", c.p2pUnavailableErr()
	}
	return mgr.PunchWithTrigger(peerVIP, trigger)
}

// p2pUnavailableErr 「当前不能打洞」的精确原因（排障时一眼看出该去改哪一边的开关）
func (c *Hysteria2Client) p2pUnavailableErr() error {
	if !c.p2pLocalEnabled {
		return fmt.Errorf("本机已禁用 P2P（高级选项 → 禁用 P2P）")
	}
	if !c.p2pServerEnabled {
		return fmt.Errorf("服务端未启用 P2P（服务端开关=%v）", c.p2pServerEnabled)
	}
	return fmt.Errorf("尚未连接（打洞管理器未启动）")
}

// refreshNAT 重新探测 NAT 并重新登记（路径失效后地址可能变了；串行化，失败只报错）
func (c *Hysteria2Client) refreshNAT(ctx context.Context) error {
	c.natRefreshMu.Lock()
	defer c.natRefreshMu.Unlock()

	log.Printf("🌐 [NAT] 重新探测（地址可能已变化）...")
	res := detectNAT(ctx, c.stunServerList())

	c.natMu.Lock()
	c.natResult = res
	c.natReady = true
	c.natMu.Unlock()

	if res.PublicAddr == "" {
		return fmt.Errorf("未取得公网地址（类型=%s）", res.Type)
	}
	log.Printf("🌐 [NAT] 重探测结果: %s 公网地址=%s", res.Type, res.PublicAddr)
	// 让对端能查到新地址：重新登记（幂等；失败只记日志）
	c.registerSignalSelf()
	return nil
}

// onPathEvent 路径状态变化 → 复用既有的 "p2p:status" 事件通道
func (c *Hysteria2Client) onPathEvent(st P2PStatus) {
	c.punchMu.Lock()
	mgr := c.punchMgr
	pending := c.pendingP2PStatus
	c.punchMu.Unlock()
	if mgr != nil {
		mgr.emit(st)
		return
	}
	if pending != nil {
		pending(st)
	}
}

// relayRTT 中继 RTT（ns）：供「直连 vs 中继」对比显示（心跳 RTT，30s 内有效）
func (c *Hysteria2Client) relayRTT() int64 {
	if c.lastRTTAt.IsZero() || time.Since(c.lastRTTAt) > 30*time.Second {
		return 0
	}
	return int64(c.lastRTT)
}

// P2PPaths 当前直连路径快照（UI 用）
func (c *Hysteria2Client) P2PPaths() []PathInfo {
	pm := c.pathManagerOrNil()
	if pm == nil {
		return nil
	}
	return pm.Paths()
}

// ---------- 写侧分流（§2.2） ----------

// directSink 若该包的目的地址有直连路径，返回**该平面对应流**的发送队列；否则 nil。
//
// ⚠️ 热路径：4 字节读取 + 原子指针加载 + map 查 + 一次 switch（平面→流分组）。
func (c *Hysteria2Client) directSink(pkt []byte, plane pathPlaneIndex) chan pathPkt {
	if len(pkt) < 20 {
		return nil
	}
	dst := [4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}
	if isBroadcastOrMulticast4(dst) {
		return nil
	}
	pm := c.pathManagerOrNil()
	if pm == nil {
		return nil
	}
	return pm.sinkFor(dst, plane)
}

// enqueueDirect 非阻塞投递到直连队列（满了就丢这一条：该流本来就在退化）
//
// ⚠️ 平面标签**随包一起入队**：帧是出队时才写的，届时已经推不出「它属于哪个平面」。
func enqueueDirect(ch chan pathPkt, plane pathPlaneIndex, pkt []byte) {
	select {
	case ch <- pathPkt{plane: plane, data: pkt}:
	default:
	}
}

// directDatagramPath 不可靠 UDP 平面：返回该目的地址的直连路径（否则 nil）
func (c *Hysteria2Client) directDatagramPath(pkt []byte) *directPath {
	if len(pkt) < 20 {
		return nil
	}
	dst := [4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}
	if isBroadcastOrMulticast4(dst) {
		return nil
	}
	pm := c.pathManagerOrNil()
	if pm == nil {
		return nil
	}
	snap := pm.routes.Load()
	if snap == nil {
		return nil
	}
	p := (*snap)[dst]
	if p == nil || p.state.Load() != pathStateUp {
		return nil
	}
	return p
}

// observeDst 热路径钩子：把目的地址交给路径管理器（触发一次流量驱动的打洞）
func (c *Hysteria2Client) observeDst(pkt []byte) {
	if len(pkt) < 20 {
		return
	}
	pm := c.pathManagerOrNil()
	if pm == nil {
		return
	}
	pm.Observe([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
}
