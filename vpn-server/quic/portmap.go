package quic

//vpn-server\quic\portmap.go

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jech/portmap"
)

// PortMapper 管理 UPnP/NAT-PMP 端口映射
type PortMapper struct {
	mu           sync.RWMutex
	internalPort int
	publicIP     string
	publicPort   int
	available    bool
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewPortMapper 创建一个新的端口映射器
func NewPortMapper(internalPort int) *PortMapper {
	ctx, cancel := context.WithCancel(context.Background())
	return &PortMapper{
		internalPort: internalPort,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start 尝试建立端口映射
// publicIP 是已知的公网 IP（通过 GetPublicIP 获取），用于拼接最终的对外地址
// 返回 (公网地址 "IP:端口", 是否成功)
func (pm *PortMapper) Start(publicIP string, timeout time.Duration) (string, bool) {
	log.Printf("🔌 [端口映射] 正在尝试 UPnP/NAT-PMP (内网端口 %d)...", pm.internalPort)

	go func() {
		err := portmap.Map(
			pm.ctx,
			"hy2-vpn",                   // label，会显示在路由器 UI 中
			uint16(pm.internalPort),     // 内网端口
			portmap.NATPMP|portmap.UPNP, // 同时尝试 NAT-PMP 和 UPnP
			func(proto string, status portmap.Status, err error) {
				if err != nil {
					if pm.ctx.Err() == nil {
						log.Printf("⚠️ [端口映射] %s 错误: %v", proto, err)
					}
					return
				}
				if status.External == 0 {
					return
				}

				pm.mu.Lock()
				changed := pm.publicPort != int(status.External)
				pm.publicPort = int(status.External)
				pm.publicIP = publicIP
				pm.available = true
				pm.mu.Unlock()

				if changed {
					log.Printf("✅ [端口映射] %s 映射成功: 公网 %s:%d → 内网 %d (租期 %v)",
						proto, publicIP, status.External, status.Internal, status.Lifetime)
				}
			},
		)
		if err != nil && err != context.Canceled {
			log.Printf("⚠️ [端口映射] 循环退出: %v", err)
		}
	}()

	// 轮询等待首次成功
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pm.mu.RLock()
		ok := pm.available
		addr := ""
		if ok {
			addr = fmt.Sprintf("%s:%d", pm.publicIP, pm.publicPort)
		}
		pm.mu.RUnlock()

		if ok {
			return addr, true
		}
		time.Sleep(500 * time.Millisecond)
	}

	log.Printf("⚠️ [端口映射] 超时（%v 内未成功）", timeout)
	return "", false
}

// Close 停止端口映射
func (pm *PortMapper) Close() {
	pm.cancel()
}

// GetPublicAddr 返回当前公网地址（IP:端口）
func (pm *PortMapper) GetPublicAddr() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if !pm.available {
		return ""
	}
	return fmt.Sprintf("%s:%d", pm.publicIP, pm.publicPort)
}
