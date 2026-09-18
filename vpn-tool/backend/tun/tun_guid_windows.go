//go:build windows

package tun

import (
	"log"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

// setupStaticGUID 设置固定的适配器 GUID
// 不设置的话每次启动都会生成随机 GUID，导致创建新的适配器实例（名字加数字）
// 设置了之后 Windows 会复用同一个适配器，名字永远是 hy2-tun0
func setupStaticGUID() {
	if tun.WintunStaticRequestedGUID != nil {
		return // 已经设置过
	}
	guid, err := windows.GUIDFromString("{6BA7B810-9DAD-11D1-80B4-00C04FD430C8}")
	if err != nil {
		log.Printf("⚠️ [TUN] 生成固定 GUID 失败: %v", err)
		return
	}
	tun.WintunStaticRequestedGUID = &guid
	log.Printf("✅ [TUN] 已设置固定适配器 GUID")
}
