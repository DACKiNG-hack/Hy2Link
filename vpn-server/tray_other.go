//go:build !windows

package main

import "vpn-server/manager"

// runTray 非 Windows 平台空实现（不阻塞）
func runTray(mgr *manager.Manager, adminAddr string, shutdown func()) {
	// 空实现
}
