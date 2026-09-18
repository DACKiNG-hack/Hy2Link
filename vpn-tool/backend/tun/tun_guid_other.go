//go:build !windows

package tun

// 非 Windows 平台无需设置 GUID
func setupStaticGUID() {}
