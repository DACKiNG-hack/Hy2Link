//go:build !windows

package main

// SetHighPriority 非 Windows 平台空实现
func SetHighPriority(enabled bool) {}
