//go:build !windows

package main

// HasConsole 非 Windows 平台默认返回 true
func HasConsole() bool { return true }

// allocConsole 非 Windows 平台无需分配控制台
func allocConsole() bool { return true }

// closeConsoleWindow 非 Windows 平台空实现
func closeConsoleWindow() {}

// setupConsoleEncoding 非 Windows 平台空实现
func setupConsoleEncoding() {}

// setupConsoleInputMode 非 Windows 平台空实现
func setupConsoleInputMode() {}
