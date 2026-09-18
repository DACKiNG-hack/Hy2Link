//go:build !windows

package main

// 非 Windows 平台托盘不可用，留空保证编译通过

func startTray(app *App) {}

func updateTrayStatus(connected bool) {}
