//go:build windows

package main

import (
	"log"
)

var (
	procGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")
	procSetPriorityClass  = kernel32.NewProc("SetPriorityClass")
)

const (
	normalPriorityClass      = 0x00000020
	aboveNormalPriorityClass = 0x00008000
)

// SetHighPriority 开/关进程高优先级
func SetHighPriority(enabled bool) {
	hProcess, _, _ := procGetCurrentProcess.Call()

	var class uintptr
	if enabled {
		class = aboveNormalPriorityClass
	} else {
		class = normalPriorityClass
	}

	ret, _, err := procSetPriorityClass.Call(hProcess, class)
	if ret == 0 {
		log.Printf("⚠️ 设置进程优先级失败: %v", err)
		return
	}

	if enabled {
		log.Println("⚡ 进程优先级已提升为 ABOVE_NORMAL")
	} else {
		log.Println("进程优先级已恢复为 NORMAL")
	}
}
