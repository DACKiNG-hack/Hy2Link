//go:build windows

package main

import (
	"log"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const serverMutexName = `Global\Hy2Link_Server_v1`

var serverMutexHandle windows.Handle

// ⭐ 用独有的名字，避免和已有声明冲突
var (
	singletonKernel32     = windows.NewLazySystemDLL("kernel32.dll")
	singletonCreateMutexW = singletonKernel32.NewProc("CreateMutexW")
)

// EnsureSingleInstance 返回 true = 唯一实例，可继续；false = 已有实例
func EnsureSingleInstance() bool {
	namePtr, err := windows.UTF16PtrFromString(serverMutexName)
	if err != nil {
		log.Printf("⚠️ [单实例] 名称无效: %v（放行）", err)
		return true
	}

	// ⭐ 直接调 CreateMutexW，从返回的 e1 判断 ERROR_ALREADY_EXISTS
	r0, _, e1 := singletonCreateMutexW.Call(
		0, // lpMutexAttributes
		0, // bInitialOwner
		uintptr(unsafe.Pointer(namePtr)),
	)
	if r0 == 0 {
		log.Printf("⚠️ [单实例] CreateMutexW 失败: %v（放行）", e1)
		return true
	}

	if errno, ok := e1.(syscall.Errno); ok && errno == windows.ERROR_ALREADY_EXISTS {
		_ = windows.CloseHandle(windows.Handle(r0))
		log.Printf("⚠️ [单实例] 检测到已有实例在运行")
		return false
	}

	serverMutexHandle = windows.Handle(r0)
	log.Printf("✅ [单实例] 已获取全局锁")
	return true
}

func ReleaseSingleInstance() {
	if serverMutexHandle != 0 {
		_ = windows.CloseHandle(serverMutexHandle)
		serverMutexHandle = 0
	}
}

// ⭐ 直接复用 main.go / 其他文件里已有的 showMsgBox
func ShowAlreadyRunningDialog() {
	showMsgBox(
		"Hy2Link 服务端",
		"服务端已在运行中，请勿重复启动。\r\n\r\n"+
			"如需重启，请先在管理面板停止服务端，\r\n"+
			"或在任务管理器中结束现有进程后再启动。",
	)
}
