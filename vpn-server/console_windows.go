//go:build windows

package main

import (
	"log"
	"os"
	"syscall"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")

	procGetConsoleWindow   = kernel32.NewProc("GetConsoleWindow")
	procAllocConsole       = kernel32.NewProc("AllocConsole")
	procFreeConsole        = kernel32.NewProc("FreeConsole")
	procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
	procSetConsoleCP       = kernel32.NewProc("SetConsoleCP")
	procGetConsoleMode     = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode     = kernel32.NewProc("SetConsoleMode")

	procPostMessageW = user32.NewProc("PostMessageW")
)

const (
	wmClose = 0x0010
	cpUTF8  = 65001

	// 控制台输入模式标志
	enableProcessedInput = 0x0001
	enableLineInput      = 0x0002
	enableEchoInput      = 0x0004
)

// HasConsole 当前进程是否拥有控制台窗口
func HasConsole() bool {
	hwnd, _, _ := procGetConsoleWindow.Call()
	return hwnd != 0
}

// setupConsoleEncoding 把控制台代码页设为 UTF-8 (65001)
func setupConsoleEncoding() {
	if !HasConsole() {
		return
	}
	procSetConsoleOutputCP.Call(uintptr(cpUTF8))
	procSetConsoleCP.Call(uintptr(cpUTF8))
}

// setupConsoleInputMode 设置控制台输入模式
// ⭐ 关键修复：确保键盘输入被正确接收
//
// 模式说明：
//   - ENABLE_PROCESSED_INPUT: Ctrl+C 被系统处理
//   - ENABLE_LINE_INPUT:      行输入模式（回车才返回）
//   - ENABLE_ECHO_INPUT:      回显输入字符
func setupConsoleInputMode() {
	if !HasConsole() {
		return
	}
	hConIn := os.Stdin.Fd()
	if hConIn == 0 || hConIn == ^uintptr(0) {
		return
	}
	mode := uintptr(enableProcessedInput | enableLineInput | enableEchoInput)
	procSetConsoleMode.Call(hConIn, mode)
}

// allocConsole 分配控制台，并设置编码 + 输入模式
func allocConsole() bool {
	ret, _, _ := procAllocConsole.Call()
	if ret == 0 {
		return false
	}

	setupConsoleEncoding()
	reopenStdio()
	setupConsoleInputMode() // ⭐ 关键
	return true
}

// closeConsoleWindow 关闭控制台窗口
func closeConsoleWindow() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd == 0 {
		return
	}

	// 先分离进程，再关窗口
	procFreeConsole.Call()
	procPostMessageW.Call(hwnd, uintptr(wmClose), 0, 0)

	// 重定向 stdout/stderr 到 NUL
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err == nil {
		os.Stdout = devNull
		os.Stderr = devNull
	}
	log.SetOutput(os.Stderr)
}

// reopenStdio 把标准流绑定到控制台
func reopenStdio() {
	conout, err := syscall.Open("CONOUT$", syscall.O_RDWR, 0)
	if err != nil {
		log.Printf("打开 CONOUT$ 失败: %v", err)
		return
	}
	conin, err := syscall.Open("CONIN$", syscall.O_RDWR, 0)
	if err != nil {
		log.Printf("打开 CONIN$ 失败: %v", err)
		_ = syscall.Close(conout)
		return
	}

	outFile := os.NewFile(uintptr(conout), "CONOUT$")
	inFile := os.NewFile(uintptr(conin), "CONIN$")

	os.Stdout = outFile
	os.Stderr = outFile
	os.Stdin = inFile

	log.SetOutput(outFile)
}
