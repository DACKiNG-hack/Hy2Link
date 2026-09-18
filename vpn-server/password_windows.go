//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unsafe"
)

// readPasswordInput 读取密码（隐藏输入的字符）
//
// 不用 golang.org/x/term.ReadPassword，
// 因为它在 AllocConsole 分配的控制台上可能失效
func readPasswordInput() (string, error) {
	hConIn := os.Stdin.Fd()

	// 1. 保存当前控制台模式
	var oldMode uint32
	procGetConsoleMode.Call(hConIn, uintptr(unsafe.Pointer(&oldMode)))

	// 2. 关闭 ECHO（密码输入时不显示字符）
	newMode := oldMode &^ uint32(enableEchoInput)
	procSetConsoleMode.Call(hConIn, uintptr(newMode))

	// 3. 恢复模式 + 换行
	defer func() {
		procSetConsoleMode.Call(hConIn, uintptr(oldMode))
		fmt.Println()
	}()

	// 4. 读取一行
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
