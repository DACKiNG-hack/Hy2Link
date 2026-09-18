//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// showMsgBox 非 Windows 平台用 fmt 输出
func showMsgBox(title, text string) {
	fmt.Printf("[%s] %s\n", title, text)
}

// showMsgBoxYesNo 非 Windows 平台用命令行确认
func showMsgBoxYesNo(title, text string) bool {
	fmt.Printf("[%s] %s (y/N): ", title, text)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}
