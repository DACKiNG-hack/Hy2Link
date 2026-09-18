//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// readPasswordInput 读取密码（Unix 用 term.ReadPassword）
func readPasswordInput() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	// 非终端环境回退到明文读取
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
