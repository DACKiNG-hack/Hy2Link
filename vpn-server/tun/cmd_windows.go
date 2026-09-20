//go:build windows

//服务端cmd_windows.go

package tun

import (
	"os/exec"
	"syscall"
)

// newHiddenCmd 创建一个不弹窗的命令
// Windows 下父进程无控制台时（GUI 程序），exec.Command 会弹出控制台窗口
// 通过 CREATE_NO_WINDOW 标志阻止
func newHiddenCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	return cmd
}
