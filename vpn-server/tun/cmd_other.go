//go:build !windows

package tun

import "os/exec"

// newHiddenCmd 非 Windows 平台直接调用 exec.Command
func newHiddenCmd(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}
