//go:build windows

package main

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed assets/wintun/amd64/wintun.dll
var wintunDLLBytes []byte

// ensureWintunDLL 释放内嵌的 wintun.dll 到 exe 同目录
func ensureWintunDLL() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exePath)
	dllPath := filepath.Join(dir, "wintun.dll")

	if _, err := os.Stat(dllPath); os.IsNotExist(err) {
		return os.WriteFile(dllPath, wintunDLLBytes, 0644)
	}
	return nil
}
