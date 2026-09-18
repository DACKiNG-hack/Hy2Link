//go:build windows

//vpn-tool\dll_embed.go

package main

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed assets/wintun/amd64/wintun.dll
var wintunDLLBytes []byte

func ensureWintunDLL() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(exePath)
	dllPath := filepath.Join(dir, "wintun.dll")

	if _, err := os.Stat(dllPath); os.IsNotExist(err) {
		err := os.WriteFile(dllPath, wintunDLLBytes, 0644)
		if err != nil {
			return err
		}
	}
	return nil
}
