//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const (
	extKey   = `.hy2`
	progID   = `Hy2Link.Config`
	fileDesc = `Hy2Link 连接配置`
)

func registerFileAssociation(exePath string) error {
	// 1. HKCU\Software\Classes\.hy2 = Hy2Link.Config
	if err := setKey(`Software\Classes\`+extKey, "", progID); err != nil {
		return fmt.Errorf("注册扩展名失败: %w", err)
	}

	// 2. HKCU\Software\Classes\Hy2Link.Config = "Hy2Link 连接配置"
	if err := setKey(`Software\Classes\`+progID, "", fileDesc); err != nil {
		return fmt.Errorf("注册 ProgID 失败: %w", err)
	}

	// 3. 图标
	_ = setKey(`Software\Classes\`+progID+`\DefaultIcon`, "", exePath+",0")

	// 4. 打开命令
	cmd := fmt.Sprintf(`"%s" "%%1"`, exePath)
	if err := setKey(`Software\Classes\`+progID+`\shell\open\command`, "", cmd); err != nil {
		return fmt.Errorf("注册打开命令失败: %w", err)
	}

	return nil
}

func isFileAssociationRegistered() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Classes\`+extKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetStringValue("")
	if err != nil {
		return false
	}
	return v == progID
}

func setKey(path, name, value string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(name, value)
}
