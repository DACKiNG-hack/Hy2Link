//go:build !windows

package main

import "fmt"

func registerFileAssociation(exePath string) error {
	return fmt.Errorf("当前平台暂不支持自动注册文件关联")
}

func isFileAssociationRegistered() bool {
	return false
}
