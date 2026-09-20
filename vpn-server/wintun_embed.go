//go:build windows

package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

//go:embed assets/wintun/amd64/wintun.dll
var wintunDLLBytes []byte

// wintunDLLSHA256 是上面嵌入的 DLL 的 SHA-256，用于校验磁盘上的副本没有被顶替。
// 更新内嵌 DLL 时必须同步更新此常量：
//
//	certutil -hashfile assets\wintun\amd64\wintun.dll SHA256
//
// ⭐ 安全审计 S12
const wintunDLLSHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"

// ensureWintunDLL 释放内嵌的 wintun.dll 到 exe 同目录。
//
// ⭐ 安全审计 S12：wintun 的 Go 封装用
//
//	LoadLibraryEx("wintun.dll", 0, LOAD_LIBRARY_SEARCH_APPLICATION_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32)
//
// 加载，即**优先从 exe 所在目录**取。如果安装目录对普通用户可写
// （桌面 / 下载 / portable 解压目录），攻击者可以预放一个伪造的 wintun.dll，
// 服务端以管理员身份启动时会加载它 → 本地权限提升。
//
// 因此这里不再「文件存在就信任」，改为强制校验 SHA-256；
// 不匹配就用内嵌的可信副本原子覆盖。
func ensureWintunDLL() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	dllPath := filepath.Join(filepath.Dir(exePath), "wintun.dll")

	want := sha256.Sum256(wintunDLLBytes)

	if data, err := os.ReadFile(dllPath); err == nil {
		got := sha256.Sum256(data)
		if got == want {
			return nil // 校验通过，复用现有文件
		}
		log.Printf("🚨 [安全] wintun.dll 与内嵌版本不一致，可能已被替换！")
		log.Printf("     期望 SHA-256: %s", hex.EncodeToString(want[:]))
		log.Printf("     实际 SHA-256: %s", hex.EncodeToString(got[:]))
		log.Printf("     正在用内嵌可信副本覆盖…")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("读取 %s 失败: %w", dllPath, err)
	}

	// 原子写：先写同目录临时文件再 Rename，避免出现半截 DLL
	tmp := dllPath + ".tmp"
	if err := os.WriteFile(tmp, wintunDLLBytes, 0644); err != nil {
		return fmt.Errorf("释放 wintun.dll 失败: %w", err)
	}
	if err := os.Rename(tmp, dllPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("替换 wintun.dll 失败（可能正被其他进程占用）: %w", err)
	}

	log.Printf("✅ [安全] wintun.dll 已释放并校验通过 (SHA-256=%s…)",
		hex.EncodeToString(want[:8]))
	return nil
}
