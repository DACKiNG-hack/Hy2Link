package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"vpn-server/config"
)

// SelfCheckIssue 表示一个自检问题
type SelfCheckIssue struct {
	Level   string // "warn" 或 "error"
	Message string
}

// SelfCheck 执行启动自检，返回问题列表
func SelfCheck(cfg *config.ServerConfig, dataDir string) []SelfCheckIssue {
	var issues []SelfCheckIssue

	// 1. 数据目录可写
	if err := checkDirWritable(dataDir); err != nil {
		issues = append(issues, SelfCheckIssue{
			Level:   "error",
			Message: fmt.Sprintf("数据目录不可写 %s: %v", dataDir, err),
		})
	}

	// 2. server.json 可读
	cfgFile := filepath.Join(dataDir, "server.json")
	if _, err := os.Stat(cfgFile); err != nil {
		if !os.IsNotExist(err) {
			issues = append(issues, SelfCheckIssue{
				Level:   "warn",
				Message: fmt.Sprintf("配置文件无法读取 %s: %v", cfgFile, err),
			})
		}
	}

	// 3. users.json 可读
	usersFile := filepath.Join(dataDir, "users.json")
	if _, err := os.Stat(usersFile); err != nil {
		if !os.IsNotExist(err) {
			issues = append(issues, SelfCheckIssue{
				Level:   "warn",
				Message: fmt.Sprintf("用户存储无法读取 %s: %v", usersFile, err),
			})
		}
	}

	// 4. 磁盘空间
	if free, err := checkDiskFree(dataDir); err == nil && free < 100*1024*1024 {
		issues = append(issues, SelfCheckIssue{
			Level:   "warn",
			Message: fmt.Sprintf("磁盘剩余空间不足: %.1f MB（建议 > 100 MB）", float64(free)/1024/1024),
		})
	}

	// 5. VPN 端口是否被占用（只在 AutoStart 时检查）
	if cfg.AutoStart {
		addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", cfg.Port))
		conn, err := net.ListenUDP("udp4", addr)
		if err != nil {
			issues = append(issues, SelfCheckIssue{
				Level:   "error",
				Message: fmt.Sprintf("VPN UDP 端口 %d 已被占用: %v", cfg.Port, err),
			})
		} else {
			_ = conn.Close()
		}
	}

	// 6. 关键配置有效性
	if cfg.Port < 1 || cfg.Port > 65535 {
		issues = append(issues, SelfCheckIssue{
			Level:   "error",
			Message: fmt.Sprintf("VPN 端口无效: %d", cfg.Port),
		})
	}
	if cfg.IPPoolStart == "" || cfg.IPPoolEnd == "" {
		issues = append(issues, SelfCheckIssue{
			Level:   "error",
			Message: "IP 池未配置（IPPoolStart / IPPoolEnd）",
		})
	}

	return issues
}

func checkDirWritable(dir string) error {
	testFile := filepath.Join(dir, ".selfcheck_tmp")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return err
	}
	_ = os.Remove(testFile)
	return nil
}

// PrintSelfCheckResult 打印自检结果。返回值：是否有 error 级问题
func PrintSelfCheckResult(issues []SelfCheckIssue) (hasError bool) {
	if len(issues) == 0 {
		log.Printf("✅ [自检] 全部通过")
		return false
	}

	var errs, warns []SelfCheckIssue
	for _, i := range issues {
		if i.Level == "error" {
			errs = append(errs, i)
		} else {
			warns = append(warns, i)
		}
	}

	if len(errs) > 0 {
		log.Printf("❌ [自检] 发现 %d 个错误:", len(errs))
		for _, i := range errs {
			log.Printf("   - %s", i.Message)
		}
		hasError = true
	}
	if len(warns) > 0 {
		log.Printf("⚠️  [自检] 发现 %d 个警告:", len(warns))
		for _, i := range warns {
			log.Printf("   - %s", i.Message)
		}
	}
	return
}

// FormatIssuesForDialog 把问题格式化成弹窗文本
func FormatIssuesForDialog(issues []SelfCheckIssue) string {
	var sb strings.Builder
	for _, i := range issues {
		if i.Level == "error" {
			sb.WriteString("❌ ")
		} else {
			sb.WriteString("⚠️  ")
		}
		sb.WriteString(i.Message)
		sb.WriteString("\n")
	}
	return sb.String()
}
