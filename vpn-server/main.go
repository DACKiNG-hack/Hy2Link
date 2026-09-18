package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"vpn-server/admin"
	"vpn-server/cert"
	"vpn-server/config"
	"vpn-server/manager"
	"vpn-server/store"
)

func main() {
	if !EnsureSingleInstance() {
		ShowAlreadyRunningDialog()
		return
	}
	defer ReleaseSingleInstance()

	if runtime.GOOS == "windows" {
		if err := ensureWintunDLL(); err != nil {
			log.Printf("警告: 释放 wintun.dll 失败: %v", err)
		}
	}

	initLogControl()
	setupConsoleEncoding()
	setupConsoleInputMode()

	if strings.ToLower(os.Getenv("HY_DEBUG")) != "true" {
		os.Setenv("QUIC_GO_LOG_LEVEL", "error")
	}

	dataDir := os.Getenv("HY_DATA_DIR")
	if dataDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			showMsgBox("启动失败", "获取工作目录失败:\n"+err.Error())
			os.Exit(1)
		}
		dataDir = wd
	}
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}

	closeLog := SetupLogOutput(dataDir)
	defer func() { closeLog() }()

	hasConsole := HasConsole()
	if hasConsole {
		fmt.Printf("📂 数据目录: %s\n", dataDir)
	}

	// 用户存储
	usersFile := filepath.Join(dataDir, "users.json")
	userStore, err := store.NewStore(usersFile)
	if err != nil {
		if hasConsole {
			fmt.Printf("加载用户存储失败: %v\n", err)
		} else {
			showMsgBox("启动失败", "加载用户存储失败:\n"+err.Error())
		}
		os.Exit(1)
	}

	_, logEnabled, highPriority, _ := userStore.GetPerformanceConfig()
	if !logEnabled {
		SetLogEnabled(false)
	}
	if highPriority {
		SetHighPriority(true)
	}

	// ⭐ 不再在这里初始化管理员，改为浏览器端初始化
	if !userStore.HasAdmin() && hasConsole {
		fmt.Println("⚠️  尚未初始化管理员账户，请打开浏览器完成初始化")
	}

	if hasConsole {
		fmt.Printf("👥 用户: %s (全局密码: %s, 多用户数: %d)\n",
			usersFile, userStore.GetGlobalPassword(), len(userStore.List()))
	}

	stopFlush := make(chan struct{})
	go userStore.FlushLoop(30*time.Second, stopFlush)
	defer close(stopFlush)

	// 服务端配置
	serverCfgFile := filepath.Join(dataDir, "server.json")
	serverCfg, err := config.Load(serverCfgFile)
	if err != nil {
		if hasConsole {
			fmt.Printf("加载服务端配置失败: %v\n", err)
		} else {
			showMsgBox("启动失败", "加载服务端配置失败:\n"+err.Error())
		}
		os.Exit(1)
	}
	if hasConsole {
		fmt.Printf("⚙️ 服务端配置: %s\n", serverCfgFile)
	}

	// ⭐ 自检
	issues := SelfCheck(serverCfg, dataDir)
	if PrintSelfCheckResult(issues) {
		if hasConsole {
			fmt.Println()
			fmt.Println("❌ 启动自检失败，请修复以上错误后重试。")
			fmt.Println("   按回车键退出...")
			buf := make([]byte, 1)
			_, _ = os.Stdin.Read(buf)
		} else {
			showMsgBox("启动失败", "服务端启动自检失败:\n\n"+FormatIssuesForDialog(issues))
		}
		os.Exit(1)
	}

	// ⭐ 证书管理器
	certCfgFile := filepath.Join(dataDir, "cert.json")
	certMgr, err := cert.NewManager(certCfgFile, dataDir)
	if err != nil {
		if hasConsole {
			fmt.Printf("加载证书配置失败: %v\n", err)
		} else {
			showMsgBox("启动失败", "加载证书配置失败:\n"+err.Error())
		}
		os.Exit(1)
	}

	// ⭐ AdminState & Manager（传 certMgr）
	adminState := admin.NewAdminState("1.0.0")
	mgr := manager.New(serverCfg, serverCfgFile, userStore, adminState, certMgr)

	// Web 管理面板
	adminAddr := getEnv("HY_ADMIN_ADDR", "127.0.0.1:8444")
	if adminAddr == "off" {
		if hasConsole {
			fmt.Println("HY_ADMIN_ADDR=off，Web 面板已禁用")
		}
		os.Exit(1)
	}
	adminSrv := admin.NewServer(adminAddr, adminState, userStore, mgr)

	adminSrv.SetLogControl(SetLogEnabled)
	adminSrv.SetPriorityControl(SetHighPriority)

	go func() {
		if err := adminSrv.Start(); err != nil {
			log.Printf("管理后台退出: %v", err)
		}
	}()

	// ⭐ 判断是否需要浏览器初始化
	needSetup := !userStore.HasAdmin()
	panelURL := fmt.Sprintf("http://%s", adminAddr)

	if needSetup {
		if hasConsole {
			fmt.Println()
			fmt.Println("╔══════════════════════════════════════════════╗")
			fmt.Println("║  首次启动：请打开浏览器完成管理员初始化       ║")
			fmt.Println("╚══════════════════════════════════════════════╝")
			fmt.Printf("   面板地址: %s\n", panelURL)
			fmt.Println()
		}
		time.AfterFunc(1*time.Second, func() {
			openBrowser(panelURL)
		})
	} else if hasConsole {
		fmt.Printf("🖥️  管理面板: %s\n", panelURL)
	}

	// 自动启动 VPN
	if serverCfg.AutoStart {
		go func() {
			time.Sleep(800 * time.Millisecond)
			if err := mgr.Start(); err != nil {
				log.Printf("⚠️ 自动启动服务端失败: %v", err)
			}
		}()
	} else if hasConsole {
		fmt.Printf("⏸️ AutoStart 已关闭，请打开 %s 手动启动服务端\n", panelURL)
	}

	// 退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			<-quit
			if !mgr.Status().Running {
				break
			}
			if hasConsole {
				fmt.Println()
				fmt.Println("⚠️  警告：VPN 服务端正在运行")
				fmt.Println("    退出将断开所有在线客户端。")
				fmt.Println("    • 5 秒后自动退出")
				fmt.Println("    • 或再次按 Ctrl+C 立即退出")
				fmt.Println()
			}
			select {
			case <-quit:
				if hasConsole {
					fmt.Println("⛔ 收到强制退出信号")
				}
			case <-time.After(5 * time.Second):
				if hasConsole {
					fmt.Println("⏱️  等待超时，正在退出…")
				}
			}
			break
		}
		_ = mgr.Stop()
		_ = adminSrv.Stop()
		certMgr.Stop()
		os.Exit(0)
	}()

	// 主线程：运行托盘
	if strings.ToLower(os.Getenv("HY_TRAY")) != "off" {
		trayShutdown := func() {
			quit <- syscall.SIGTERM
		}
		if hasConsole {
			fmt.Println("🖥️ [托盘] 已启动（右键托盘图标可操作）")
		}
		runTray(mgr, adminAddr, trayShutdown)
	} else {
		select {}
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// 保证 exec 被使用（openBrowser 在 tray_windows.go 里）
var _ = exec.Command
