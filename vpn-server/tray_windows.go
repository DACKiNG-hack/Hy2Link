//go:build windows

package main

import (
	_ "embed"
	"log"
	"os/exec"
	"runtime"
	"time"

	"fyne.io/systray"

	"vpn-server/manager"
)

//go:embed assets/tray.ico
var trayIcon []byte

func runTray(mgr *manager.Manager, adminAddr string, shutdown func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	systray.Run(
		func() { onTrayReady(mgr, adminAddr, shutdown) },
		func() { log.Println("🔚 [托盘] 已退出") },
	)
}

func onTrayReady(mgr *manager.Manager, adminAddr string, shutdown func()) {
	systray.SetIcon(trayIcon)
	systray.SetTitle("Hy2Link 服务端")
	systray.SetTooltip("Hy2Link 服务端 · 已停止")

	mOpenPanel := systray.AddMenuItem("打开 Web 面板", "在浏览器打开管理界面")
	mOpenLogs := systray.AddMenuItem("打开日志目录", "查看运行日志")
	systray.AddSeparator()
	mStart := systray.AddMenuItem("启动服务端", "启动 VPN 服务")
	mStop := systray.AddMenuItem("停止服务端", "停止 VPN 服务")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("退出", "完全退出服务端")

	if mgr.Status().Running {
		mStart.Disable()
	} else {
		mStop.Disable()
	}

	// 后台同步状态
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			running := mgr.Status().Running
			if running {
				systray.SetTooltip("Hy2Link 服务端 · 运行中")
				mStart.Disable()
				mStop.Enable()
			} else {
				systray.SetTooltip("Hy2Link 服务端 · 已停止")
				mStart.Enable()
				mStop.Disable()
			}
		}
	}()

	for {
		select {
		case <-mOpenPanel.ClickedCh:
			openBrowser("http://" + adminAddr)

		case <-mOpenLogs.ClickedCh:
			openLogDir()

		case <-mStart.ClickedCh:
			log.Println("🖱️ [托盘] 启动服务端")
			go func() {
				if err := mgr.Start(); err != nil {
					log.Printf("⚠️ [托盘] 启动失败: %v", err)
				}
			}()

		case <-mStop.ClickedCh:
			log.Println("🖱️ [托盘] 停止服务端")
			go func() {
				if err := mgr.Stop(); err != nil {
					log.Printf("⚠️ [托盘] 停止失败: %v", err)
				}
			}()

		case <-mQuit.ClickedCh:
			log.Println("🖱️ [托盘] 退出")
			if shutdown != nil {
				shutdown()
			}
			return
		}
	}
}

func openBrowser(url string) {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	if err := cmd.Start(); err != nil {
		log.Printf("⚠️ [托盘] 打开浏览器失败: %v", err)
	}
}

func openLogDir() {
	cmd := exec.Command("explorer", "logs")
	_ = cmd.Start()
}
