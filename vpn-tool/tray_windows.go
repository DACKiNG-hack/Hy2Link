//go:build windows

package main

import (
	_ "embed"
	"log"
	"sync"

	"github.com/energye/systray"
)

//go:embed assets/tray.ico
var trayIcon []byte

var (
	trayReady      = make(chan struct{})
	trayReadyOnce  sync.Once
	trayMenuToggle *systray.MenuItem
)

// startTray 启动托盘（阻塞在 systray.Run，需在 goroutine 里调用）
func startTray(app *App) {
	go func() {
		systray.Run(
			func() { onTrayReady(app) },
			func() { log.Println("🔚 [托盘] 已退出") },
		)
	}()
}

func onTrayReady(app *App) {
	systray.SetIcon(trayIcon)
	systray.SetTitle("Hy2Link")
	systray.SetTooltip("Hy2Link · 未连接")

	// ⭐ 左键单击：切换窗口显示/隐藏
	systray.SetOnClick(func(menu systray.IMenu) {
		app.ToggleWindowVisibility()
	})

	// ⭐ 左键双击：同上
	systray.SetOnDClick(func(menu systray.IMenu) {
		app.ToggleWindowVisibility()
	})

	// ⭐ 右键单击：弹出菜单
	systray.SetOnRClick(func(menu systray.IMenu) {
		menu.ShowMenu()
	})

	// ========== 右键菜单项（回调方式） ==========
	mShow := systray.AddMenuItem("显示主窗口", "打开主界面")
	mShow.Click(func() {
		app.ShowWindowFromTray()
	})

	trayMenuToggle = systray.AddMenuItem("连接", "连接 / 断开")
	trayMenuToggle.Click(func() {
		app.ToggleConnectionFromTray()
	})

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("退出", "完全退出客户端")
	mQuit.Click(func() {
		app.QuitFromTray()
	})

	trayReadyOnce.Do(func() { close(trayReady) })

	// ⭐ 阻塞当前 goroutine，让托盘保持运行
	// 事件通过上面的 Click 回调处理，不需要循环监听
	select {}
}

// updateTrayStatus 由 App 在连接状态变化时调用
func updateTrayStatus(connected bool) {
	select {
	case <-trayReady:
		// 托盘已就绪
	default:
		return // 托盘还没起来，忽略
	}
	if trayMenuToggle == nil {
		return
	}
	if connected {
		systray.SetTooltip("Hy2Link · 已连接")
		trayMenuToggle.SetTitle("断开")
	} else {
		systray.SetTooltip("Hy2Link · 未连接")
		trayMenuToggle.SetTitle("连接")
	}
}
