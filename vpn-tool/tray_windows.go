//go:build windows

//tray_windows.go

package main

import (
	_ "embed"
	"log"
	"runtime"
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

// ⭐ 托盘回调安全包装：异步执行 + recover
func safeCall(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("⚠️ [托盘] %s panic: %v", name, r)
			}
		}()
		fn()
	}()
}

// startTray 启动托盘
func startTray(app *App) {
	go func() {
		// ⭐ 关键：systray 需要独占一个 OS 线程
		//    Windows 的消息泵必须绑定到固定线程，否则跑一段时间后消息会丢失
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		systray.Run(
			func() { onTrayReady(app) },
			func() { log.Println("🔚 [托盘] 已退出") },
		)
	}()
}

func onTrayReady(app *App) {
	log.Println("🖱️ [托盘] 初始化中...")

	systray.SetIcon(trayIcon)
	systray.SetTitle("Hy2Link")
	systray.SetTooltip("Hy2Link · 未连接")

	// ⭐ 所有点击回调都异步执行，避免阻塞消息泵
	systray.SetOnClick(func(menu systray.IMenu) {
		safeCall("OnClick", func() {
			app.ToggleWindowVisibility()
		})
	})

	systray.SetOnDClick(func(menu systray.IMenu) {
		safeCall("OnDClick", func() {
			app.ToggleWindowVisibility()
		})
	})

	// ⚠️ RClick 的 menu.ShowMenu() 不能异步，
	//    它是 systray 内部 API，必须在消息泵线程调用
	systray.SetOnRClick(func(menu systray.IMenu) {
		menu.ShowMenu()
	})

	// ========== 右键菜单项 ==========
	mShow := systray.AddMenuItem("显示主窗口", "打开主界面")
	mShow.Click(func() {
		safeCall("ShowWindow", func() {
			app.ShowWindowFromTray()
		})
	})

	trayMenuToggle = systray.AddMenuItem("连接", "连接 / 断开")
	trayMenuToggle.Click(func() {
		safeCall("ToggleConnection", func() {
			app.ToggleConnectionFromTray()
		})
	})

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("退出", "完全退出客户端")
	mQuit.Click(func() {
		safeCall("Quit", func() {
			app.QuitFromTray()
		})
	})

	trayReadyOnce.Do(func() { close(trayReady) })

	log.Println("✅ [托盘] 已就绪")

	// ⭐ 去掉 select {}，让 onReady 正常返回
	//    systray 内部会接管消息循环
}

// updateTrayStatus 由 App 在连接状态变化时调用
func updateTrayStatus(connected bool) {
	select {
	case <-trayReady:
	default:
		return
	}
	if trayMenuToggle == nil {
		return
	}

	// ⭐ 异步更新，避免阻塞调用方
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("⚠️ [托盘] updateTrayStatus panic: %v", r)
			}
		}()
		if connected {
			systray.SetTooltip("Hy2Link · 已连接")
			trayMenuToggle.SetTitle("断开")
		} else {
			systray.SetTooltip("Hy2Link · 未连接")
			trayMenuToggle.SetTitle("连接")
		}
	}()
}
