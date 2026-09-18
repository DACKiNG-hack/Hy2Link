package main

// vpn-tool\main.go

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

const instancePort = 59001

// ⭐ 单实例通信协议（兼容旧版纯文本 "ACTIVATE"）
type instanceMsg struct {
	Cmd  string   `json:"cmd"`            // "activate" | "import"
	Args []string `json:"args,omitempty"` // 附加参数（.hy2 文件路径）
}

func main() {
	// ========== 禁用 quic-go 调试日志 ==========
	if strings.ToLower(os.Getenv("HY_DEBUG")) != "true" {
		os.Setenv("QUIC_GO_LOG_LEVEL", "error")
	}

	// ⭐ 从命令行中提取 .hy2 文件路径
	hyFiles := extractHyFiles(os.Args[1:])

	// 单实例检测
	if isAnotherInstanceRunning() {
		msg := instanceMsg{Cmd: "activate"}
		if len(hyFiles) > 0 {
			msg.Cmd = "import"
			msg.Args = hyFiles
		}

		if err := sendInstanceSignal(msg); err == nil {
			log.Println("已激活已有窗口，本实例退出")
			return
		}

		// 端口可能刚释放，重试一次
		time.Sleep(300 * time.Millisecond)
		if err := sendInstanceSignal(msg); err == nil {
			log.Println("已激活已有窗口（重试成功），本实例退出")
			return
		}

		log.Println("激活信号发送失败，尝试启动新实例")
	}

	// Windows 下释放 wintun.dll
	if runtime.GOOS == "windows" {
		if err := ensureWintunDLL(); err != nil {
			log.Printf("警告: 释放 wintun.dll 失败: %v", err)
		} else {
			log.Println("wintun.dll 已就绪")
		}
	}

	app := NewApp()
	// ⭐ 把启动时的 .hy2 文件路径交给 app，startup 时处理
	app.SetStartupArgs(hyFiles)

	// ⭐ 启动托盘
	startTray(app)

	err := wails.Run(&options.App{
		Title:     "Hy2Link客户端",
		Width:     1280,
		Height:    760,
		MinWidth:  1000,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		Bind: []interface{}{app},
		OnStartup: func(ctx context.Context) {
			app.startup(ctx)
			go startActivationListener(app)
		},
		// ⭐ 关闭窗口 → 隐藏到托盘；主动退出时放行
		OnBeforeClose: func(ctx context.Context) (prevent bool) {
			if app.IsQuitting() {
				return false
			}
			wailsruntime.WindowHide(ctx)
			app.setWindowVisible(false)
			return true
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}

// ⭐ 从命令行参数中过滤出 .hy2 文件路径
func extractHyFiles(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasSuffix(strings.ToLower(a), ".hy2") {
			out = append(out, a)
		}
	}
	return out
}

// 单实例相关函数
func isAnotherInstanceRunning() bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", instancePort), 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ⭐ 发送结构化信号（JSON + 换行）
func sendInstanceSignal(msg instanceMsg) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", instancePort), 300*time.Millisecond)
	if err != nil {
		return err
	}
	defer conn.Close()
	data, _ := json.Marshal(msg)
	data = append(data, '\n')
	_, err = conn.Write(data)
	return err
}

func startActivationListener(app *App) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", instancePort))
	if err != nil {
		log.Printf("启动激活监听失败: %v", err)
		return
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()

			buf := make([]byte, 8192)
			n, err := c.Read(buf)
			if err != nil || n == 0 {
				app.ActivateWindow()
				return
			}

			text := strings.TrimSpace(string(buf[:n]))

			// 兼容旧版纯文本协议
			if text == "ACTIVATE" {
				app.ActivateWindow()
				return
			}

			var msg instanceMsg
			if err := json.Unmarshal(buf[:n], &msg); err != nil {
				app.ActivateWindow()
				return
			}

			switch msg.Cmd {
			case "activate":
				app.ActivateWindow()
			case "import":
				app.HandleRemoteImport(msg.Args)
			default:
				app.ActivateWindow()
			}
		}(conn)
	}
}
