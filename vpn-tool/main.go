package main

// vpn-tool\main.go

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
			// ⭐ 安全审计 S12：完整性无法确认时必须显式告警
			log.Printf("🚨 [安全] wintun.dll 完整性校验/释放失败: %v", err)
			log.Printf("     若程序目录可被普通用户写入，请改用管理员专属目录（如 Program Files）安装。")
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

// ipcMaxConcurrent 限制并发处理的 IPC 连接数。
// ⭐ 安全审计 S16：原实现每条连接一个 goroutine 且没有读超时，
// 本地任意进程都能开成千上万个连接，每个钉住一个 goroutine + 8 KiB，
// 直至内存/句柄耗尽。
const ipcMaxConcurrent = 8

func startActivationListener(app *App) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", instancePort))
	if err != nil {
		log.Printf("启动激活监听失败: %v", err)
		return
	}
	defer listener.Close()

	sem := make(chan struct{}, ipcMaxConcurrent)

	for {
		conn, err := listener.Accept()
		if err != nil {
			// ⭐ 安全审计 S16/S41：原实现无条件 continue，
			// 监听器一旦永久性出错就变成 100% CPU 忙循环。
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("⚠️ [IPC] Accept 失败: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		select {
		case sem <- struct{}{}:
		default:
			log.Printf("⚠️ [IPC] 并发连接已达上限，拒绝 %s", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}

		go func(c net.Conn) {
			defer func() { <-sem }()
			defer c.Close()

			// ⭐ 安全审计 S16：必须设置读超时，
			// 否则连接可以被无限期挂住（每个连接占一个 goroutine）。
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))

			// ⭐ 安全审计 S16：用 json.Decoder 读取**一个完整 JSON 对象**。
			// 原来只调用一次 c.Read()，TCP 分包时 JSON 会被截断，
			// json.Unmarshal 失败后静默降级为「只激活窗口」，
			// 用户的导入请求被悄悄丢弃。
			var msg instanceMsg
			dec := json.NewDecoder(io.LimitReader(c, 64*1024))
			if err := dec.Decode(&msg); err != nil {
				// 兼容旧版纯文本协议（发送 "ACTIVATE" 时 JSON 解码必然失败）
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
