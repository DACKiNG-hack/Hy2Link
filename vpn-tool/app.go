package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"vpn-tool/backend/config"
	"vpn-tool/backend/quic"

	"github.com/energye/systray"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

const (
	reconnectAttempts = 3
	reconnectDelay    = 2500 * time.Millisecond
)

// ⭐ 待导入的配置（跨协程/事件传递）
var (
	pendingImportMu  sync.Mutex
	pendingImport    *config.ClientConfig
	pendingImportErr string
)

type App struct {
	ctx          context.Context
	quicClient   *quic.Hysteria2Client
	healthTicker *time.Ticker
	healthStop   chan struct{}

	lastConfig config.ClientConfig
	clientMu   sync.Mutex

	reconnectMu        sync.Mutex
	reconnecting       bool
	reconnectExhausted bool
	// ⭐ 用于中断正在进行的重连（如用户主动断开）
	reconnectStop chan struct{}

	windowVisibleMu sync.Mutex
	windowVisible   bool

	quittingMu sync.Mutex
	quitting   bool

	// ⭐ 启动时传入的 .hy2 文件路径
	startupArgs []string
}

func NewApp() *App {
	return &App{}
}

// ⭐ 由 main.go 调用，记录启动参数
func (a *App) SetStartupArgs(args []string) {
	a.startupArgs = args
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.setWindowVisible(true)
	log.Println("VPN 客户端启动")

	if !isFileAssociationRegistered() {
		if err := a.RegisterFileAssociation(); err != nil {
			log.Printf("⚠️ [客户端] 注册文件关联失败: %v", err)
		} else {
			log.Println("✅ [客户端] .hy2 文件关联已注册")
		}
	}

	if len(a.startupArgs) > 0 {
		go func() {
			time.Sleep(600 * time.Millisecond)
			a.processHyFiles(a.startupArgs)
		}()
	}
}

// ---------- 退出标志 ----------

func (a *App) SetQuitting(v bool) {
	a.quittingMu.Lock()
	a.quitting = v
	a.quittingMu.Unlock()
}

func (a *App) IsQuitting() bool {
	a.quittingMu.Lock()
	defer a.quittingMu.Unlock()
	return a.quitting
}

// ---------- 窗口可见性 ----------

func (a *App) setWindowVisible(v bool) {
	a.windowVisibleMu.Lock()
	a.windowVisible = v
	a.windowVisibleMu.Unlock()
}

func (a *App) ActivateWindow() {
	if a.ctx != nil {
		runtime.WindowShow(a.ctx)
		runtime.WindowCenter(a.ctx)
		runtime.WindowSetAlwaysOnTop(a.ctx, true)
		a.setWindowVisible(true)
		go func() {
			time.Sleep(200 * time.Millisecond)
			runtime.WindowSetAlwaysOnTop(a.ctx, false)
		}()
	}
}

func (a *App) ToggleWindowVisibility() {
	if a.ctx == nil {
		return
	}

	a.windowVisibleMu.Lock()
	visible := a.windowVisible
	a.windowVisibleMu.Unlock()

	if visible {
		log.Println("🖱️ [托盘] 隐藏窗口")
		runtime.WindowHide(a.ctx)
		a.setWindowVisible(false)
	} else {
		log.Println("🖱️ [托盘] 显示窗口")
		a.ActivateWindow()
	}
}

// ---------- 托盘相关 ----------

func (a *App) ShowWindowFromTray() {
	a.ActivateWindow()
}

func (a *App) ToggleConnectionFromTray() {
	a.clientMu.Lock()
	cli := a.quicClient
	a.clientMu.Unlock()

	if cli != nil {
		log.Println("🔌 [托盘] 断开连接")
		go func() {
			_ = a.Stop()
			runtime.EventsEmit(a.ctx, "disconnected", "从托盘断开")
		}()
		return
	}

	a.ShowWindowFromTray()
}

func (a *App) QuitFromTray() {
	log.Println("🚪 [托盘] 用户请求退出")

	a.SetQuitting(true)
	_ = a.Stop()

	if a.ctx != nil {
		runtime.Quit(a.ctx)
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		systray.Quit()
	}()
}

// ---------- 连接管理 ----------

func (a *App) ConnectClient(cfg config.ClientConfig) (string, error) {
	a.lastConfig = cfg

	// ⭐ 重置重连状态（包括中断信号）
	a.reconnectMu.Lock()
	a.reconnecting = false
	a.reconnectExhausted = false
	a.reconnectStop = nil
	a.reconnectMu.Unlock()

	a.clientMu.Lock()
	if a.quicClient != nil {
		log.Println("🧹 [客户端] 清理旧连接...")
		a.quicClient.Close()
		a.quicClient = nil
	}
	a.clientMu.Unlock()

	a.stopHealthPusher()

	cli := quic.NewHysteria2Client(
		cfg.IP,
		cfg.Port,
		cfg.PortVPN,
		cfg.Username,
		cfg.Password,
		cfg.UseDHCP,
		cfg.StaticIP,
		cfg.StaticMask,
		cfg.SkipCertVerify,
	)
	cli.SetObfs(cfg.ObfsEnabled, cfg.ObfsPassword)

	ip, err := cli.Connect()
	if err != nil {
		updateTrayStatus(false)
		return "", fmt.Errorf("连接失败: %v", err)
	}

	a.clientMu.Lock()
	a.quicClient = cli
	a.clientMu.Unlock()

	updateTrayStatus(true)

	a.startHealthPusher()

	return ip, nil
}

// ---------- 指纹管理（供前端调用） ----------

func (a *App) ClearPinnedFingerprint(serverIP string) error {
	if serverIP == "" {
		a.clientMu.Lock()
		serverIP = a.lastConfig.IP
		a.clientMu.Unlock()
	}
	if serverIP == "" {
		return fmt.Errorf("未指定服务器地址")
	}
	if err := quic.ClearPinnedFingerprintByIP(serverIP); err != nil {
		return err
	}
	log.Printf("🧹 [客户端] 已清除 %s 的证书指纹", serverIP)
	return nil
}

func (a *App) HasPinnedFingerprint(serverIP string) bool {
	if serverIP == "" {
		return false
	}
	return quic.HasPinnedFingerprint(serverIP)
}

func (a *App) GetPinnedFingerprint(serverIP string) string {
	if serverIP == "" {
		return ""
	}
	return quic.GetPinnedFingerprintByIP(serverIP)
}

// ---------- ⭐ 配置导入 / 导出 ----------

func (a *App) ExportConfig(cfg config.ClientConfig) (string, error) {
	if cfg.IP == "" {
		return "", fmt.Errorf("服务器地址为空")
	}
	if cfg.Password == "" {
		return "", fmt.Errorf("认证密码为空")
	}

	defaultDir := config.DefaultDownloadsPath()
	defaultName := config.SuggestFileName(cfg)

	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:            "导出配置",
		DefaultFilename:  defaultName,
		DefaultDirectory: defaultDir,
		Filters: []runtime.FileFilter{
			{DisplayName: "Hy2Link 配置 (*.hy2)", Pattern: "*.hy2"},
		},
	})
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}

	if err := config.ExportToFile(cfg, path); err != nil {
		return "", err
	}
	log.Printf("📤 [客户端] 已导出配置: %s", path)
	return path, nil
}

func (a *App) ImportConfigDialog() (*config.ClientConfig, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "选择 Hy2Link 配置文件",
		Filters: []runtime.FileFilter{
			{DisplayName: "Hy2Link 配置 (*.hy2)", Pattern: "*.hy2"},
		},
	})
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil
	}
	return a.ImportConfigFile(path)
}

func (a *App) ImportConfigFile(path string) (*config.ClientConfig, error) {
	cfg, err := config.ParseHyFile(path)
	if err != nil {
		return nil, err
	}
	log.Printf("📥 [客户端] 已解析配置: %s:%d (obfs=%v)", cfg.IP, cfg.Port, cfg.ObfsEnabled)
	return cfg, nil
}

func (a *App) ConsumePendingImport() map[string]interface{} {
	pendingImportMu.Lock()
	defer pendingImportMu.Unlock()

	if pendingImportErr != "" {
		msg := pendingImportErr
		pendingImportErr = ""
		return map[string]interface{}{"ok": false, "error": msg}
	}
	if pendingImport == nil {
		return map[string]interface{}{"ok": false}
	}

	cfg := pendingImport
	pendingImport = nil
	return map[string]interface{}{
		"ok":     true,
		"config": cfg,
	}
}

func (a *App) HandleRemoteImport(paths []string) {
	a.ActivateWindow()
	go a.processHyFiles(paths)
}

func (a *App) processHyFiles(paths []string) {
	for _, p := range paths {
		cfg, err := config.ParseHyFile(p)

		pendingImportMu.Lock()
		if err != nil {
			pendingImportErr = err.Error()
			pendingImport = nil
			log.Printf("⚠️ [客户端] 解析配置失败 %s: %v", p, err)
		} else {
			pendingImport = cfg
			pendingImportErr = ""
			log.Printf("📥 [客户端] 收到配置文件: %s", p)
		}
		pendingImportMu.Unlock()

		if a.ctx != nil {
			runtime.EventsEmit(a.ctx, "pending-import")
		}
		return
	}
}

// ---------- ⭐ 文件关联注册 ----------

func (a *App) RegisterFileAssociation() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败: %w", err)
	}
	if err := registerFileAssociation(exe); err != nil {
		return err
	}
	log.Println("✅ [客户端] 已注册 .hy2 文件关联")
	return nil
}

func (a *App) IsFileAssociationRegistered() bool {
	return isFileAssociationRegistered()
}

// ---------- 健康状态推送 ----------

func (a *App) startHealthPusher() {
	a.stopHealthPusher()

	ticker := time.NewTicker(2 * time.Second)
	stop := make(chan struct{})

	a.healthTicker = ticker
	a.healthStop = stop

	go func(t *time.Ticker, s chan struct{}) {
		log.Println("📊 [健康推送] 协程已启动")
		for {
			select {
			case <-s:
				log.Println("📊 [健康推送] 协程退出")
				return
			case <-t.C:
				a.clientMu.Lock()
				cli := a.quicClient
				a.clientMu.Unlock()

				if cli == nil {
					continue
				}

				snapshot := cli.GetHealthSnapshot()
				runtime.EventsEmit(a.ctx, "health", snapshot)

				if kicked, _ := snapshot["kicked"].(bool); kicked {
					reason, _ := snapshot["kickedReason"].(string)
					if reason == "" {
						reason = "服务端将你踢出连线"
					}
					log.Printf("🚫 [客户端] 检测到被踢: %s", reason)

					a.reconnectMu.Lock()
					a.reconnectExhausted = true
					a.reconnectMu.Unlock()

					a.autoDisconnect(reason)
					return
				}

				state, _ := snapshot["state"].(string)
				switch state {
				case "reconnecting":
					a.tryReconnect()
				case "offline":
					log.Println("🛑 [客户端] 服务端离线，自动断开")
					a.autoDisconnect("服务端已离线")
					return
				}
			}
		}
	}(ticker, stop)

	log.Println("📊 健康状态推送已启动")
}

// ---------- 尝试重连 ----------

func (a *App) tryReconnect() {
	a.reconnectMu.Lock()
	if a.reconnecting || a.reconnectExhausted {
		a.reconnectMu.Unlock()
		return
	}
	a.reconnecting = true
	// ⭐ 新建一个可被外部关闭的中断信号
	stopCh := make(chan struct{})
	a.reconnectStop = stopCh
	a.reconnectMu.Unlock()

	go func(stop <-chan struct{}) {
		defer func() {
			a.reconnectMu.Lock()
			a.reconnecting = false
			// 只清自己这一轮的 stop channel（避免覆盖新的）
			if a.reconnectStop == stopCh {
				a.reconnectStop = nil
			}
			a.reconnectMu.Unlock()
		}()

		for attempt := 1; attempt <= reconnectAttempts; attempt++ {
			// ⭐ 每轮开始检查是否已被取消
			a.reconnectMu.Lock()
			aborted := a.reconnectExhausted
			a.reconnectMu.Unlock()
			if aborted {
				log.Printf("🛑 [客户端] 重连已被取消（用户断开或已放弃）")
				return
			}

			log.Printf("🔄 [客户端] 第 %d/%d 次重连尝试...", attempt, reconnectAttempts)
			runtime.EventsEmit(a.ctx, "reconnecting", attempt)

			a.clientMu.Lock()
			old := a.quicClient
			a.quicClient = nil
			a.clientMu.Unlock()

			if old != nil {
				old.Close()
			}

			// ⭐ 可中断的等待
			select {
			case <-stop:
				log.Printf("🛑 [客户端] 重连等待被中断（用户断开）")
				return
			case <-time.After(reconnectDelay):
			}

			// 再次检查，避免等待期间被取消
			a.reconnectMu.Lock()
			aborted = a.reconnectExhausted
			a.reconnectMu.Unlock()
			if aborted {
				log.Printf("🛑 [客户端] 重连已被取消（用户断开或已放弃）")
				return
			}

			cli := quic.NewHysteria2Client(
				a.lastConfig.IP,
				a.lastConfig.Port,
				a.lastConfig.PortVPN,
				a.lastConfig.Username,
				a.lastConfig.Password,
				a.lastConfig.UseDHCP,
				a.lastConfig.StaticIP,
				a.lastConfig.StaticMask,
				a.lastConfig.SkipCertVerify,
			)
			cli.SetObfs(a.lastConfig.ObfsEnabled, a.lastConfig.ObfsPassword)

			ip, err := cli.Connect()
			if err != nil {
				log.Printf("⚠️ [客户端] 第 %d 次重连失败: %v", attempt, err)
				cli.Close()
				continue
			}

			// ⭐ 连接成功前再检查一次（避免用户恰好在这一刻点了断开）
			a.reconnectMu.Lock()
			aborted = a.reconnectExhausted
			a.reconnectMu.Unlock()
			if aborted {
				log.Printf("🛑 [客户端] 重连成功但已被取消，丢弃连接")
				cli.Close()
				return
			}

			a.clientMu.Lock()
			a.quicClient = cli
			a.clientMu.Unlock()

			updateTrayStatus(true)

			log.Printf("✅ [客户端] 重连成功，虚拟 IP: %s", ip)
			runtime.EventsEmit(a.ctx, "reconnected", ip)
			return
		}

		log.Printf("⚠️ [客户端] 重连 %d 次均失败，连接已断开", reconnectAttempts)
		a.reconnectMu.Lock()
		a.reconnectExhausted = true
		a.reconnectMu.Unlock()

		a.autoDisconnect("重连失败，连接已断开")
	}(stopCh)
}

// ⭐ 中断正在进行的重连（不改动 quicClient 状态）
func (a *App) abortReconnectLocked() {
	a.reconnectExhausted = true
	if a.reconnectStop != nil {
		close(a.reconnectStop)
		a.reconnectStop = nil
	}
}

func (a *App) autoDisconnect(reason string) {
	a.stopHealthPusher()

	// ⭐ 中断可能正在进行的重连
	a.reconnectMu.Lock()
	a.abortReconnectLocked()
	a.reconnectMu.Unlock()

	a.clientMu.Lock()
	cli := a.quicClient
	a.quicClient = nil
	a.clientMu.Unlock()

	if cli != nil {
		cli.Close()
	}

	updateTrayStatus(false)

	runtime.EventsEmit(a.ctx, "disconnected", reason)
	log.Printf("📢 [客户端] 已通知前端断开: %s", reason)
}

func (a *App) stopHealthPusher() {
	if a.healthTicker != nil {
		a.healthTicker.Stop()
		a.healthTicker = nil
	}
	if a.healthStop != nil {
		close(a.healthStop)
		a.healthStop = nil
	}
}

func (a *App) GetHealth() map[string]interface{} {
	a.clientMu.Lock()
	cli := a.quicClient
	a.clientMu.Unlock()

	if cli == nil {
		return map[string]interface{}{
			"state":           "offline",
			"lastRecvAgo":     0.0,
			"lastPongAgo":     0.0,
			"consecutiveFail": 0,
			"kicked":          false,
			"kickedReason":    "",
			"latency":         -1,
		}
	}
	return cli.GetHealthSnapshot()
}

func (a *App) Stop() error {
	a.stopHealthPusher()

	// ⭐ 中断可能正在进行的重连
	a.reconnectMu.Lock()
	a.abortReconnectLocked()
	a.reconnectMu.Unlock()

	a.clientMu.Lock()
	cli := a.quicClient
	a.quicClient = nil
	a.clientMu.Unlock()

	if cli != nil {
		cli.Close()
	}

	updateTrayStatus(false)

	return nil
}

func (a *App) Greet(name string) string {
	return "Hello " + name
}

func (a *App) GetClientVersion() string {
	return quic.ClientVersion
}

// 保留供 tray.go 使用
var _ = strings.TrimSpace
