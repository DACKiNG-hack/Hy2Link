package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
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
	// ⭐ 安全审计 S35：连接（含 DHCP 协商）的整体看门狗超时。
	//    hy-core 的 TCP() 内部是一次没有 deadline 的 io.ReadFull，
	//    恶意/异常服务端只要完成认证后不回应 DHCP 流，
	//    就能让 Connect() 永久阻塞，而此刻 a.quicClient 还是 nil，
	//    Stop() 什么也做不了 —— 用户只能杀进程。
	connectTimeout = 30 * time.Second
)

// ⭐ 待导入的配置（跨协程/事件传递）
var (
	pendingImportMu  sync.Mutex
	pendingImport    *config.ClientConfig
	pendingImportErr string
)

type App struct {
	ctx        context.Context
	quicClient *quic.Hysteria2Client

	// ⭐ 安全审计 S35：正在连接中的客户端。
	// Connect() 期间 quicClient 尚未赋值，必须单独记录，否则无法取消。
	pendingClient *quic.Hysteria2Client

	// ⭐ 安全审计 S15：healthTicker/healthStop 原来没有任何互斥保护，
	//    而 stopHealthPusher 会从 Wails UI 线程、健康推送协程、
	//    重连协程三处并发调用 → 同一个 channel 可能被 close 两次
	//    → "close of closed channel" panic 直接崩溃客户端。
	healthMu     sync.Mutex
	healthTicker *time.Ticker
	healthStop   chan struct{}

	lastConfig config.ClientConfig
	clientMu   sync.Mutex

	reconnectMu        sync.Mutex
	reconnecting       bool
	reconnectExhausted bool
	// ⭐ 用于中断正在进行的重连（如用户主动断开）
	reconnectStop chan struct{}
	// ⭐ 安全审计 S37：代际号。ConnectClient 会自增它，
	//   在途的重连协程发现代际不匹配就必须立刻放弃，
	//   不能再碰 a.quicClient（否则会关掉用户刚建立的新连接）。
	reconnectEpoch uint64

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

// ⭐ 最轻量的窗口唤起：
//
//	只 Show + Unminimise，避免频繁跨线程调用拖垮托盘消息泵。
//	原先的 WindowCenter + WindowSetAlwaysOnTop × 2 会在每次托盘点击时
//	触发 3~4 次跨线程 runtime 调用 + 1 个定时器，长时间高频点击后
//	会累积阻塞 systray 的消息循环，表现为"托盘图标点击无响应"。
func (a *App) ActivateWindow() {
	if a.ctx == nil {
		return
	}
	runtime.WindowShow(a.ctx)
	runtime.WindowUnminimise(a.ctx)
	a.setWindowVisible(true)
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
	// ⭐ 安全审计 S37：lastConfig 的读写一律在 clientMu 下进行，
	//    原来这里是无锁写、而 tryReconnect 里是无锁读 → 数据竞争，
	//    可能出现「A 服务器的 IP 配 B 服务器的口令」的撕裂读。
	a.clientMu.Lock()
	a.lastConfig = cfg
	a.clientMu.Unlock()

	// ⭐ 安全审计 S37：重置重连状态时**必须先真正中断**在途的重连协程。
	//    原实现只是把 reconnectStop 置 nil（没有 close），并把
	//    reconnectExhausted 重置为 false，于是那个协程既收不到中断信号、
	//    又以为自己仍然有效 —— 它会在用户新连接建立后取走 a.quicClient
	//    并把它 Close 掉。这里改为：close 旧 channel + 自增代际号。
	a.reconnectMu.Lock()
	if a.reconnectStop != nil {
		close(a.reconnectStop)
		a.reconnectStop = nil
	}
	a.reconnectEpoch++
	a.reconnecting = false
	a.reconnectExhausted = false
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
	// ⭐ 1b-2A：本机「禁用 P2P」开关（取反传给 SetP2P）。
	//    ⚠️ 配置里存的是「禁用」（默认 false = 不禁止），因为 Go bool 零值必须是「启用」语义，
	//    否则旧配置/旧 .hy2 会静默变成禁用 P2P（详见 config.ClientConfig.P2PDisabled 注释）。
	cli.SetP2P(!cfg.P2PDisabled)
	// ⭐ P2SP 阶段 1b：直连状态 → Wails 事件（前端订阅 "p2p:status"）
	//    只在状态变化时发；失败一律是普通提示，绝不弹阻断式对话框。
	cli.SetP2PStatusHandler(func(st quic.P2PStatus) {
		if a.ctx == nil {
			return
		}
		runtime.EventsEmit(a.ctx, "p2p:status", st)
	})

	// ⭐ 安全审计 S35：登记「正在连接」的客户端，并启动看门狗。
	//    Connect() 期间 a.quicClient 仍是 nil，Stop() 无法取消它，
	//    所以必须有一个独立的引用，且要有超时兜底。
	a.clientMu.Lock()
	a.pendingClient = cli
	a.clientMu.Unlock()

	watchdog := time.AfterFunc(connectTimeout, func() {
		log.Printf("⏱️ [客户端] 连接超过 %v 仍未完成，强制中止", connectTimeout)
		cli.Close()
	})

	ip, err := cli.Connect()
	watchdog.Stop()

	a.clientMu.Lock()
	if a.pendingClient == cli {
		a.pendingClient = nil
	}
	a.clientMu.Unlock()

	if err != nil {
		// ⭐ 关键：Connect 中途失败可能残留 TUN 设备 / Transport / hysteria client
		//    这里再兜底一次（client.go 内部已有 defer 清理，双重保险）
		cli.Close()
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

// isSafeHyFilePath 校验来自外部的配置文件路径
// （命令行参数或 IPC 传入）。
//
// ⭐ 安全审计 S16：
//   - 只接受 .hy2 后缀，避免把任意本地文件交给 JSON 解析器；
//   - **拒绝 UNC / 网络路径**：os.ReadFile(`\\attacker\share\x.hy2`)
//     会让 Windows 主动向攻击者的 SMB 主机进行身份认证，
//     从而泄露当前用户的 NetNTLMv2 哈希（可用于中继或离线爆破）。
func isSafeHyFilePath(p string) bool {
	if p == "" {
		return false
	}
	if !strings.HasSuffix(strings.ToLower(p), config.HyFileExt) {
		return false
	}
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") {
		return false
	}
	if strings.HasPrefix(p, `\\.\`) || strings.HasPrefix(p, `\\?\`) {
		return false
	}
	abs, err := filepath.Abs(p)
	if err != nil || !filepath.IsAbs(abs) {
		return false
	}
	return true
}

// processHyFiles 处理 .hy2 文件。
// 语义保持「只处理第一个可用文件」—— UI 一次只保存一个待导入配置。
func (a *App) processHyFiles(paths []string) {
	for _, p := range paths {
		if !isSafeHyFilePath(p) {
			log.Printf("⚠️ [客户端] 拒绝不安全的配置文件路径: %q", p)
			continue
		}

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

	// ⭐ 安全审计 S15：字段写入必须持 healthMu
	a.healthMu.Lock()
	a.healthTicker = ticker
	a.healthStop = stop
	a.healthMu.Unlock()

	go func(t *time.Ticker, s chan struct{}) {
		// ⭐ 安全审计 S15：全局协程，panic 会带走整个客户端
		defer func() {
			if r := recover(); r != nil {
				log.Printf("💥 [健康推送] panic 已被捕获: %v\n%s", r, debug.Stack())
			}
		}()
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
	// ⭐ 安全审计 S37：记录本轮的代际号。
	//    ConnectClient 自增该值即代表「本轮作废」。
	epoch := a.reconnectEpoch
	a.reconnectMu.Unlock()

	// ⭐ 安全审计 S37：读取 lastConfig 前先加锁快照，
	//    不能在循环里反复读共享字段。
	a.clientMu.Lock()
	cfg := a.lastConfig
	a.clientMu.Unlock()

	go func(stop <-chan struct{}, ep uint64, cfg config.ClientConfig) {
		defer func() {
			a.reconnectMu.Lock()
			a.reconnecting = false
			// 只清自己这一轮的 stop channel（避免覆盖新的）
			if a.reconnectStop == stopCh {
				a.reconnectStop = nil
			}
			a.reconnectMu.Unlock()
		}()

		// ⭐ 安全审计 S37：统一的「本轮是否已作废」判定
		stale := func() bool {
			a.reconnectMu.Lock()
			defer a.reconnectMu.Unlock()
			return a.reconnectEpoch != ep || a.reconnectExhausted
		}

		for attempt := 1; attempt <= reconnectAttempts; attempt++ {
			// ⭐ 每轮开始检查是否已被取消
			if stale() {
				log.Printf("🛑 [客户端] 重连已被取消或已过期（用户断开/重新连接）")
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
			if stale() {
				log.Printf("🛑 [客户端] 重连已被取消或已过期")
				return
			}

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
			// ⭐ 1b-2A：重连时同样带上本机「禁用 P2P」开关（取反）
			cli.SetP2P(!cfg.P2PDisabled)
			// ⭐ P2SP 阶段 1b：重连后的直连状态同样推给前端
			cli.SetP2PStatusHandler(func(st quic.P2PStatus) {
				if a.ctx == nil {
					return
				}
				runtime.EventsEmit(a.ctx, "p2p:status", st)
			})

			ip, err := cli.Connect()
			if err != nil {
				log.Printf("⚠️ [客户端] 第 %d 次重连失败: %v", attempt, err)
				// ⭐ client.go 内部已有 defer 清理，这里兜底再关一次
				cli.Close()
				continue
			}

			// ⭐ 连接成功前再检查一次（避免用户恰好在这一刻点了断开，
			//    或者 ConnectClient 已经建立了新的连接）
			if stale() {
				log.Printf("🛑 [客户端] 重连成功但本轮已作废，丢弃该连接")
				cli.Close()
				return
			}

			// ⭐ 安全审计 S37：最后一道防线 —— 只有代际仍然有效时
			//    才允许覆盖 a.quicClient。原实现在这里无条件覆盖，
			//    造成「重连协程关掉用户刚建立的新连接」。
			a.reconnectMu.Lock()
			stillValid := a.reconnectEpoch == ep && !a.reconnectExhausted
			a.reconnectMu.Unlock()
			if !stillValid {
				log.Printf("🛑 [客户端] 重连完成但代际已过期，丢弃该连接")
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
	}(stopCh, epoch, cfg)
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

// stopHealthPusher 停止健康推送协程（幂等）。
//
// ⭐ 安全审计 S15：原实现无任何互斥保护，
// 两个 goroutine 可以同时通过 nil 检查、然后都执行 close
// → "panic: close of closed channel"，客户端直接崩溃。
func (a *App) stopHealthPusher() {
	a.healthMu.Lock()
	defer a.healthMu.Unlock()

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
	// ⭐ 安全审计 S35：把「正在连接中」的客户端也取出来一起关闭。
	//    原来只关 quicClient，而 Connect() 期间 quicClient 还是 nil，
	//    于是用户点「断开」对卡住的连接毫无作用。
	pending := a.pendingClient
	a.pendingClient = nil
	a.clientMu.Unlock()

	if cli != nil {
		cli.Close()
	}
	if pending != nil {
		log.Println("🧹 [客户端] 已取消正在进行的连接")
		pending.Close()
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

// ---------- P2SP 阶段 1：隧道内信令（供前端 / 调试使用） ----------

// SignalSelf 返回本机的 P2P 状态与 NAT 探测结果。
// 用于人工验证「P2P 开关 / NAT 探测 / 信令是否就绪」。
func (a *App) SignalSelf() map[string]interface{} {
	a.clientMu.Lock()
	cli := a.quicClient
	a.clientMu.Unlock()

	if cli == nil {
		return map[string]interface{}{"connected": false}
	}
	res, ready := cli.NATResult()
	return map[string]interface{}{
		"connected":          true,
		"p2pServerEnabled":   cli.P2PServerEnabled(),
		"p2pLocalEnabled":    cli.P2PLocalEnabled(),
		"p2pEffective":       cli.P2PEffective(),
		"natReady":           ready,
		"natType":            string(res.Type),
		"publicAddr":         res.PublicAddr,
		"observedPorts":      res.ObservedPorts,
		"respondedServers":   res.RespondedServers,
		"mappingIndependent": res.MappingIndependent,
		// ⭐ 本机信令流是否已建好（本地视角）。
		// 注意与 SignalQuery 返回的 SignalReady 区分：
		// 那个说的是「**对端**信令就绪、服务端推得过去」。
		"signalStreamReady": cli.SignalStreamReady(),
	}
}

// SignalQuery 通过**隧道内**信令查询对端 VIP 的公网地址与 NAT 类型。
//
// 阶段 1a 只做地址交换；阶段 1b 的打洞会用返回的 metadata。
func (a *App) SignalQuery(peerVIP string) (quic.SignalPeer, error) {
	a.clientMu.Lock()
	cli := a.quicClient
	a.clientMu.Unlock()

	if cli == nil {
		return quic.SignalPeer{}, fmt.Errorf("尚未连接")
	}
	return cli.SignalQuery(peerVIP)
}

// PunchTo 发起一次到指定对端 VIP 的**直连尝试**（P2SP 阶段 1b-1）。
//
// 异步：立即返回 attemptId（用于日志关联），过程中的状态与结果通过
// "p2p:status" 事件推送（见 P2PStatus）。业务流量在 1b-1 仍走中继。
func (a *App) PunchTo(peerVIP string) (string, error) {
	a.clientMu.Lock()
	cli := a.quicClient
	a.clientMu.Unlock()

	if cli == nil {
		return "", fmt.Errorf("尚未连接")
	}
	return cli.PunchTo(peerVIP)
}

// PunchSessionState 查询某次直连尝试的当前状态（诊断/UI 用）
func (a *App) PunchSessionState(attemptID string) (string, bool) {
	a.clientMu.Lock()
	cli := a.quicClient
	a.clientMu.Unlock()

	if cli == nil {
		return "", false
	}
	return cli.PunchSessionState(attemptID)
}

// P2PReasonText 原因码 → 中文文案（前端也可以自己映射；这里作为兜底与一致性来源）
func (a *App) P2PReasonText(code string) string {
	return quic.P2PReasonText(code)
}

// P2PPaths 当前直连路径快照（1b-2A：面板「直连对端」列表用）。
//
// 每个对端给出：VIP / 状态 / 角色 / 直连 RTT / 已承载的上下行字节 / 建立时刻。
func (a *App) P2PPaths() []quic.PathInfo {
	a.clientMu.Lock()
	cli := a.quicClient
	a.clientMu.Unlock()
	if cli == nil {
		return nil
	}
	return cli.P2PPaths()
}

// P2PTrafficNote 直连流量的计量口径（Q7 定稿：配额 = **中继流量配额**）。
//
// ⚠️ 放在后端返回是为了「口径只有一处」：面板与文档都引用它，
// 避免各处自己写一句不一致的说明（服务端看不到直连字节数，所以这里只能是说明，不能是数字）。
func (a *App) P2PTrafficNote() string {
	return "直连流量不经服务端，不计入流量配额（配额统计的是中继流量）"
}

// SetP2PLocal 本机 P2P 开关（客户端「高级选项 → 禁用 P2P」的运行时入口）。
//
// 语义（与验收要求一致）：
//   - false（禁用）：**立即**清空路由表并关闭已有直连路径 → 流量回中继；
//   - true （启用）：不主动触发任何打洞，等流量驱动。
//
// ⚠️ 与「连接时的配置」是同一份语义：`enabled` 是 **P2P 启用**（不是「禁用」），
// 前端那个开关是「禁用 P2P」，所以要传 `!disabled`。
func (a *App) SetP2PLocal(enabled bool) error {
	a.clientMu.Lock()
	cli := a.quicClient
	a.clientMu.Unlock()
	if cli == nil {
		// 未连接：只记录到「下一次连接」由配置决定（这里不报错，避免切换开关时弹错误）
		return nil
	}
	cli.ApplyP2PLocal(enabled)
	return nil
}
