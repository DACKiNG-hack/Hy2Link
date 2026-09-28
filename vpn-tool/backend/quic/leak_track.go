package quic

// vpn-tool/backend/quic/leak_track.go
//
// 第 3 步-D：**路径生命周期埋点**（用于测试定位「未关闭的路径」）。
//
// ⚠️ 为什么放在**产品文件**而不是 `_test.go`：`path.go` 会调用它，
// 而**产品代码不能依赖测试文件**（`go build ./...` 会直接失败：
// `undefined: notePathCreated`）—— 这是我踩过的一次构建期错误。
//
// 设计（零成本 + 生产无副作用）：
//   - 未启用时（生产）：`enabled=false` ⇒ 两个函数都**立即返回**，
//     不做栈回溯（`runtime.Callers` 很贵）、不分配、不取锁；
//   - 测试由 `TestMain` 调 `enablePathLeakTracking()` 打开，
//     结束时读 `pathLeakReport()` 即可点名「哪个用例漏关路径」。
//
// 判据（定位思路）：路径的「创建点」与「关闭点」是生命周期的两个端点；
// 用计数器 + 创建栈键就能在整包结束时直接问「有几条路径没关、分别是哪建的」，
// 把范围从「全包 ~60 个用例」缩到「确切的几处」。

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	pathLeakMu      sync.Mutex
	pathLeakEnabled bool
	livePathCounts  = map[string]int{} // key = 创建点（测试函数 + 文件:行）
)

// enablePathLeakTracking 打开埋点（仅供测试的 TestMain 调用）。
func enablePathLeakTracking() {
	pathLeakMu.Lock()
	pathLeakEnabled = true
	pathLeakMu.Unlock()
}

// notePathCreated 记录一次路径创建，返回它的「创建点键」（供关闭时销账）。
//
// 未启用时返回空串 ⇒ `directPath.leakKey` 为空 ⇒ `notePathClosed` 也不会被调用。
func notePathCreated() string {
	pathLeakMu.Lock()
	on := pathLeakEnabled
	pathLeakMu.Unlock()
	if !on {
		return ""
	}
	key := pathLeakCallerKey()
	pathLeakMu.Lock()
	livePathCounts[key]++
	pathLeakMu.Unlock()
	return key
}

// notePathClosed 销账（与 notePathCreated 配对）。
func notePathClosed(key string) {
	if key == "" {
		return
	}
	pathLeakMu.Lock()
	livePathCounts[key]--
	pathLeakMu.Unlock()
}

// pathLeakReport 返回「未被关闭的路径」摘要（按创建点归类）；空串 = 无泄漏。
func pathLeakReport() string {
	pathLeakMu.Lock()
	defer pathLeakMu.Unlock()
	var leaked []string
	for k, v := range livePathCounts {
		if v > 0 {
			leaked = append(leaked, fmt.Sprintf("%s ×%d", k, v))
		}
	}
	if len(leaked) == 0 {
		return ""
	}
	return fmt.Sprintf("未关闭路径 %d 类：%v", len(leaked), leaked)
}

// pathLeakCallerKey 取创建点所属的**外层测试函数**（`TestXxx` / `BenchmarkXxx`）。
//
// ⚠️ 不能用「第一个匹配某个助手的帧」：那会落在**助手函数自己**的行号上
// （实测全部报成同一个行号，定位失败一次）。必须只认 `Test`/`Benchmark` 前缀，
// 才能指回真正的调用用例。
func pathLeakCallerKey() string {
	var pcs [32]uintptr
	n := runtime.Callers(2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	for {
		fr, more := frames.Next()
		base := fr.Function
		if i := strings.LastIndex(base, "."); i >= 0 {
			base = base[i+1:]
		}
		if strings.HasPrefix(base, "Test") || strings.HasPrefix(base, "Benchmark") {
			return fmt.Sprintf("%s (%s:%d)", base, filepath.Base(fr.File), fr.Line)
		}
		if !more {
			break
		}
	}
	return "unknown(caller)"
}
