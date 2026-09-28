package quic

// vpn-tool/backend/quic/signal_ctx_test.go
//
// ⭐ 第 2 步-B（review 追问 3）：信令往返的**可取消**语义测试。
//
// 为什么单独一个文件：`overrideSignalExchangeWait` 是**整个包唯一**允许写
// `signalExchangeWait` 的地方，集中在这里便于审查「谁能改这个变量」。
// 用例本身：`PeersQuery` 的 ctx 契约见 `d1a_peers_test.go`。
// （⚠️ A3a 2026-09-28：该用例原在 `prepunch_test.go` —— 该文件已**桩化**（只剩留档说明），
// 原代码见 `A2-干净点快照-2026-09-28\quic\prepunch_test.go:257-296`；
// 调度器相关用例已随预打洞发起侧一并删除。）

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// overrideSignalExchangeWait 测试专用：把「等信令应答」的上限临时改成 d。
//
// 为什么需要：要把「随 ctx 取消立即返回」与「白等到超时」在时间尺度上拉开
// （否则旧行为也在用例超时内返回，用例无牙）。
//
// ⚠️ 纪律（review 追问 2）：
//   - **只能**在用例里调用；还原走 `t.Cleanup`，且**还原时会校验**「确实回到了
//     调用前的值」（否则污染会静默传给后续用例 —— 专门测试信号超时的
//     `TestSignalQueryTimeoutDropsStream` 会开始说谎）；
//   - 本包测试**不使用** `t.Parallel()`（该变量是包级共享状态，并行会互相干扰）；
//   - 生产代码里没有任何地方写它（初值 = `signalTimeout`，且**没有**在别处
//     硬编码这个超时值 —— 超时分支与错误文案都读同一个变量）。
func overrideSignalExchangeWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := signalExchangeWait
	signalExchangeWait = d
	t.Cleanup(func() {
		got := signalExchangeWait
		signalExchangeWait = old
		if got != d {
			t.Errorf("`signalExchangeWait` 被测试之外的代码改动：期望 %v，实际 %v"+
				"（包级可变状态，必须在用例结束时回到调用前的值）", d, got)
		}
	})
}

// TestSignalExchangeWaitIsTestOnly ⭐ review 追问 3②：**源码级契约守卫**。
//
//	`signalExchangeWait` 是「只测试用的可覆盖点」—— 生产代码**不得**写它。
//	本仓**没有** CI grep 步骤，所以把这条禁令写成用例：扫描本包**非测试**源文件，
//	凡出现「给 `signalExchangeWait` 赋值」就报红。
//
// 为什么值得一条用例：赋值（而不是读取）在生产里是**静默的行为变更**——
// 线上信令超时会瞬时变化，而 `signalTimeout` 这个真相源失效、没人会立刻发现。
//
// ⚠️ 判定方式刻意**保守**（只看以 `signalExchangeWait` 开头的简单赋值/自增等语句）：
//
//	宁可漏报也不误报，否则将来正常的重构（比如把它挪进结构体）会被这条用例拦住。
func TestSignalExchangeWaitIsTestOnly(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("读取包目录失败: %v", err)
	}
	// 判定（**不用复杂正则**，避免自己写错）：见 scanSignalExchangeWaitWrites 的注释。
	violations := scanSignalExchangeWaitWrites(t, entries)
	// 自检：扫描器对「已知的违规写法」必须报红（否则是扫描器自己的 bug，不是代码干净）
	selfCheck := lineWritesSignalExchangeWait("func init() { signalExchangeWait = 9 * time.Second } // x")
	selfCheckOK := lineWritesSignalExchangeWait("var signalExchangeWait = signalTimeout")
	if !selfCheck || selfCheckOK {
		t.Fatalf("扫描器自检失败：违规样本应判 true（实际 %v），合法样本应判 false（实际 %v）"+
			" —— 这是扫描器自身的 bug，不能拿它当「代码干净」的证据", selfCheck, selfCheckOK)
	}
	t.Logf("扫描结果：%d 处违规", len(violations))
	if len(violations) > 0 {
		t.Errorf("生产代码给 `signalExchangeWait` 赋值了（它**只**允许由测试辅助 "+
			"`overrideSignalExchangeWait` 覆盖，见 signal.go 注释）：\n  %s",
			strings.Join(violations, "\n  "))
	}
	// 声明行必须仍然存在（别把变量删了却留下这条用例自鸣得意）
	if !strings.Contains(readFileString(t, "signal.go"), "var signalExchangeWait = signalTimeout") {
		t.Fatal("signal.go 里应有 `var signalExchangeWait = signalTimeout`（初值 = signalTimeout）")
	}
}

// readFileString 读一个包内源文件（测试辅助）
func readFileString(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", name, err)
	}
	return string(data)
}

// lineWritesSignalExchangeWait 判断**单行**是否「违规写 `signalExchangeWait`」。
//
// 抽成**纯函数**（不碰 IO、不碰 `*testing.T`）：既给扫描器用，也能被用例直接拿
// 「已知违规的样本行」自检 —— 扫描器自己写错时，自检会红，而不是静默放行。
func lineWritesSignalExchangeWait(line string) bool {
	const target = "signalExchangeWait"
	code := stripLineComment(line)
	pos := strings.Index(code, target)
	if pos < 0 {
		return false
	}
	// 前后必须是独立标识符边界（避免 `signalExchangeWaitFoo` / `x.signalExchangeWait`）
	if pos > 0 && (isIdentByte(code[pos-1]) || code[pos-1] == '.') {
		return false
	}
	rest := code[pos+len(target):]
	// ⚠️ **必须先去掉前导空白**：`rest` 形如 `" = signalTimeout"`（标识符后面有个空格），
	//    直接 `HasPrefix(rest, "=")` 永远不成立 —— 这正是我第三次假绿的根因
	//    （连带「连 = 都判不出来」，于是每一行都被当成「只是读」而放行）。
	trimmed := strings.TrimLeft(rest, " \t")
	if trimmed == "" {
		return false // 只是读（如 `time.NewTimer(signalExchangeWait)`）
	}
	for _, op := range []string{"=", "+=", "-=", "*=", "/=", "%="} {
		if strings.HasPrefix(trimmed, op) {
			rhs := strings.TrimSpace(strings.TrimPrefix(trimmed, op))
			return rhs != "signalTimeout" // 右侧就是 signalTimeout ⇒ 合法
		}
	}
	return false
}

// scanSignalExchangeWaitWrites 扫描包内**非测试**源文件，返回所有「违规写 `signalExchangeWait`」的位置。
//
// ⚠️ 踩过的坑（**三次假绿**，全部留档）：
//
//	第一版用正则 `^\s*(var\s+)?signalExchangeWait\s*([+\-*/]?=)` —— 要求标识符在**行首**，
//	  于是 `func init() { signalExchangeWait = 9*time.Second }`（标识符在行中）**漏过**；
//	第二版加了「整行以空白/分号结尾」的判定 ⇒ 行尾带注释的写法漏过；
//	第三版用 `TrimPrefix(TrimSpace(rest), "=")` 但 `rest` 是 `" = signalTimeout"`（**以空格开头**，
//	  故 `TrimPrefix` 什么都没去掉）⇒ 合法/违规的判据失效。
//	⇒ 现在把「单行判定」抽成纯函数 `lineWritesSignalExchangeWait`，并在用例里**自检样本行**。
func scanSignalExchangeWaitWrites(t *testing.T, entries []os.DirEntry) []string {
	t.Helper()
	var violations []string
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue // 只看**非测试**源文件
		}
		checked++
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", name, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if lineWritesSignalExchangeWait(line) {
				violations = append(violations,
					fmt.Sprintf("%s:%d %q", name, i+1, strings.TrimSpace(line)))
			}
		}
	}
	if checked == 0 {
		t.Fatal("没有扫到任何非测试源文件 —— 用例失效（工作目录不对？）")
	}
	return violations
}

// stripLineComment 去掉一行里的 `//` 注释（**只看行注释**；本包没有把 `//` 放进字符串字面量的写法）
func stripLineComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

// indexOutsideWord 已不再需要（判定收敛到 lineWritesSignalExchangeWait）。
func isIdentByte(b byte) bool {
	return b == '_' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// TestSignalExchangeWaitDefaultsToTimeout 初值契约（review 追问 2③）：
//
//	`signalExchangeWait` 必须**由 `signalTimeout` 初始化**（而不是另写一个 5s）。
//	若有人把它硬编码成别的值，「改 `signalTimeout` 就生效」这条直觉会失效
//	—— 而这里正是「超时分支、错误文案、超时用例」三处的共同真相源。
//
// ⚠️ 有牙：把 signal.go 里的初值改成 `10 * time.Second` ⇒ 红。
func TestSignalExchangeWaitDefaultsToTimeout(t *testing.T) {
	if signalExchangeWait != signalTimeout {
		t.Fatalf("signalExchangeWait 初值必须 = signalTimeout(%v)，实际 %v —— "+
			"硬编码会让「改 signalTimeout」不再生效", signalTimeout, signalExchangeWait)
	}
	if signalTimeout != 5*time.Second {
		t.Fatalf("signalTimeout 应为 5s（协议侧既有定稿值），实际 %v", signalTimeout)
	}
}

// TestOverrideSignalExchangeWaitRestores 自证「覆盖生效」（追问 2①②）。
//
// ⚠️ 还原本身由 `t.Cleanup` 断言（见 helper）；这里**只**断言覆盖已生效。
//
//	（不能在同一个用例里再注册一个 cleanup 去断言还原结果：cleanup 是 LIFO
//	 ⇒ 后注册的先跑，会在**还原之前**执行 —— 第一版就是这么写的，实测报红。）
func TestOverrideSignalExchangeWaitRestores(t *testing.T) {
	overrideSignalExchangeWait(t, 60*time.Second)
	if signalExchangeWait != 60*time.Second {
		t.Fatalf("覆盖应立即生效，实际 %v", signalExchangeWait)
	}
}

// TestSignalExchangeWaitRestoredAfterOverride **污染守卫**（追问 2①②）：
//
//	本用例在 `TestOverrideSignalExchangeWaitRestores` **之后**运行（go test 默认
//	串行、按源码顺序），因此它读到的值就是「上一个用例收尾之后」的值。
//	若 helper 的还原失效（或在别处多写了一次），这里立刻红 —— 否则污染会**静默**
//	传给后面专门测信令超时的用例，让它们开始说谎。
//
//	⚠️ 依赖「同文件内用例按源码顺序执行」：Go 官方不承诺跨文件顺序，同文件内是顺序的。
func TestSignalExchangeWaitRestoredAfterOverride(t *testing.T) {
	if signalExchangeWait != signalTimeout {
		t.Fatalf("上一个用例的覆盖必须已还原为 %v，实际 %v —— 包级状态被污染了",
			signalTimeout, signalExchangeWait)
	}
}
