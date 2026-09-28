package quic

// 📌📌 **本文件已于 2026-09-28（A3a）整体删除 —— 此处只留「删除留档桩」，无任何代码。**
//
// 删除内容（预打洞**发起**侧）：`prePunchSchedulerLoop` / `prePunchOnce` / `prePunchOne` /
//
//	`runPrePunchBatch` / `prePunchCandidates` / `prePunchWorklist` / `classifyPrePunchTier` /
//	`prePunchQuota*` / `prePunchReady` / `prePunchDrawn`・`prePunchLastTry` 护栏 / `prePunchSuccessHook` …
//	（原 25 个函数 + `prePunchConfig`/`prePunchCand` 等类型与常量）
//
// 为什么删除：A2 收口后，预打洞走 **A3a 永久删除**（`P2SP-阶段1b-4-A2-…进度.md` §0.2 拍板
//
//	「从追加项删除『预打洞恢复』」）—— **不是** B1 §8 那份已作废的"恢复清单"。
//	B1 早已让 `start()` **不启动**调度器 ⇒ 发起侧**已是死代码** ⇒ 本次删除**不改变运行时行为**。
//
// 🔎 原代码怎么找回（**项目无 VCS，务必按此找**）：
//
//	1. `A2-干净点快照-2026-09-28\quic\prepunch.go`（**推荐**；sha256 前缀 580D9E89E6930AD2，
//	   共 27996 字节 / 692 LF / 30 个顶层声明）—— 已记入 `.a3a-recover\manifest.json`
//	2. `B1B3-干净点快照-2026-09-27\quic\prepunch.go`（与 1 **逐字相同**：A2 未触碰预打洞）
//	3. DSH 会话记录（`%USERPROFILE%\.dsh\sessions\**\session.v3.jsonl.zstd`，多帧 zstd）里的 `write` 原文
//	   ⚠️ 会话记录**不保证最新**（实测过截断）⇒ 优先用快照，且用 sha256 自证
//
// 保留了什么（**responder 兼容**，删不得）：入站邀请处理与 `P2PTriggerRemote` 会话、
//
//	`peerPunchAddr(s)`/`WindowMs`/`DirectFingerprint`/`Metadata` 解析、以及 **B1 灰度期启发式**
//	（它补偿旧对端"探路收尾"的丢包）—— 后者在 **A3b** 才删。
//
// ⚠️ 本桩**零 import、零声明**（必须是合法 `.go`：`package quic` + 纯注释）；
//
//	保留原文件名 `prepunch.go` 是因为沙箱不允许在 `backend\quic\` 下改名/删除文件。
//	**不采用** `//go:build ignore`：那会让 `go vet` 跳过它，而纯注释桩仍受 gofmt/vet 覆盖。
//
// 相关改动（同批 = {②,⑥} 原子核）：
//
//	· `punch.go`：删 11 个字段 + 3 处初始化 + `start()` 的启动块/文档 + `succeed()` 的
//	  `P2PTriggerPrePunch` 分支（含 `onPrePunchSuccess` 钩子）+ 常量 `P2PTriggerPrePunch`；
//	· `punch_test.go`：③ 已完成（夹具签名收 3 参、删两入口与注入块）。
//
// 已收割的通用教训（**勿重复收割 —— 它们已在《工程纪律》里**）：
//
//	· 测试钩子**四约束**（只留钩子不留重复计数器 / 必须在 `closeAll()` 之前调用 /
//	  生产恒为 `nil` 且无生产代码设置它 / ⭐ **不得在锁内回调**）        → 《工程纪律》**§3 第 11 条**
//	· 断言不得依赖日志文本（要断言可查询的状态/计数器）                  → **§3 第 12 条**
//	· 配置必须在「读它的 goroutine 启动之前」注入（否则数据竞争）        → **§4 第 7 条**
//	· 锁粒度/锁序：取快照时持锁、过滤与排序在锁外（不构造跨管理器锁边）   → **§4 第 8 条**
//	· 「删掉」优于「留着以防万一」（假保护比没有保护更危险）              → **§4 第 9 条**
//	· 改注释要用「读者视角」：代码消失了 ≠ 它支撑的判据消失了            → **§4 第 10 条**
//
// 权威文档：`P2SP-阶段1b-4-A3a-实施计划-删发起保responder.md`
//
//	（§2 删除清单 / §3 用例映射 29 删·1 保留·1 改写 / §7.3 执行与回滚 / §9 教训收割 / §10 交付说明清单）
//
// ⚠️ **生命周期**：本桩**至少保留到 A3b 完成**；A3b 时与 B1 灰度期启发式一起决定是否删除。
//
//	**A3b 之前不得删除本桩**（它是被删内容的仓库内引用点之一）。
