package quic

// ⚠️ 本文件是临时调试占位（沙箱不允许删除工作区文件），可安全删除：
//
//	Remove-Item backend/quic/zz_scratch_debug_test.go
//
// 曾用于查明三处问题（结论均已成为正式用例/注释）：
//  1. `removeRoute` 的守卫是 `(*old)[dst] == p` ⇒ A 降级摘不掉 B 的注册。
//     真因是「一个槽位两条路径」，见 path.go §试用中路径的登记。
//  2. `punchSession.succeed()`：无路径管理器时发 direct（原行为），有路径管理器时不发。
//  3. `enterStandby`/`exitStandby` 的陈旧 state 覆写（§4.2.1）：
//     复现用例见 standby_race_test.go；其中 exit 那条的第一版前置设错
//     （陈旧基准 100ms、刷新后 7ms ⇒ 退出判据自己否决 ⇒ 假通过），已修正。
