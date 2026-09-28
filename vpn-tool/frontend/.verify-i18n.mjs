// vpn-tool/frontend/.verify-i18n.mjs
//
// ⭐ 1b-4 第一步（方案 A）复验脚本：四语言键集必须一致 + 新增键必须都在。
//
//   node .verify-i18n.mjs
//
// 覆盖：
//   - messages 里每个 locale 的键集合逐一比对（多键/少键都报错并列出差异）；
//   - 1b-4 新增的两个键：`p2pStateTrial`（补充 A）与 `logP2PQualityPoor`（方案 A）；
//   - 顺带复验 App.vue 的方案 A 分支仍在（quality-poor → info 不弹、其余 → warn + toast）。
import { readFileSync } from 'node:fs'
import { messages, SUPPORTED_LOCALES } from './src/i18n.js'

let failed = false
const fail = (msg) => { failed = true; console.error('  [FAIL] ' + msg) }
const ok = (msg) => console.log('  [ok] ' + msg)

const locales = SUPPORTED_LOCALES.map((l) => l.code)
console.log('=== i18n 键集一致性 ===')
const keysOf = (code) => new Set(Object.keys(messages[code] || {}))
const base = keysOf(locales[0])
console.log(`  基准 ${locales[0]}: ${base.size} 键`)
for (const code of locales) {
  const keys = keysOf(code)
  const missing = [...base].filter((k) => !keys.has(k))
  const extra = [...keys].filter((k) => !base.has(k))
  if (missing.length || extra.length) {
    fail(`${code}: 键集不一致（缺 ${missing.length} / 多 ${extra.length}）` +
      (missing.length ? ` 缺=${missing.join(',')}` : '') +
      (extra.length ? ` 多=${extra.join(',')}` : ''))
  } else {
    ok(`${code}: ${keys.size} 键，与基准一致`)
  }
}

console.log('=== 1b-4 新增键 ===')
for (const key of ['p2pStateTrial', 'logP2PQualityPoor']) {
  for (const code of locales) {
    const v = messages[code]?.[key]
    if (typeof v !== 'string' || v.trim() === '') fail(`${code}.${key} 缺失或为空`)
  }
  ok(`${key}: 四语言齐备 → ${locales.map((c) => JSON.stringify(messages[c][key])).join(' / ')}`)
}

console.log('=== App.vue 方案 A 分支 ===')
const app = readFileSync(new URL('./src/App.vue', import.meta.url), 'utf8')
const checks = [
  [/st\.reasonCode === 'quality-poor'/, 'failed 分支里按 reasonCode 特判 quality-poor'],
  [/logP2PQualityPoor'.*'info'\)/, 'quality-poor 走 info 日志（不弹提示）'],
  [/st\.state === 'trial'/, 'trial 状态分支仍在（补充 A）'],
]
for (const [re, what] of checks) {
  if (re.test(app)) ok(what)
  else fail(what + ' —— 正则未命中：' + re)
}
// 其余失败原因必须保持 warn + toast（方案 A 只动了 quality-poor 一条）
const failedStart = app.indexOf("st.state === 'failed'")
const failedEnd = app.indexOf("st.state === 'trial'") > failedStart
  ? app.indexOf('} else {', failedStart) + 200 // failed 分支之后紧跟的 else（过程状态）
  : failedStart + 1200
const failedBlock = app.slice(failedStart, failedEnd)
if (/logP2PFailed/.test(failedBlock) && /showToastMessage/.test(failedBlock)) {
  ok('其余失败原因仍走 warn 日志 + 错误提示（方案 A 未顺手放宽）')
} else {
  fail('其余失败原因的 warn/toast 分支不见了')
}

if (failed) { console.error('\n[FAIL] i18n / 方案 A 复验未通过'); process.exit(1) }
console.log('\n[OK] i18n 键集一致 + 方案 A 就位')
