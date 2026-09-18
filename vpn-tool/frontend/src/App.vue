<template>
  <div id="app">
    <header class="topbar">
      <div class="brand">
        <img class="brand-logo" src="/logo.png" alt="Hy2Link" />
        <div class="brand-text">
          <div class="brand-title">
            Hy2Link
            <span class="brand-ver">v{{ version }}</span>
          </div>
          <div class="brand-sub">{{ t('brandSub') }}</div>
        </div>
      </div>
      <div class="topbar-right">
        <span class="run-chip" :class="globalStatusClass">
          <span class="run-dot"></span>
          {{ globalStatusText }}
        </span>

        <!-- ⭐ 语言切换 -->
        <div class="lang-switch">
          <button class="lang-btn" @click="langOpen = !langOpen" :title="t('langTitle')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/>
              <line x1="2" y1="12" x2="22" y2="12"/>
              <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>
            </svg>
            <span>{{ currentLocaleShort }}</span>
          </button>
          <div v-if="langOpen" class="lang-menu">
            <button v-for="l in languages" :key="l.code"
                    class="lang-option"
                    :class="{ active: currentLocale === l.code }"
                    @click="setLocale(l.code)">
              <span class="lang-check">
                <svg v-if="currentLocale === l.code" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
              </span>
              <span>{{ l.label }}</span>
            </button>
          </div>
        </div>

        <button class="btn btn-ghost btn-sm" @click="handleImport" :title="t('import')">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;">
            <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          {{ t('import') }}
        </button>
        <button class="btn btn-ghost btn-sm" @click="showAbout = true">{{ t('about') }}</button>
      </div>
    </header>

    <div class="app-body">
      <aside class="sidebar">
        <div class="sidebar-head">
          <span class="sidebar-label">{{ t('sidebarLabel') }}</span>
          <button class="btn-icon" @click="createNewConnection" :disabled="isLocked" :title="t('sidebarNew')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 5v14M5 12h14"/>
            </svg>
          </button>
        </div>

        <div class="conn-list">
          <div
              v-for="conn in connections"
              :key="conn.id"
              class="conn-item"
              :class="{ active: activeConnectionId === conn.id, disabled: isConnectionDisabled(conn.id) || isLocked }"
              @click="selectConnection(conn.id)"
          >
            <span class="conn-dot" :class="conn.status"></span>
            <div class="conn-info">
              <div class="conn-name">{{ conn.name || t('sidebarUntitled') }}</div>
              <div class="conn-addr">{{ conn.serverIP || '—' }}<span class="dim">:</span>{{ conn.port }}</div>
            </div>
            <div class="conn-tail">
              <button
                  v-if="conn.status !== 'connected' && conn.status !== 'connecting'"
                  class="conn-x"
                  @click.stop="deleteFromCard(conn)"
                  :title="t('sidebarDelete')"
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <line x1="18" y1="6" x2="6" y2="18"/>
                  <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
              </button>
              <span v-else class="conn-time mono">{{ connShortTime(conn) }}</span>
            </div>
          </div>

          <div v-if="!connections.length" class="empty-side">
            <p>{{ t('sidebarEmpty') }}</p>
            <button class="btn btn-primary btn-sm" @click="createNewConnection">{{ t('sidebarNew') }}</button>
          </div>
        </div>
      </aside>

      <main class="main">
        <div v-if="!activeConnection" class="empty-main">
          <div class="empty-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <rect x="2" y="7" width="20" height="14" rx="2"/>
              <path d="M16 21V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v16"/>
            </svg>
          </div>
          <h3>{{ t('sidebarEmpty') }}</h3>
          <p>{{ t('sidebarNew') }}</p>
        </div>

        <template v-else>
          <div class="card hero-card" :class="`is-${activeConnection.status}`">
            <div class="card-body">
              <div class="hero-top">
                <div class="hero-status">
                  <span class="conn-dot lg" :class="activeConnection.status"></span>
                  <div class="hero-text">
                    <div class="hero-state">{{ statusText(activeConnection.status) }}</div>
                    <div class="hero-host">
                      <span class="hero-host-ip">{{ activeConnection.serverIP || t('heroNoServer') }}</span>
                      <span class="hero-host-port" v-if="activeConnection.serverIP">:{{ activeConnection.port }}</span>
                      <button
                          v-if="activeConnection.serverIP"
                          class="copy-mini"
                          @click="copyServerAddr"
                          :title="t('heroCopyAddr')"
                      >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                          <rect x="9" y="9" width="13" height="13" rx="2"/>
                          <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
                        </svg>
                      </button>
                    </div>
                  </div>
                </div>

                <button
                    class="btn"
                    :class="connectBtnClass"
                    @click="toggleConnection"
                    :disabled="isConnecting"
                >
                  <svg v-if="activeConnection.status === 'connecting'" class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4">
                    <path d="M21 12a9 9 0 11-6.219-8.56"/>
                  </svg>
                  <span>{{ primaryBtnText }}</span>
                </button>
              </div>

              <!-- ⭐ 4 列：虚拟 IP / 时长 / 延迟 / 健康 -->
              <div class="hero-stats">
                <div class="hero-cell">
                  <div class="stat-label">{{ t('heroVirtualIp') }}</div>
                  <div class="stat-value mono">{{ virtualIP || '—' }}</div>
                </div>
                <div class="hero-cell">
                  <div class="stat-label">{{ t('heroDuration') }}</div>
                  <div class="stat-value mono">{{ elapsedText }}</div>
                </div>
                <div class="hero-cell">
                  <div class="stat-label">{{ t('heroLatency') }}</div>
                  <div class="stat-value mono" :class="latencyClass">{{ latencyText }}</div>
                </div>
                <div class="hero-cell">
                  <div class="stat-label">{{ t('heroHealth') }}</div>
                  <div class="stat-value" :class="healthValueClass">{{ healthText }}</div>
                </div>
              </div>

              <transition name="fade">
                <div v-if="showHealthDetail" class="health-strip" :class="healthState">
                  {{ healthStripText }}
                </div>
              </transition>
            </div>
          </div>

          <div class="card">
            <div class="card-head">
              <h2>{{ t('configTitle') }}</h2>
              <div class="card-head-right">
                <button class="btn btn-ghost btn-sm" @click="handleExport" :disabled="isLocked" :title="t('configExport')">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:13px;height:13px;">
                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                    <polyline points="17 8 12 3 7 8"/>
                    <line x1="12" y1="3" x2="12" y2="15"/>
                  </svg>
                  {{ t('configExport') }}
                </button>
                <button class="btn btn-ghost btn-sm" @click="handleSave" :disabled="isLocked">{{ t('configSave') }}</button>
              </div>
            </div>
            <div class="card-body">
              <div class="form-grid">
                <div class="field col-addr">
                  <label>{{ t('configServer') }}</label>
                  <input
                      v-model="activeConnection.serverIP"
                      :placeholder="t('configServerPlaceholder')"
                      :disabled="isLocked"
                      @change="checkFingerprint"
                  />
                </div>
                <div class="field col-port">
                  <label>{{ t('configPort') }}</label>
                  <input
                      v-model.number="activeConnection.port"
                      type="number"
                      placeholder="8443"
                      :disabled="isLocked"
                  />
                </div>
                <div class="field col-pwd">
                  <label>{{ t('configPassword') }}</label>
                  <input
                      v-model="activeConnection.password"
                      type="password"
                      :placeholder="t('configPasswordPlaceholder')"
                      :disabled="isLocked"
                      @keyup.enter="!isLocked && connect()"
                  />
                </div>
              </div>

              <details class="adv">
                <summary>
                  <span class="adv-chev">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4">
                      <polyline points="9 6 15 12 9 18"/>
                    </svg>
                  </span>
                  <span>{{ t('advTitle') }}</span>
                  <span class="adv-badges" v-if="advancedTagCount">
                    <span v-if="obfsEnabled" class="tag ok">Salamander</span>
                    <span v-if="skipCertEnabled" class="tag warn">{{ t('advSkipCertTag') }}</span>
                    <span v-else-if="hasPinned" class="tag ok">{{ t('advPinnedTag') }}</span>
                  </span>
                </summary>

                <div class="adv-body">
                  <div class="switch-row">
                    <div class="switch-info">
                      <div class="switch-name">{{ t('advObfsName') }}</div>
                      <div class="switch-desc">{{ t('advObfsDesc') }}</div>
                    </div>
                    <label class="switch">
                      <input type="checkbox" v-model="activeConnection.obfsEnabled" :disabled="isLocked" />
                      <span class="switch-track"></span>
                    </label>
                  </div>
                  <div v-if="activeConnection.obfsEnabled" class="field mt-12">
                    <input
                        v-model="activeConnection.obfsPassword"
                        type="password"
                        :placeholder="t('advObfsPlaceholder')"
                        :disabled="isLocked"
                    />
                  </div>

                  <div class="switch-row">
                    <div class="switch-info">
                      <div class="switch-name">{{ t('advSkipCertName') }}</div>
                      <div class="switch-desc">{{ t('advSkipCertDesc') }}</div>
                    </div>
                    <label class="switch">
                      <input type="checkbox" v-model="activeConnection.skipCertVerify" :disabled="isLocked" />
                      <span class="switch-track"></span>
                    </label>
                  </div>
                  <div v-if="!activeConnection.skipCertVerify" class="hint-row" :class="hasPinned ? 'ok' : 'info'">
                    <span>{{ hasPinned ? t('advCertPinned') : t('advCertNotPinned') }}</span>
                    <button v-if="hasPinned" class="link" @click="clearFingerprint" :disabled="isLocked">{{ t('advClear') }}</button>
                  </div>
                </div>
              </details>
            </div>
          </div>

          <div class="card log-card">
            <div class="card-head">
              <div class="log-head-left">
                <span class="live-dot" :class="{ on: activeConnection.status === 'connected' }"></span>
                <h2>{{ t('logsTitle') }}</h2>
                <span class="log-count">{{ logs.length }}</span>
              </div>
              <div class="card-head-right">
                <div class="seg">
                  <button
                      v-for="f in logFilterOptions"
                      :key="f.key"
                      :class="{ on: logFilter === f.key }"
                      @click="logFilter = f.key"
                  >{{ f.label }}</button>
                </div>
                <button
                    class="btn-icon"
                    :class="{ on: logAutoScroll }"
                    @click="logAutoScroll = !logAutoScroll"
                    :title="logAutoScroll ? t('logsAutoScrollOn') : t('logsAutoScrollOff')"
                >
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 5v14M5 12l7 7 7-7"/>
                  </svg>
                </button>
                <button class="btn-icon" @click="copyLogs" :title="t('logsCopy')">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="9" y="9" width="13" height="13" rx="2"/>
                    <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
                  </svg>
                </button>
                <button class="btn-icon" @click="clearLogs" :title="t('logsClear')">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/>
                  </svg>
                </button>
              </div>
            </div>
            <div class="log-view" ref="logContainer">
              <div v-for="(msg, idx) in filteredLogs" :key="idx" class="log-line" :class="getLogClass(msg)">
                <span class="log-t mono">{{ msg.time }}</span>
                <span class="log-m">{{ msg.text }}</span>
              </div>
              <div v-if="!filteredLogs.length" class="log-none">
                {{ logs.length ? t('logsEmptyFiltered') : t('logsEmpty') }}
              </div>
            </div>
          </div>
        </template>
      </main>
    </div>

    <transition name="toast">
      <div v-if="showToast" class="toast" :class="toastType">{{ toastMessage }}</div>
    </transition>

    <transition name="modal">
      <div v-if="showConfirmDialog" class="modal-overlay" @click.self="closeConfirm">
        <div class="modal">
          <div class="modal-head">
            <h3>{{ confirmTitle }}</h3>
          </div>
          <div class="modal-body">
            <p class="confirm-text">{{ confirmMessage }}</p>
          </div>
          <div class="modal-foot">
            <button class="btn btn-ghost" @click="closeConfirm">{{ t('confirmCancel') }}</button>
            <button class="btn btn-primary danger" @click="confirmCallback">{{ t('confirmOk') }}</button>
          </div>
        </div>
      </div>
    </transition>

    <transition name="modal">
      <div v-if="showAbout" class="modal-overlay" @click.self="closeAbout">
        <div class="modal modal-about">
          <button class="modal-x" @click="closeAbout" title="Close">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <line x1="18" y1="6" x2="6" y2="18"/>
              <line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>

          <div class="about-avatar">
            <img src="/logo.png" alt="目代キョウコ" />
          </div>
          <div class="about-name">目代キョウコ</div>
          <div class="about-role">{{ t('aboutRole') }}</div>

          <div class="about-links">
            <a class="about-link" @click.prevent="openExternal('https://space.bilibili.com/477193400')">
              <span class="about-link-label">Bilibili</span>
              <span class="about-link-value">space.bilibili.com/477193400</span>
            </a>
            <a class="about-link" @click.prevent="openExternal('https://kingblog.top/')">
              <span class="about-link-label">{{ t('aboutBlog') }}</span>
              <span class="about-link-value">kingblog.top</span>
            </a>
          </div>

          <div class="about-ver">{{ t('aboutVer', { version }) }}</div>
        </div>
      </div>
    </transition>
  </div>
</template>

<script>
import { SUPPORTED_LOCALES, messages, detectLocale, format } from './i18n.js'

export default {
  data() {
    return {
      version: '0.0.0',
      connections: [],
      activeConnectionId: null,
      logs: [],
      isConnecting: false,
      virtualIP: null,

      healthState: 'healthy',
      healthDetail: { lastRecvAgo: 0, lastPongAgo: 0, consecutiveFail: 0 },
      latency: -1,

      showToast: false,
      toastMessage: '',
      toastType: 'success',
      toastTimer: null,

      showConfirmDialog: false,
      confirmTitle: '',
      confirmMessage: '',
      confirmCallback: null,

      showAbout: false,
      hasPinned: false,

      connectedAt: null,
      nowTick: 0,
      clockTimer: null,
      logFilter: 'all',
      logAutoScroll: true,

      // ⭐ 语言
      currentLocale: 'zh-CN',
      langOpen: false,
      languages: SUPPORTED_LOCALES,
    }
  },

  computed: {
    activeConnection() {
      return this.connections.find(c => c.id === this.activeConnectionId) || null
    },
    isLocked() {
      const c = this.activeConnection
      if (!c) return false
      return c.status === 'connecting' || c.status === 'connected'
    },
    currentLocaleShort() {
      const l = this.languages.find(x => x.code === this.currentLocale)
      return l ? l.short : this.currentLocale
    },
    logFilterOptions() {
      return [
        { key: 'all', label: this.t('logsFilterAll') },
        { key: 'info', label: this.t('logsFilterInfo') },
        { key: 'success', label: this.t('logsFilterSuccess') },
        { key: 'warn', label: this.t('logsFilterWarn') },
        { key: 'error', label: this.t('logsFilterError') },
      ]
    },
    healthText() {
      switch (this.healthState) {
        case 'healthy': return this.t('healthHealthy')
        case 'degraded': return this.t('healthDegraded')
        case 'reconnecting': return this.t('healthReconnecting')
        case 'offline': return this.t('healthOffline')
        default: return this.t('healthUnknown')
      }
    },
    healthValueClass() {
      switch (this.healthState) {
        case 'healthy': return 'ok'
        case 'degraded': return 'warn'
        case 'reconnecting': return 'warn'
        case 'offline': return 'err'
        default: return ''
      }
    },
    latencyText() {
      if (this.latency < 0) return '—'
      return this.latency + ' ms'
    },
    latencyClass() {
      if (this.latency < 0) return ''
      if (this.latency < 100) return 'ok'
      if (this.latency < 200) return 'warn'
      return 'err'
    },
    showHealthDetail() {
      const c = this.activeConnection
      if (!c || c.status !== 'connected') return false
      return this.healthState !== 'healthy'
    },
    healthStripText() {
      const d = this.healthDetail
      switch (this.healthState) {
        case 'degraded':
          return this.t('healthDegradedDetail', { n: d.consecutiveFail, s: d.lastRecvAgo.toFixed(1) })
        case 'reconnecting':
          return this.t('healthReconnectingDetail', { s: d.lastRecvAgo.toFixed(1) })
        case 'offline':
          return this.t('healthOfflineDetail', { s: d.lastRecvAgo.toFixed(1) })
        default:
          return ''
      }
    },
    globalStatusClass() {
      const c = this.connections.find(x => x.status === 'connected' || x.status === 'connecting')
      if (!c) return 'idle'
      return c.status
    },
    globalStatusText() {
      const c = this.connections.find(x => x.status === 'connected' || x.status === 'connecting')
      if (!c) return this.t('statusIdle')
      return c.status === 'connected' ? this.t('statusConnected') : this.t('statusConnecting')
    },
    elapsedText() {
      void this.nowTick
      if (!this.connectedAt) return '—'
      if (this.activeConnection?.status !== 'connected') return '—'
      return this.fmtDuration((Date.now() - this.connectedAt) / 1000)
    },
    obfsEnabled() { return !!this.activeConnection?.obfsEnabled },
    skipCertEnabled() { return !!this.activeConnection?.skipCertVerify },
    advancedTagCount() {
      return (this.obfsEnabled ? 1 : 0) + (this.skipCertEnabled ? 1 : (this.hasPinned ? 1 : 0))
    },
    primaryBtnText() {
      const s = this.activeConnection?.status
      if (s === 'connecting') return this.t('heroBtnConnecting')
      if (s === 'connected') return this.t('heroBtnDisconnect')
      return this.t('heroBtnConnect')
    },
    connectBtnClass() {
      const s = this.activeConnection?.status
      if (s === 'connected') return 'btn-danger'
      if (s === 'connecting') return 'btn-ghost'
      return 'btn-primary'
    },
    filteredLogs() {
      if (this.logFilter === 'all') return this.logs
      return this.logs.filter(l => this.getLogClass(l) === this.logFilter)
    },
  },

  mounted() {
    // ⭐ 初始化语言
    document.addEventListener('click', this.onDocClick)
    this.currentLocale = detectLocale()

    if (window.go?.main?.App?.GetClientVersion) {
      window.go.main.App.GetClientVersion()
          .then(v => { if (v) this.version = v })
          .catch(() => {})
    }

    this.loadConnections()
    if (this.connections.length === 0) this.createNewConnection()
    this.activeConnectionId = this.connections[0]?.id || null
    this.checkFingerprint()

    this.clockTimer = setInterval(() => { this.nowTick++ }, 1000)

    window.runtime.EventsOn('health', (snapshot) => {
      if (!snapshot) return
      this.healthState = snapshot.state || 'healthy'
      this.healthDetail = {
        lastRecvAgo: snapshot.lastRecvAgo || 0,
        lastPongAgo: snapshot.lastPongAgo || 0,
        consecutiveFail: snapshot.consecutiveFail || 0,
      }
      if (typeof snapshot.latency === 'number') {
        this.latency = snapshot.latency
      }
    })

    window.runtime.EventsOn('disconnected', (reason) => {
      const conn = this.activeConnection
      if (conn) conn.status = 'disconnected'
      this.virtualIP = null
      this.connectedAt = null
      this.latency = -1
      this.healthState = 'healthy'
      this.healthDetail = { lastRecvAgo: 0, lastPongAgo: 0, consecutiveFail: 0 }
      this.addLog(this.t('logAutoDisconnect', { reason: reason || this.t('toastServerOffline') }))
      this.showToastMessage(reason || this.t('toastServerOffline'), 'error')
    })

    window.runtime.EventsOn('reconnecting', (attempt) => {
      this.addLog(this.t('logReconnecting', { n: attempt }))
      this.showToastMessage(this.t('toastReconnecting', { n: attempt }), 'error')
    })

    window.runtime.EventsOn('reconnected', (newIP) => {
      const conn = this.activeConnection
      if (conn) conn.status = 'connected'
      this.virtualIP = newIP
      this.connectedAt = Date.now()
      this.latency = -1
      this.healthState = 'healthy'
      this.healthDetail = { lastRecvAgo: 0, lastPongAgo: 0, consecutiveFail: 0 }
      this.addLog(this.t('logReconnected', { ip: newIP }))
      this.showToastMessage(this.t('toastReconnected'), 'success')
      this.checkFingerprint()
    })

    window.runtime.EventsOn('pending-import', async () => {
      await this.consumePendingImport()
    })

    setTimeout(() => { this.consumePendingImport() }, 800)

    window.addEventListener('keydown', this.onKeydown)
    window.addEventListener('wheel', this.preventCtrlWheel, { passive: false })
    window.addEventListener('keydown', this.preventZoomShortcut)
  },

  beforeUnmount() {
    document.removeEventListener('click', this.onDocClick)
    if (this.clockTimer) clearInterval(this.clockTimer)
    window.removeEventListener('keydown', this.onKeydown)
    window.removeEventListener('wheel', this.preventCtrlWheel)
    window.removeEventListener('keydown', this.preventZoomShortcut)
  },

  methods: {
    onDocClick(e) {
      if (!this.langOpen) return
      // 点击不在 .lang-switch 区域内则关闭
      if (!e.target.closest('.lang-switch')) {
        this.langOpen = false
      }
    },
    // ---------- ⭐ 语言 ----------
    t(key, params) {
      const dict = messages[this.currentLocale] || messages['zh-CN']
      const s = dict[key]
      if (s === undefined) return key
      return params ? format(s, params) : s
    },

    setLocale(code) {
      if (!messages[code]) return
      this.currentLocale = code
      try { localStorage.setItem('hy2link_locale', code) } catch (_) {}
      document.documentElement.setAttribute('lang', code)
      this.langOpen = false
    },

    // ---------- 缩放拦截 ----------
    preventCtrlWheel(e) {
      if (e.ctrlKey || e.metaKey) e.preventDefault()
    },
    preventZoomShortcut(e) {
      if (e.ctrlKey || e.metaKey) {
        const k = e.key
        if (k === '+' || k === '=' || k === '-' || k === '_' || k === '0') e.preventDefault()
      }
    },

    // ---------- 导入 / 导出 ----------
    async consumePendingImport() {
      try {
        const res = await window.go.main.App.ConsumePendingImport()
        if (res?.ok && res.config) {
          this.applyImportedConfig(res.config)
          this.showToastMessage(this.t('toastImported'), 'success')
        } else if (res?.error) {
          this.showToastMessage(this.t('toastImportFailed', { err: res.error }), 'error')
        }
      } catch (e) {}
    },

    async handleImport() {
      try {
        const cfg = await window.go.main.App.ImportConfigDialog()
        if (!cfg) return
        this.applyImportedConfig(cfg)
        this.showToastMessage(this.t('toastImported'), 'success')
      } catch (e) {
        this.showToastMessage(this.t('toastImportFailed', { err: e.message }), 'error')
      }
    },

    async handleExport() {
      const conn = this.activeConnection
      if (!conn) return
      if (!conn.serverIP) {
        this.showToastMessage(this.t('toastConfigNoServer'), 'error')
        return
      }
      try {
        const path = await window.go.main.App.ExportConfig({
          ip: conn.serverIP,
          port: conn.port,
          portVPN: 8444,
          username: '',
          password: conn.password,
          useDHCP: true,
          staticIP: '',
          staticMask: '',
          skipCertVerify: !!conn.skipCertVerify,
          obfsEnabled: !!conn.obfsEnabled,
          obfsPassword: conn.obfsPassword || '',
        })
        if (path) {
          this.addLog(this.t('logExported', { path }))
          this.showToastMessage(this.t('toastExported'), 'success')
        }
      } catch (e) {
        this.showToastMessage(this.t('toastExportFailed', { err: e.message }), 'error')
      }
    },

    applyImportedConfig(cfg) {
      const ip = cfg.ip || cfg.IP || ''
      const port = cfg.port || cfg.Port || 0
      if (!ip) {
        this.showToastMessage(this.t('toastConfigNoServer'), 'error')
        return
      }
      if (!port) {
        this.showToastMessage(this.t('toastConfigNoPort'), 'error')
        return
      }

      const exists = this.connections.find(c => c.serverIP === ip && c.port === port)
      if (exists) {
        this.showConfirm(
            this.t('confirmExistsTitle'),
            this.t('confirmExistsMsg', { name: exists.name || this.t('sidebarUntitled') }),
            () => {
              exists.password = cfg.password || ''
              exists.obfsEnabled = !!cfg.obfsEnabled
              exists.obfsPassword = cfg.obfsPassword || ''
              exists.skipCertVerify = !!cfg.skipCertVerify
              this.saveConnections()
              this.showToastMessage(this.t('toastUpdated'), 'success')
              this.closeConfirm()
            }
        )
        return
      }

      const newConn = {
        id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
        name: ip,
        serverIP: ip,
        port: port,
        password: cfg.password || '',
        status: 'disconnected',
        skipCertVerify: !!cfg.skipCertVerify,
        obfsEnabled: !!cfg.obfsEnabled,
        obfsPassword: cfg.obfsPassword || '',
      }
      this.connections.push(newConn)
      this.activeConnectionId = newConn.id
      this.saveConnections()
      this.addLog(this.t('logImported', { addr: `${ip}:${port}` }))
      this.checkFingerprint()
    },

    // ---------- 原有方法 ----------
    fmtDuration(sec) {
      sec = Math.max(0, Math.floor(sec))
      const h = Math.floor(sec / 3600)
      const m = Math.floor((sec % 3600) / 60)
      const s = sec % 60
      const pad = (n) => String(n).padStart(2, '0')
      if (h > 0) return `${h}:${pad(m)}:${pad(s)}`
      return `${pad(m)}:${pad(s)}`
    },

    connShortTime(conn) {
      if (conn.status !== 'connected') return '—'
      if (conn.id === this.activeConnectionId && this.connectedAt) {
        void this.nowTick
        return this.fmtDuration((Date.now() - this.connectedAt) / 1000)
      }
      return '—'
    },

    onKeydown(e) {
      if (e.key === 'Escape') {
        if (this.showConfirmDialog) this.closeConfirm()
        else if (this.showAbout) this.closeAbout()
      }
    },

    showToastMessage(msg, type = 'success') {
      if (this.toastTimer) clearTimeout(this.toastTimer)
      this.toastMessage = msg
      this.toastType = type
      this.showToast = true
      this.toastTimer = setTimeout(() => {
        this.showToast = false
        this.toastTimer = null
      }, 2400)
    },

    showConfirm(title, msg, callback) {
      this.confirmTitle = title
      this.confirmMessage = msg
      this.confirmCallback = callback
      this.showConfirmDialog = true
    },
    closeConfirm() {
      this.showConfirmDialog = false
      this.confirmCallback = null
    },
    closeAbout() { this.showAbout = false },

    openExternal(url) {
      if (window.runtime?.BrowserOpenURL) window.runtime.BrowserOpenURL(url)
      else window.open(url, '_blank')
    },

    async copyServerAddr() {
      const c = this.activeConnection
      if (!c?.serverIP) return
      try {
        await navigator.clipboard.writeText(`${c.serverIP}:${c.port}`)
        this.showToastMessage(this.t('toastAddrCopied'), 'success')
      } catch {
        this.showToastMessage(this.t('toastCopyFailed'), 'error')
      }
    },

    async copyLogs() {
      if (!this.logs.length) return
      const text = this.logs.map(l => `[${l.time}] ${l.text}`).join('\n')
      try {
        await navigator.clipboard.writeText(text)
        this.showToastMessage(this.t('toastLogsCopied', { n: this.logs.length }), 'success')
      } catch {
        this.showToastMessage(this.t('toastCopyFailed'), 'error')
      }
    },

    async checkFingerprint() {
      const conn = this.activeConnection
      if (!conn?.serverIP) { this.hasPinned = false; return }
      try {
        this.hasPinned = await window.go.main.App.HasPinnedFingerprint(conn.serverIP)
      } catch { this.hasPinned = false }
    },

    createNewConnection() {
      if (this.isLocked) return
      const newConn = {
        id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
        name: '',
        serverIP: '',
        port: 8443,
        password: '',
        status: 'disconnected',
        skipCertVerify: false,
        obfsEnabled: false,
        obfsPassword: '',
      }
      this.connections.push(newConn)
      this.activeConnectionId = newConn.id
      this.saveConnections()
      this.hasPinned = false
      this.showToastMessage(this.t('toastCreated'), 'success')
    },

    selectConnection(id) {
      if (this.isLocked) return
      if (this.isConnectionDisabled(id)) return
      if (this.activeConnection?.status === 'connected') {
        this.addLog(this.t('toastSwitchFirst'))
        return
      }
      this.activeConnectionId = id
      this.virtualIP = null
      this.connectedAt = null
      this.latency = -1
      this.healthState = 'healthy'
      this.healthDetail = { lastRecvAgo: 0, lastPongAgo: 0, consecutiveFail: 0 }
      this.checkFingerprint()
    },

    deleteFromCard(conn) {
      if (this.isLocked) return
      if (conn.status === 'connected' || conn.status === 'connecting') {
        this.showToastMessage(this.t('toastDisconnectFirst'), 'error')
        return
      }
      this.showConfirm(
          this.t('confirmDeleteTitle'),
          this.t('confirmDeleteMsg', { name: conn.name || this.t('sidebarUntitled') }),
          () => {
            const idx = this.connections.indexOf(conn)
            if (idx < 0) return
            this.connections.splice(idx, 1)
            if (this.activeConnectionId === conn.id) {
              this.activeConnectionId = this.connections[0]?.id || null
            }
            this.saveConnections()
            this.showToastMessage(this.t('toastDeleted'), 'success')
            this.checkFingerprint()
            this.closeConfirm()
          }
      )
    },

    isConnectionDisabled(id) {
      const active = this.connections.find(c => c.status === 'connected' || c.status === 'connecting')
      return active && active.id !== id
    },

    statusText(s) {
      switch (s) {
        case 'connected': return this.t('heroConnected')
        case 'connecting': return this.t('heroConnecting')
        case 'disconnected': return this.t('heroDisconnected')
        case 'error': return this.t('heroError')
        default: return s
      }
    },

    async toggleConnection() {
      if (this.isConnecting) return
      if (this.activeConnection.status === 'connected') await this.disconnect()
      else await this.connect()
    },

    async connect() {
      if (this.isConnecting) return
      const conn = this.activeConnection
      if (!conn) return
      if (!conn.serverIP) { this.showToastMessage(this.t('toastNeedServer'), 'error'); return }
      if (!conn.password) { this.showToastMessage(this.t('toastNeedPassword'), 'error'); return }
      if (conn.obfsEnabled) {
        const psk = (conn.obfsPassword || '').trim()
        if (psk.length < 4) { this.showToastMessage(this.t('toastObfsTooShort'), 'error'); return }
      }

      this.isConnecting = true
      conn.status = 'connecting'
      this.latency = -1
      this.healthState = 'healthy'
      this.healthDetail = { lastRecvAgo: 0, lastPongAgo: 0, consecutiveFail: 0 }

      this.addLog(this.t('logConnecting', { addr: `${conn.serverIP}:${conn.port}` }))
      this.addLog(this.t('logObfsState', {
        obfs: conn.obfsEnabled ? this.t('logObfsEnabled') : this.t('logObfsDisabled'),
        cert: conn.skipCertVerify ? this.t('logCertSkipped') : this.t('logCertPin'),
      }))

      try {
        const ip = await window.go.main.App.ConnectClient({
          ip: conn.serverIP,
          port: conn.port,
          username: '',
          password: conn.password,
          useDHCP: true,
          staticIP: '',
          staticMask: '',
          skipCertVerify: !!conn.skipCertVerify,
          obfsEnabled: !!conn.obfsEnabled,
          obfsPassword: conn.obfsPassword || '',
        })
        conn.status = 'connected'
        this.virtualIP = ip
        this.connectedAt = Date.now()
        this.addLog(this.t('logConnectSuccess', { ip }))
        this.showToastMessage(this.t('toastConnectSuccess'), 'success')
        this.checkFingerprint()
      } catch (e) {
        conn.status = 'error'
        this.addLog(this.t('logConnectFailed', { err: e.message }))
        this.showToastMessage(this.t('toastConnectFailed', { err: e.message }), 'error')
        this.checkFingerprint()
      } finally {
        this.isConnecting = false
        this.saveConnections()
      }
    },

    async disconnect() {
      if (this.isConnecting) return
      const conn = this.activeConnection
      if (!conn) return
      this.isConnecting = true
      try {
        await window.go.main.App.Stop()
        conn.status = 'disconnected'
        this.virtualIP = null
        this.connectedAt = null
        this.latency = -1
        this.healthState = 'healthy'
        this.addLog(this.t('logDisconnected'))
        this.showToastMessage(this.t('toastDisconnected'), 'success')
      } catch (e) {
        this.addLog(this.t('logDisconnectFailed', { err: e.message }))
        this.showToastMessage(this.t('toastDisconnectFailed', { err: e.message }), 'error')
      } finally {
        this.isConnecting = false
        this.saveConnections()
      }
    },

    async clearFingerprint() {
      if (this.isLocked) return
      const conn = this.activeConnection
      if (!conn?.serverIP) return
      this.showConfirm(
          this.t('confirmClearFpTitle'),
          this.t('confirmClearFpMsg', { ip: conn.serverIP }),
          async () => {
            try {
              await window.go.main.App.ClearPinnedFingerprint(conn.serverIP)
              this.addLog(this.t('logClearedFp', { ip: conn.serverIP }))
              this.showToastMessage(this.t('advClear'), 'success')
              this.hasPinned = false
            } catch (e) {
              this.addLog(this.t('logClearFpFailed', { err: e.message }))
              this.showToastMessage(this.t('toastSaveFailed', { err: e.message }), 'error')
            } finally { this.closeConfirm() }
          })
    },

    handleSave() {
      try {
        this.saveConnections()
        this.showToastMessage(this.t('toastSaved'), 'success')
      } catch (e) {
        this.showToastMessage(this.t('toastSaveFailed', { err: e.message }), 'error')
      }
    },

    addLog(msg) {
      this.logs.push({ time: new Date().toLocaleTimeString('zh-CN', { hour12: false }), text: msg })
      if (this.logAutoScroll) {
        this.$nextTick(() => {
          const c = this.$refs.logContainer
          if (c) c.scrollTop = c.scrollHeight
        })
      }
    },

    clearLogs() { this.logs = [] },

    getLogClass(msg) {
      const t = msg?.text || ''
      if (/失败|错误|error|failed/i.test(t)) return 'error'
      if (/警告|warn|⚠/i.test(t)) return 'warn'
      if (/成功|已连接|已启动|重连成功|connected|success/i.test(t)) return 'success'
      return 'info'
    },

    saveConnections() {
      localStorage.setItem('vpn_connections', JSON.stringify(this.connections))
    },

    loadConnections() {
      try {
        const data = localStorage.getItem('vpn_connections')
        if (data) {
          this.connections = JSON.parse(data)
          this.connections.forEach(c => {
            c.status = 'disconnected'
            delete c.useDHCP
            delete c.staticIP
            delete c.staticMask
            delete c.latencyMode
            delete c.ccMode
            delete c.bandwidthMbps
            if (typeof c.skipCertVerify !== 'boolean') c.skipCertVerify = false
            if (typeof c.obfsEnabled !== 'boolean') c.obfsEnabled = false
            if (typeof c.obfsPassword !== 'string') c.obfsPassword = ''
          })
        }
      } catch (e) { console.warn('load connections failed:', e) }
    },
  }
}
</script>

<style>
/* ============================================================
   Hy2Link Client — Linear / Vercel inspired dark UI
   ============================================================ */
:root {
  --bg: #08080a;
  --bg-1: #0d0d0f;
  --bg-2: #101012;
  --bg-3: #16161a;
  --border: #1c1c20;
  --border-1: #26262b;
  --border-2: #34343a;
  --text-1: #ededed;
  --text-2: #a1a1a6;
  --text-3: #6b6b72;
  --text-4: #4a4a52;
  --accent: #22c55e;
  --accent-hi: #4ade80;
  --ok: #22c55e;
  --warn: #f59e0b;
  --err: #ef4444;
  --r-sm: 6px;
  --r-md: 8px;
  --r-lg: 12px;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
html, body, #app { height: 100%; }

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
  background: var(--bg);
  color: var(--text-1);
  overflow: hidden;
  -webkit-font-smoothing: antialiased;
  font-feature-settings: 'cv02', 'cv03', 'cv04', 'cv11';
  font-size: 13px;
  line-height: 1.5;

  -webkit-user-select: none;
  -moz-user-select: none;
  -ms-user-select: none;
  user-select: none;
  cursor: default;
}

input,
textarea {
  -webkit-user-select: text;
  -moz-user-select: text;
  -ms-user-select: text;
  user-select: text;
}

.log-view {
  -webkit-user-select: text;
  -moz-user-select: text;
  -ms-user-select: text;
  user-select: text;
}

.mono {
  font-family: 'JetBrains Mono', 'SF Mono', 'Consolas', monospace;
  font-variant-numeric: tabular-nums;
  letter-spacing: 0;
}
.dim { opacity: 0.5; }
.mt-12 { margin-top: 12px; }

#app {
  height: 100%;
  display: flex;
  flex-direction: column;
  background: var(--bg);
  overflow: hidden;
  -webkit-user-select: none;
  user-select: none;
}

/* Topbar */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 56px;
  padding: 0 20px;
  border-bottom: 1px solid var(--border);
  background: var(--bg);
  flex-shrink: 0;
  -webkit-app-region: drag;
  user-select: none;
}

.brand {
  display: flex;
  align-items: center;
  gap: 11px;
}
.brand-logo {
  width: 26px; height: 26px;
  border-radius: var(--r-sm);
  object-fit: cover;
  -webkit-user-drag: none;
}
.brand-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}
.brand-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13.5px;
  font-weight: 600;
  color: var(--text-1);
  letter-spacing: -0.01em;
  line-height: 1.1;
}
.brand-sub {
  font-size: 10.5px;
  color: var(--text-3);
  letter-spacing: 0.04em;
  line-height: 1.1;
  font-weight: 500;
}
.brand-ver {
  font-size: 10.5px;
  color: var(--text-3);
  font-family: 'JetBrains Mono', monospace;
  padding: 1px 6px;
  border: 1px solid var(--border-1);
  border-radius: 4px;
  letter-spacing: 0.02em;
  font-weight: 400;
}

.topbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
  -webkit-app-region: no-drag;
}
.run-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  font-size: 11.5px;
  font-weight: 500;
  border: 1px solid var(--border-1);
  border-radius: 100px;
  color: var(--text-2);
  letter-spacing: -0.005em;
}
.run-chip .run-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--text-4);
}
.run-chip.connected {
  color: var(--ok);
  border-color: rgba(34, 197, 94, 0.25);
  background: rgba(34, 197, 94, 0.06);
}
.run-chip.connected .run-dot {
  background: var(--ok);
  box-shadow: 0 0 6px rgba(34, 197, 94, 0.7);
}
.run-chip.connecting {
  color: var(--warn);
  border-color: rgba(245, 158, 11, 0.25);
  background: rgba(245, 158, 11, 0.06);
}
.run-chip.connecting .run-dot {
  background: var(--warn);
  box-shadow: 0 0 6px rgba(245, 158, 11, 0.7);
  animation: pulse 1.4s ease-in-out infinite;
}

/* ⭐ 语言切换 */
.lang-switch {
  position: relative;
  display: inline-flex;
}
.lang-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 11px;
  background: transparent;
  border: 1px solid var(--border-1);
  border-radius: var(--r-sm);
  color: var(--text-2);
  font-family: inherit;
  font-size: 11.5px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.12s;
  white-space: nowrap;
  letter-spacing: -0.005em;
}
.lang-btn:hover {
  background: var(--bg-2);
  color: var(--text-1);
  border-color: var(--border-2);
}
.lang-btn svg {
  width: 13px;
  height: 13px;
  flex-shrink: 0;
  opacity: 0.85;
}
.lang-menu {
  position: absolute;
  top: calc(100% + 6px);
  right: 0;
  min-width: 148px;
  padding: 4px;
  background: var(--bg-1);
  border: 1px solid var(--border-1);
  border-radius: var(--r-md);
  box-shadow: 0 12px 32px -8px rgba(0, 0, 0, 0.75);
  z-index: 200;
}
.lang-option {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 7px 10px;
  background: transparent;
  border: none;
  border-radius: var(--r-sm);
  color: var(--text-2);
  font-family: inherit;
  font-size: 12.5px;
  text-align: left;
  cursor: pointer;
  transition: background 0.12s, color 0.12s;
  letter-spacing: -0.005em;
}
.lang-option:hover {
  background: var(--bg-2);
  color: var(--text-1);
}
.lang-option.active { color: var(--accent); }
.lang-check {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 13px;
  height: 13px;
  flex-shrink: 0;
  color: var(--accent);
}
.lang-check svg { width: 100%; height: 100%; }

/* Body */
.app-body {
  flex: 1;
  display: grid;
  grid-template-columns: 232px 1fr;
  min-height: 0;
  overflow: hidden;
}

/* Sidebar */
.sidebar {
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--border);
  background: var(--bg);
  min-height: 0;
  overflow: hidden;
}
.sidebar-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 18px 16px 10px;
  flex-shrink: 0;
}
.sidebar-label {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.btn-icon {
  width: 22px; height: 22px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: 1px solid transparent;
  border-radius: var(--r-sm);
  color: var(--text-3);
  cursor: pointer;
  transition: all 0.12s;
  flex-shrink: 0;
}
.btn-icon:hover:not(:disabled) {
  background: var(--bg-2);
  border-color: var(--border-1);
  color: var(--text-1);
}
.btn-icon:disabled { opacity: 0.35; cursor: not-allowed; }
.btn-icon svg { width: 12px; height: 12px; }
.btn-icon.on {
  color: var(--accent);
  border-color: rgba(34, 197, 94, 0.25);
  background: rgba(34, 197, 94, 0.06);
}

.conn-list {
  flex: 1;
  overflow-y: auto;
  padding: 0 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-height: 0;
}
.conn-list::-webkit-scrollbar { width: 4px; }
.conn-list::-webkit-scrollbar-thumb { background: var(--border-1); border-radius: 4px; }
.conn-item {
  position: relative;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 10px 9px 12px;
  border-radius: var(--r-sm);
  cursor: pointer;
  transition: background 0.12s;
  border: 1px solid transparent;
}
.conn-item:hover:not(.disabled) { background: var(--bg-2); }
.conn-item.active {
  background: var(--bg-2);
  border-color: var(--border-1);
}
.conn-item.active::before {
  content: '';
  position: absolute;
  left: 0;
  top: 50%;
  transform: translateY(-50%);
  width: 2px;
  height: 16px;
  background: var(--accent);
  border-radius: 0 2px 2px 0;
}
.conn-item.disabled { opacity: 0.35; cursor: not-allowed; }

.conn-dot {
  width: 7px; height: 7px;
  border-radius: 50%;
  background: var(--text-4);
  flex-shrink: 0;
}
.conn-dot.connected { background: var(--ok); box-shadow: 0 0 6px rgba(34, 197, 94, 0.7); }
.conn-dot.connecting {
  background: var(--warn);
  box-shadow: 0 0 6px rgba(245, 158, 11, 0.7);
  animation: pulse 1.4s ease-in-out infinite;
}
.conn-dot.error { background: var(--err); box-shadow: 0 0 6px rgba(239, 68, 68, 0.7); }
.conn-dot.lg { width: 10px; height: 10px; }

.conn-info { flex: 1; min-width: 0; }
.conn-name {
  font-size: 12.5px;
  font-weight: 500;
  color: var(--text-1);
  letter-spacing: -0.005em;
  line-height: 1.3;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.conn-addr {
  font-size: 10.5px;
  color: var(--text-3);
  font-family: 'JetBrains Mono', monospace;
  margin-top: 2px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.conn-tail {
  flex-shrink: 0;
  display: flex;
  align-items: center;
}
.conn-time {
  font-size: 10.5px;
  color: var(--text-3);
  font-variant-numeric: tabular-nums;
}
.conn-item.active .conn-time { color: var(--text-2); }
.conn-x {
  width: 18px; height: 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  border-radius: 5px;
  color: var(--text-3);
  cursor: pointer;
  opacity: 0;
  transition: all 0.12s;
}
.conn-item:hover .conn-x { opacity: 1; }
.conn-x:hover { background: rgba(239, 68, 68, 0.1); color: var(--err); }
.conn-x svg { width: 10px; height: 10px; }

.empty-side {
  padding: 32px 16px;
  text-align: center;
  color: var(--text-3);
  font-size: 12px;
}
.empty-side p { margin-bottom: 14px; }

/* Main */
.main {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 20px 24px 24px;
  min-width: 0;
  min-height: 0;
  overflow-y: auto;
}
.main::-webkit-scrollbar { width: 6px; }
.main::-webkit-scrollbar-thumb { background: var(--border-1); border-radius: 6px; }

.empty-main {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  color: var(--text-3);
  gap: 8px;
}
.empty-icon {
  width: 56px; height: 56px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px dashed var(--border-2);
  border-radius: var(--r-lg);
  margin-bottom: 8px;
}
.empty-icon svg { width: 24px; height: 24px; color: var(--text-3); }
.empty-main h3 { font-size: 14px; font-weight: 500; color: var(--text-2); }
.empty-main p { font-size: 12px; color: var(--text-3); }

/* Card */
.card {
  background: var(--bg-1);
  border: 1px solid var(--border);
  border-radius: var(--r-lg);
  overflow: hidden;
  flex-shrink: 0;
}
.card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 13px 18px;
  border-bottom: 1px solid var(--border);
}
.card-head h2 {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--text-1);
  letter-spacing: -0.005em;
}
.card-head-right {
  display: flex;
  align-items: center;
  gap: 6px;
}
.card-body { padding: 18px; }

/* Hero */
.hero-card { transition: border-color 0.2s; }
.hero-card.is-connected { border-color: rgba(34, 197, 94, 0.22); }
.hero-card.is-connecting { border-color: rgba(245, 158, 11, 0.22); }
.hero-card.is-error { border-color: rgba(239, 68, 68, 0.22); }

.hero-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.hero-status {
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
  flex: 1;
}
.hero-text { min-width: 0; }
.hero-state {
  font-size: 16px;
  font-weight: 600;
  color: var(--text-1);
  letter-spacing: -0.015em;
  line-height: 1.2;
}
.hero-host {
  display: flex;
  align-items: baseline;
  margin-top: 3px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12px;
  color: var(--text-3);
}
.hero-host-ip {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 320px;
}
.hero-host-port { opacity: 0.7; }

.copy-mini {
  width: 20px; height: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  border-radius: 5px;
  color: var(--text-3);
  cursor: pointer;
  margin-left: 6px;
  transition: all 0.12s;
  flex-shrink: 0;
}
.copy-mini:hover { background: var(--bg-2); color: var(--text-1); }
.copy-mini svg { width: 11px; height: 11px; }

.hero-stats {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
}
.hero-cell {
  padding: 0 16px;
  border-right: 1px solid var(--border);
  min-width: 0;
}
.hero-cell:first-child { padding-left: 0; }
.hero-cell:last-child { padding-right: 0; border-right: none; }
.stat-label {
  font-size: 11px;
  color: var(--text-3);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  font-weight: 500;
  margin-bottom: 6px;
}
.stat-value {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-1);
  letter-spacing: -0.015em;
  font-variant-numeric: tabular-nums;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.stat-value.mono { font-size: 14px; }
.stat-value.ok { color: var(--ok); }
.stat-value.warn { color: var(--warn); }
.stat-value.err { color: var(--err); }

.health-strip {
  margin-top: 16px;
  padding: 10px 14px;
  border-radius: var(--r-md);
  font-size: 12px;
  line-height: 1.5;
}
.health-strip.degraded {
  background: rgba(245, 158, 11, 0.06);
  border: 1px solid rgba(245, 158, 11, 0.2);
  color: var(--warn);
}
.health-strip.reconnecting {
  background: rgba(59, 130, 246, 0.06);
  border: 1px solid rgba(59, 130, 246, 0.2);
  color: #60a5fa;
}
.health-strip.offline {
  background: rgba(239, 68, 68, 0.06);
  border: 1px solid rgba(239, 68, 68, 0.2);
  color: #fca5a5;
}

.fade-enter-active, .fade-leave-active { transition: opacity 0.2s; }
.fade-enter-from, .fade-leave-to { opacity: 0; }

/* Buttons */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 16px;
  font-family: inherit;
  font-size: 12.5px;
  font-weight: 500;
  letter-spacing: -0.005em;
  border-radius: var(--r-sm);
  border: 1px solid transparent;
  cursor: pointer;
  transition: background 0.12s, border-color 0.12s, color 0.12s;
  white-space: nowrap;
  line-height: 1.2;
}
.btn:disabled { opacity: 0.4; cursor: not-allowed; }
.btn svg { width: 13px; height: 13px; }
.btn-primary {
  background: var(--accent);
  color: #04160a;
  border-color: var(--accent);
  min-width: 96px;
}
.btn-primary:hover:not(:disabled) {
  background: var(--accent-hi);
  border-color: var(--accent-hi);
}
.btn-ghost {
  background: transparent;
  color: var(--text-2);
  border-color: var(--border-1);
}
.btn-ghost:hover:not(:disabled) {
  background: var(--bg-2);
  color: var(--text-1);
  border-color: var(--border-2);
}
.btn-danger {
  background: transparent;
  color: var(--err);
  border-color: rgba(239, 68, 68, 0.28);
  min-width: 96px;
}
.btn-danger:hover:not(:disabled) {
  background: rgba(239, 68, 68, 0.08);
  border-color: rgba(239, 68, 68, 0.5);
}
.btn-sm { padding: 5px 11px; font-size: 11.5px; }
.spin { animation: spin 1s linear infinite; }

/* Tag */
.tag {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  font-size: 10.5px;
  font-weight: 500;
  border-radius: 100px;
  border: 1px solid var(--border-1);
  color: var(--text-3);
  background: var(--bg-2);
  white-space: nowrap;
}
.tag.ok {
  color: var(--ok);
  border-color: rgba(34, 197, 94, 0.25);
  background: rgba(34, 197, 94, 0.06);
}
.tag.warn {
  color: var(--warn);
  border-color: rgba(245, 158, 11, 0.25);
  background: rgba(245, 158, 11, 0.06);
}

/* Form */
.form-grid {
  display: grid;
  grid-template-columns: 2fr 90px 2fr;
  gap: 12px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
}
.field label {
  font-size: 12px;
  font-weight: 500;
  color: var(--text-2);
}
.field input {
  width: 100%;
  padding: 8px 11px;
  background: var(--bg-2);
  border: 1px solid var(--border-1);
  border-radius: var(--r-sm);
  color: var(--text-1);
  font-size: 13px;
  font-family: inherit;
  outline: none;
  transition: border-color 0.15s, background 0.15s;
}
.field input:focus {
  border-color: var(--accent);
  background: var(--bg-1);
}
.field input:disabled { opacity: 0.5; cursor: not-allowed; }
.field input::placeholder { color: var(--text-4); }
.field input[type="number"]::-webkit-outer-spin-button,
.field input[type="number"]::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; }
.field input[type="number"] { -moz-appearance: textfield; }

/* Advanced */
.adv {
  margin-top: 18px;
  border-top: 1px solid var(--border);
  padding-top: 4px;
}
.adv summary {
  list-style: none;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 0 6px;
  user-select: none;
  color: var(--text-2);
  font-size: 12.5px;
  font-weight: 500;
}
.adv summary::-webkit-details-marker { display: none; }
.adv summary:hover { color: var(--text-1); }
.adv-chev { display: flex; transition: transform 0.2s; color: var(--text-3); }
.adv-chev svg { width: 11px; height: 11px; }
.adv[open] .adv-chev { transform: rotate(90deg); }
.adv-badges { display: flex; gap: 6px; margin-left: auto; }
.adv-body {
  padding-top: 8px;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

/* Switch */
.switch-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 20px;
  padding: 10px 0;
}
.switch-info { flex: 1; min-width: 0; }
.switch-name {
  font-size: 12.5px;
  font-weight: 500;
  color: var(--text-1);
}
.switch-desc {
  font-size: 11.5px;
  color: var(--text-3);
  margin-top: 2px;
  line-height: 1.45;
}
.switch {
  position: relative;
  display: inline-block;
  width: 36px;
  height: 20px;
  flex-shrink: 0;
}
.switch input { opacity: 0; width: 0; height: 0; position: absolute; }
.switch-track {
  position: absolute;
  inset: 0;
  cursor: pointer;
  background: var(--bg-3);
  border: 1px solid var(--border-1);
  border-radius: 100px;
  transition: all 0.18s;
}
.switch-track::before {
  content: "";
  position: absolute;
  height: 14px;
  width: 14px;
  left: 2px;
  top: 50%;
  transform: translateY(-50%);
  background: var(--text-3);
  border-radius: 50%;
  transition: all 0.18s;
}
.switch input:checked + .switch-track {
  background: var(--accent);
  border-color: var(--accent);
}
.switch input:checked + .switch-track::before {
  transform: translate(16px, -50%);
  background: #04160a;
}
.switch input:disabled + .switch-track { opacity: 0.4; cursor: not-allowed; }

.hint-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 12px;
  font-size: 11.5px;
  border-radius: var(--r-sm);
  line-height: 1.4;
  margin-top: 4px;
}
.hint-row.ok {
  background: rgba(34, 197, 94, 0.06);
  border: 1px solid rgba(34, 197, 94, 0.18);
  color: var(--accent-hi);
}
.hint-row.info {
  background: rgba(59, 130, 246, 0.06);
  border: 1px solid rgba(59, 130, 246, 0.18);
  color: #60a5fa;
}
.link {
  background: transparent;
  border: none;
  color: inherit;
  font-family: inherit;
  font-size: 11.5px;
  cursor: pointer;
  text-decoration: underline;
  text-underline-offset: 3px;
  opacity: 0.85;
  padding: 0;
}
.link:hover:not(:disabled) { opacity: 1; }
.link:disabled { opacity: 0.4; cursor: not-allowed; }

/* Logs */
.log-card {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 200px;
}
.log-head-left {
  display: flex;
  align-items: center;
  gap: 9px;
}
.live-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--text-4);
  transition: all 0.2s;
}
.live-dot.on {
  background: var(--accent);
  box-shadow: 0 0 6px rgba(34, 197, 94, 0.75);
}
.log-count {
  font-size: 10.5px;
  padding: 1px 7px;
  background: var(--bg-2);
  border: 1px solid var(--border-1);
  border-radius: 100px;
  color: var(--text-3);
  font-variant-numeric: tabular-nums;
  font-weight: 500;
}
.seg {
  display: flex;
  gap: 0;
  padding: 2px;
  background: var(--bg-2);
  border: 1px solid var(--border-1);
  border-radius: var(--r-sm);
  margin-right: 4px;
}
.seg button {
  padding: 3px 10px;
  background: transparent;
  border: none;
  color: var(--text-3);
  font-family: inherit;
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
  border-radius: 4px;
  transition: all 0.15s;
}
.seg button:hover { color: var(--text-2); }
.seg button.on {
  background: var(--bg-3);
  color: var(--text-1);
}

.log-view {
  flex: 1;
  overflow-y: auto;
  padding: 12px 18px;
  font-family: 'JetBrains Mono', 'SF Mono', 'Consolas', monospace;
  font-size: 11.5px;
  line-height: 1.7;
  min-height: 0;
  background: var(--bg-1);
}
.log-view::-webkit-scrollbar { width: 6px; }
.log-view::-webkit-scrollbar-thumb { background: var(--border-1); border-radius: 6px; }
.log-line { display: flex; gap: 14px; padding: 1px 0; }
.log-t {
  color: var(--text-4);
  flex-shrink: 0;
  user-select: none;
  letter-spacing: 0;
}
.log-m {
  color: var(--text-2);
  word-break: break-word;
  white-space: pre-wrap;
}
.log-line.success .log-m { color: #4ade80; }
.log-line.warn .log-m { color: #fbbf24; }
.log-line.error .log-m { color: #f87171; }
.log-none {
  padding: 40px 0;
  text-align: center;
  color: var(--text-4);
  font-size: 11.5px;
  font-style: italic;
}

/* Toast */
.toast {
  position: fixed;
  bottom: 22px;
  left: 50%;
  transform: translateX(-50%);
  padding: 10px 18px;
  border-radius: var(--r-md);
  font-size: 12px;
  font-weight: 500;
  z-index: 10000;
  pointer-events: none;
  max-width: 80vw;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  border: 1px solid;
  box-shadow: 0 12px 40px -12px rgba(0, 0, 0, 0.8);
}
.toast.success {
  background: #0a1a0f;
  border-color: rgba(34, 197, 94, 0.35);
  color: #4ade80;
}
.toast.error {
  background: #1c0a0a;
  border-color: rgba(239, 68, 68, 0.35);
  color: #f87171;
}
.toast-enter-active, .toast-leave-active { transition: all 0.22s cubic-bezier(0.4, 0, 0.2, 1); }
.toast-enter-from { opacity: 0; transform: translateX(-50%) translateY(12px); }
.toast-leave-to { opacity: 0; transform: translateX(-50%) translateY(-6px); }

/* Modal */
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.72);
  z-index: 9999;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.modal {
  position: relative;
  background: var(--bg-1);
  border: 1px solid var(--border-1);
  border-radius: var(--r-lg);
  width: 100%;
  max-width: 380px;
  box-shadow: 0 24px 60px -12px rgba(0, 0, 0, 0.85);
}
.modal-head {
  padding: 16px 20px 12px;
  border-bottom: 1px solid var(--border);
}
.modal-head h3 {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-1);
  letter-spacing: -0.01em;
}
.modal-body { padding: 18px 20px; }
.confirm-text {
  font-size: 12.5px;
  color: var(--text-2);
  line-height: 1.6;
  white-space: pre-wrap;
}
.modal-foot {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding: 12px 20px;
  border-top: 1px solid var(--border);
}
.btn-primary.danger {
  background: var(--err);
  border-color: var(--err);
  color: #fff;
}
.btn-primary.danger:hover:not(:disabled) {
  background: #dc2626;
  border-color: #dc2626;
}

/* About */
.modal-about {
  max-width: 320px;
  padding: 32px 24px 20px;
  text-align: center;
}
.modal-x {
  position: absolute;
  top: 10px; right: 10px;
  width: 26px; height: 26px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  border-radius: var(--r-sm);
  color: var(--text-3);
  cursor: pointer;
  transition: all 0.12s;
}
.modal-x:hover { background: var(--bg-2); color: var(--text-1); }
.modal-x svg { width: 12px; height: 12px; }
.about-avatar {
  width: 72px; height: 72px;
  margin: 0 auto 14px;
  border-radius: var(--r-lg);
  overflow: hidden;
  border: 1px solid var(--border-1);
}
.about-avatar img {
  width: 100%; height: 100%;
  display: block;
  object-fit: cover;
  -webkit-user-drag: none;
}
.about-name {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-1);
}
.about-role {
  font-size: 11.5px;
  color: var(--text-3);
  margin-top: 3px;
}
.about-links {
  margin-top: 22px;
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border);
  border-radius: var(--r-md);
  overflow: hidden;
}
.about-link {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 11px 14px;
  background: var(--bg-2);
  cursor: pointer;
  text-decoration: none;
  transition: background 0.12s;
  border-bottom: 1px solid var(--border);
}
.about-link:last-child { border-bottom: none; }
.about-link:hover { background: var(--bg-3); }
.about-link-label {
  font-size: 12.5px;
  font-weight: 500;
  color: var(--text-1);
}
.about-link-value {
  font-size: 11px;
  color: var(--text-3);
  font-family: 'JetBrains Mono', monospace;
}
.about-ver {
  margin-top: 20px;
  font-size: 10.5px;
  color: var(--text-4);
  font-family: 'JetBrains Mono', monospace;
  letter-spacing: 0.05em;
}
.modal-enter-active, .modal-leave-active { transition: opacity 0.2s; }
.modal-enter-from, .modal-leave-to { opacity: 0; }

/* Animations */
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

/* Responsive */
@media (max-width: 900px) {
  .app-body { grid-template-columns: 1fr; }
  .sidebar {
    border-right: none;
    border-bottom: 1px solid var(--border);
    max-height: 200px;
  }
  .form-grid { grid-template-columns: 1fr 80px 1fr; }
  .hero-stats { grid-template-columns: repeat(2, 1fr); }
  .hero-cell:nth-child(2) { border-right: none; }
}
@media (max-width: 640px) {
  .topbar { padding: 0 14px; }
  .main { padding: 16px; }
  .form-grid { grid-template-columns: 1fr; }
  .hero-cell { padding: 0 10px; }
  .seg { display: none; }
}
</style>