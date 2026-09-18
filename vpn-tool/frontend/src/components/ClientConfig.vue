<template>
  <div class="client-config">
    <div class="form-row">
      <div class="field">
        <label>服务器 IP</label>
        <input v-model="cfg.ip" placeholder="127.0.0.1" />
      </div>
      <div class="field">
        <label>端口</label>
        <input v-model.number="cfg.port" type="number" placeholder="8443" />
      </div>
    </div>
    <div class="form-row">
      <div class="field">
        <label>用户名</label>
        <input v-model="cfg.username" placeholder="用户名" />
      </div>
      <div class="field">
        <label>密码</label>
        <input v-model="cfg.password" type="password" placeholder="密码" />
      </div>
    </div>
    <div class="form-actions">
      <button v-if="!connected" @click="connect" :disabled="loading" class="btn-connect">
        {{ loading ? '连接中...' : '连接' }}
      </button>
      <button v-else @click="disconnect" class="btn-disconnect">
        断开
      </button>
    </div>
    <div v-if="status" class="status-message">{{ status }}</div>
  </div>
</template>

<script>
import { ConnectClient, Stop } from '../../wailsjs/go/main/App'

export default {
  name: 'ClientConfig',
  data() {
    return {
      cfg: { ip: '127.0.0.1', port: 8443, username: 'client', password: 'test123' },
      status: '',
      loading: false,
      connected: false
    }
  },
  methods: {
    async connect() {
      if (this.loading) return
      this.loading = true
      this.status = '连接中...'
      try {
        const ip = await ConnectClient(this.cfg)
        this.status = `✅ 连接成功，IP: ${ip}`
        this.connected = true
        this.$emit('log', `连接成功，IP: ${ip}`)
        this.$emit('connected', ip)
        this.$emit('server-info', { ip: this.cfg.ip, port: this.cfg.port, username: this.cfg.username })
      } catch (e) {
        this.status = '❌ ' + e.message
        this.$emit('log', '错误: ' + e.message)
      } finally {
        this.loading = false
      }
    },
    async disconnect() {
      try {
        await Stop()
        this.status = '已断开'
        this.connected = false
        this.$emit('log', '已断开')
        this.$emit('disconnected')
      } catch (e) {
        this.status = '断开失败: ' + e.message
        this.$emit('log', '断开失败: ' + e.message)
      }
    }
  }
}
</script>

<style scoped>
.client-config {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.form-row {
  display: flex;
  gap: 16px;
}
.form-row .field {
  flex: 1;
}
.field label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  color: #94a3b8;
  margin-bottom: 4px;
}
.field input {
  width: 100%;
  padding: 8px 12px;
  background: rgba(255,255,255,0.06);
  border: 1px solid rgba(255,255,255,0.08);
  border-radius: 10px;
  color: #e2e8f0;
  font-size: 14px;
  transition: 0.2s;
}
.field input:focus {
  outline: none;
  border-color: #6c8cff;
  background: rgba(255,255,255,0.08);
  box-shadow: 0 0 0 3px rgba(108, 140, 255, 0.15);
}
.field input::placeholder {
  color: #475569;
}
.form-actions {
  display: flex;
  gap: 12px;
  margin-top: 4px;
}
.btn-connect, .btn-disconnect {
  flex: 1;
  padding: 10px;
  border: none;
  border-radius: 10px;
  font-weight: 600;
  font-size: 15px;
  cursor: pointer;
  transition: 0.2s;
}
.btn-connect {
  background: linear-gradient(135deg, #6c8cff, #a78bfa);
  color: white;
}
.btn-connect:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 16px rgba(108, 140, 255, 0.3);
}
.btn-connect:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
}
.btn-disconnect {
  background: linear-gradient(135deg, #f87171, #ef4444);
  color: white;
}
.btn-disconnect:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 16px rgba(239, 68, 68, 0.3);
}
.status-message {
  margin-top: 8px;
  font-size: 14px;
  padding: 6px 12px;
  border-radius: 8px;
  background: rgba(255,255,255,0.04);
  color: #cbd5e1;
  word-break: break-all;
}
</style>