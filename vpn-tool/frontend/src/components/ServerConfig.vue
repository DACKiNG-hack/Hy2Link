<template>
  <div class="server-config">
    <h2>🖥️ 服务端配置</h2>
    <form @submit.prevent="handleStart">
      <div class="form-group">
        <label>监听端口</label>
        <input v-model.number="cfg.listenPort" type="number" placeholder="8443" required />
      </div>
      <div class="form-group">
        <label>密码</label>
        <input v-model="cfg.password" type="password" placeholder="设置密码" required />
      </div>
      <div class="button-group">
        <button type="submit" class="btn btn-start">▶️ 启动服务端</button>
        <button type="button" class="btn btn-stop" @click="stopServer">⏹ 停止服务端</button>
      </div>
    </form>
    <div class="status" v-if="status">{{ status }}</div>
  </div>
</template>

<script>
import { StartServer, Stop } from '../../wailsjs/go/main/App'

export default {
  name: 'ServerConfig',
  data() {
    return {
      cfg: {
        listenIP: '0.0.0.0',
        listenPort: 8443,
        username: '',
        password: 'test123'
      },
      status: ''
    }
  },
  methods: {
    async handleStart() {
      try {
        const result = await StartServer(this.cfg)
        this.status = result
        this.$emit('log', `[服务端] ${result}`)
      } catch (err) {
        this.status = '错误: ' + err.message
        this.$emit('log', `[服务端错误] ${err.message}`)
      }
    },
    async stopServer() {
      try {
        await Stop()
        this.status = '服务端已停止'
        this.$emit('log', '[服务端] 已停止')
      } catch (err) {
        this.status = '停止失败: ' + err.message
      }
    }
  }
}
</script>

<style scoped>
.server-config h2 {
  font-size: 1.3rem;
  margin-bottom: 16px;
  color: #27ae60;
}
.form-group {
  margin-bottom: 14px;
}
.form-group label {
  display: block;
  font-weight: 500;
  margin-bottom: 4px;
  font-size: 0.9rem;
  color: #555;
}
.form-group input {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid #d0d7de;
  border-radius: 6px;
  font-size: 0.95rem;
  transition: 0.2s;
}
.form-group input:focus {
  outline: none;
  border-color: #2ecc71;
  box-shadow: 0 0 0 3px rgba(46,204,113,0.2);
}
.button-group {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-top: 6px;
}
.btn {
  padding: 8px 18px;
  border: none;
  border-radius: 6px;
  font-weight: 600;
  font-size: 0.95rem;
  cursor: pointer;
  transition: 0.2s;
  flex: 1 1 auto;
}
.btn-start {
  background: #2ecc71;
  color: white;
}
.btn-start:hover {
  background: #27ae60;
}
.btn-stop {
  background: #e74c3c;
  color: white;
}
.btn-stop:hover {
  background: #c0392b;
}
.status {
  margin-top: 12px;
  padding: 8px 12px;
  background: #ecf0f1;
  border-radius: 6px;
  font-size: 0.9rem;
  word-break: break-all;
}
</style>