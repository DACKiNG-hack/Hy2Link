// vpn-server/admin/static/javascript.js
const { createApp, ref, onMounted, onUnmounted, watch, nextTick } = Vue;
const { createI18n, useI18n } = VueI18n;

// ⭐ 初始化 i18n
const savedLang = localStorage.getItem('admin_lang');
const initialLang = (window.HY2LINK_LANGUAGES || []).find(l => l.code === savedLang)
    ? savedLang : 'zh-CN';

const i18n = createI18n({
    legacy: false,
    globalInjection: true,
    locale: initialLang,
    fallbackLocale: 'en',
    messages: window.HY2LINK_MESSAGES,
});
document.documentElement.setAttribute('lang', initialLang);

const app = createApp({
    setup() {
        const { t, locale } = useI18n({ useScope: 'global' });

        // ⭐ 语言切换（内联）
        const languages = window.HY2LINK_LANGUAGES || [];
        const langOpen = ref(false);
        const currentLangLabel = ref('');

        function refreshLangLabel() {
            const l = languages.find(x => x.code === locale.value);
            currentLangLabel.value = l ? l.label : locale.value;
        }

        function changeLang(code) {
            locale.value = code;
            localStorage.setItem('admin_lang', code);
            document.documentElement.setAttribute('lang', code);
            refreshLangLabel();
            langOpen.value = false;
        }

        refreshLangLabel();
        watch(locale, (v) => {
            document.documentElement.setAttribute('lang', v);
            refreshLangLabel();
        });

        // ⭐ 初始化状态
        const initChecked = ref(false);
        const initialized = ref(true);
        const setupForm = ref({ username: '', password: '', confirm: '' });
        const setupMsg = ref('');
        const setupOk = ref(false);
        const setupBusy = ref(false);

        const token = ref(localStorage.getItem('admin_token') || '');
        const currentUser = ref(localStorage.getItem('admin_user') || '');
        const version = ref('0.0.0');
        const loginForm = ref({ username: '', password: '' });
        const loginMsg = ref('');
        const loginOk = ref(false);
        const logging = ref(false);

        const tab = ref('server');
        const clients = ref([]);
        const users = ref([]);
        const editUser = ref(null);
        const busy = ref(false);
        const pwdForm = ref({ oldPassword: '', newPassword: '', confirmPassword: '' });

        const server = ref({ running: false, config: {} });
        const cfg = ref({});
        const dirty = ref(false);
        let suppressDirty = false;

        const geo = ref({ mode: 'off', countries: [], blockPrivate: false });
        const geoCountriesInput = ref('');
        const geoSaving = ref(false);

        const perf = ref({
            lowPerformanceMode: false,
            logEnabled: true,
            highPriority: false,
        });
        const perfSaving = ref(false);

        const certInfo = ref(null);
        const certStatusError = ref('');
        const certCfg = ref({});
        const certDirty = ref(false);
        const certBusy = ref(false);
        let certSuppressDirty = false;

        const onlineChart = ref(null);
        const trafficChart = ref(null);
        let onlineChartInst = null;
        let trafficChartInst = null;

        let es = null;
        let metricsTicker = null;

        const DEFAULT_UDP_RELIABLE_PORTS = ['42300-42800'];
        const DEFAULT_UDP_UNRELIABLE_PORTS = ['50000-50550'];

        // ⭐ 生成随机混淆密码（32 字节 base62）
        function generateObfsPassword() {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            const len = 32;
            const arr = new Uint8Array(len);
            crypto.getRandomValues(arr);
            let out = '';
            for (let i = 0; i < len; i++) {
                out += chars[arr[i] % chars.length];
            }
            if (!cfg.value) cfg.value = {};
            cfg.value.obfsPassword = out;
            dirty.value = true;
        }

        async function api(path, opts = {}) {
            opts.headers = Object.assign({
                'Authorization': 'Bearer ' + token.value,
                'Content-Type': 'application/json',
            }, opts.headers || {});
            const r = await fetch(path, opts);
            if (r.status === 401) {
                doLogout(true);
                throw new Error(t('login.sessionExpired'));
            }
            if (!r.ok) {
                const txt = await r.text();
                try {
                    const j = JSON.parse(txt);
                    throw new Error(j.error || txt);
                } catch (e) {
                    if (e.message) throw e;
                    throw new Error(txt || ('HTTP ' + r.status));
                }
            }
            const ct = r.headers.get('content-type') || '';
            return ct.includes('json') ? r.json() : null;
        }

        async function checkInitStatus() {
            try {
                const r = await fetch('/api/init-status');
                const data = await r.json().catch(() => ({}));
                initialized.value = !!data.initialized;
            } catch (e) {
                initialized.value = true;
            } finally {
                initChecked.value = true;
            }
        }

        async function doSetup() {
            const f = setupForm.value;
            const u = (f.username || '').trim();
            const p = f.password || '';
            const c = f.confirm || '';

            if (u.length < 3) { setupOk.value = false; setupMsg.value = t('init.usernameShort'); return; }
            if (p.length < 6) { setupOk.value = false; setupMsg.value = t('init.passwordShort'); return; }
            if (p !== c) { setupOk.value = false; setupMsg.value = t('init.passwordMismatch'); return; }

            setupBusy.value = true;
            setupMsg.value = '';
            try {
                const r = await fetch('/api/setup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: u, password: p }),
                });
                const data = await r.json().catch(() => ({}));
                if (!r.ok) {
                    setupOk.value = false;
                    setupMsg.value = data.error || t('init.createFailed');
                    return;
                }
                setupOk.value = true;
                setupMsg.value = t('init.createSuccess');
                initialized.value = true;
                loginForm.value.username = u;
                loginForm.value.password = '';
            } catch (e) {
                setupOk.value = false;
                setupMsg.value = t('init.connFailed') + '：' + e.message;
            } finally {
                setupBusy.value = false;
            }
        }

        async function login() {
            const u = loginForm.value.username.trim();
            const p = loginForm.value.password;
            if (!u || !p) { loginMsg.value = t('login.empty'); loginOk.value = false; return; }
            logging.value = true;
            try {
                const r = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: u, password: p }),
                });
                const data = await r.json().catch(() => ({}));
                if (!r.ok) {
                    loginOk.value = false;
                    loginMsg.value = data.error || t('login.failed');
                    return;
                }
                localStorage.setItem('admin_token', data.token);
                localStorage.setItem('admin_user', data.username);
                token.value = data.token;
                currentUser.value = data.username;
                loginOk.value = true;
                loginMsg.value = t('login.success');
                loginForm.value.password = '';
                await bootstrap();
            } catch (e) {
                loginOk.value = false;
                loginMsg.value = t('init.connFailed') + '：' + e.message;
            } finally {
                logging.value = false;
            }
        }

        async function doLogout(silent = false) {
            if (es) { es.close(); es = null; }
            if (metricsTicker) { clearInterval(metricsTicker); metricsTicker = null; }
            if (onlineChartInst) { onlineChartInst.destroy(); onlineChartInst = null; }
            if (trafficChartInst) { trafficChartInst.destroy(); trafficChartInst = null; }
            const oldToken = token.value;
            localStorage.removeItem('admin_token');
            localStorage.removeItem('admin_user');
            token.value = '';
            currentUser.value = '';
            server.value = { running: false, config: {} };
            cfg.value = {};
            clients.value = [];
            users.value = [];
            dirty.value = false;
            if (!silent && oldToken) {
                fetch('/api/logout', { method: 'POST', headers: { 'Authorization': 'Bearer ' + oldToken } }).catch(() => {});
            }
        }

        function logout() { doLogout(false); }

        function openExternal(url) {
            if (window.runtime && window.runtime.BrowserOpenURL) {
                window.runtime.BrowserOpenURL(url);
            } else {
                window.open(url, '_blank', 'noopener,noreferrer');
            }
        }

        async function bootstrap() {
            await loadServer();
            await syncCfg(true);
            await loadUsers();
            await loadGeo();
            await loadPerformance();
            await loadMetrics();
            connectSSE();
        }

        async function loadServer() {
            try {
                const s = await api('/api/server/status');
                server.value = s;
            } catch (e) { console.warn(e); }
        }

        async function syncCfg(force = false) {
            if (dirty.value && !force) return;
            try {
                const c = await api('/api/server/config');
                suppressDirty = true;

                const cfgCopy = { ...c };

                cfgCopy.tcpSplitPortsInput = (c.tcpSplitPorts || [22345, 443]).join(', ');

                cfgCopy.udpReliablePortsInput =
                    (Array.isArray(c.udpReliablePorts) && c.udpReliablePorts.length > 0
                            ? c.udpReliablePorts
                            : DEFAULT_UDP_RELIABLE_PORTS
                    ).join(', ');

                cfgCopy.udpUnreliablePortsInput =
                    (Array.isArray(c.udpUnreliablePorts) && c.udpUnreliablePorts.length > 0
                            ? c.udpUnreliablePorts
                            : DEFAULT_UDP_UNRELIABLE_PORTS
                    ).join(', ');

                cfgCopy.obfsEnabled = !!c.obfsEnabled;
                cfgCopy.obfsPassword = c.obfsPassword || '';

                cfg.value = cfgCopy;
                dirty.value = false;
                setTimeout(() => { suppressDirty = false; }, 0);
            } catch (e) { suppressDirty = false; console.warn(e); }
        }

        async function resetConfig() {
            if (!confirm(t('config.resetConfirm'))) return;
            await syncCfg(true);
        }

        async function loadUsers() {
            try { users.value = await api('/api/users'); } catch (e) { console.warn(e); }
        }

        async function loadGeo() {
            try {
                const r = await api('/api/panel/geo');
                geo.value = {
                    mode: r.mode || 'off',
                    countries: r.countries || [],
                    blockPrivate: !!r.blockPrivate,
                };
                geoCountriesInput.value = (r.countries || []).join(', ');
            } catch (e) { console.warn(e); }
        }

        async function saveGeo() {
            const countries = (geoCountriesInput.value || '')
                .split(/[,\s]+/)
                .map(s => s.trim().toUpperCase())
                .filter(s => s.length > 0);

            if (geo.value.mode !== 'off' && countries.length === 0) {
                alert(t('settings.geoNeedCountry'));
                return;
            }
            for (const code of countries) {
                if (code.length !== 2) {
                    alert(t('settings.geoInvalidCode', { code }));
                    return;
                }
            }

            geoSaving.value = true;
            try {
                await api('/api/panel/geo', {
                    method: 'PUT',
                    body: JSON.stringify({
                        mode: geo.value.mode,
                        countries: countries,
                        blockPrivate: geo.value.blockPrivate,
                    }),
                });
                alert(t('settings.geoSaved'));
                await loadGeo();
            } catch (e) {
                alert(t('settings.geoSaveFail') + '：' + e.message);
            } finally {
                geoSaving.value = false;
            }
        }

        async function loadPerformance() {
            try {
                const r = await api('/api/panel/performance');
                perf.value = {
                    lowPerformanceMode: !!r.lowPerformanceMode,
                    logEnabled: r.logEnabled !== false,
                    highPriority: !!r.highPriority,
                };
            } catch (e) { console.warn(e); }
        }

        async function savePerformance() {
            perfSaving.value = true;
            try {
                await api('/api/panel/performance', {
                    method: 'PUT',
                    body: JSON.stringify({
                        lowPerformanceMode: perf.value.lowPerformanceMode,
                        logEnabled: perf.value.logEnabled,
                        highPriority: perf.value.highPriority,
                    }),
                });
                alert(t('settings.perfSaved'));
            } catch (e) {
                alert(t('settings.saveFail') + '：' + e.message);
            } finally {
                perfSaving.value = false;
            }
        }

        async function loadCertStatus() {
            try {
                const r = await api('/api/cert/status');
                if (r.ok) {
                    certInfo.value = r.info;
                    certStatusError.value = '';
                } else {
                    certInfo.value = null;
                    certStatusError.value = r.error || t('cert.notLoaded');
                }
            } catch (e) {
                certStatusError.value = e.message;
            }
        }

        async function loadCertConfig() {
            try {
                const c = await api('/api/cert/config');
                certSuppressDirty = true;
                certCfg.value = { ...c };
                certDirty.value = false;
                setTimeout(() => { certSuppressDirty = false; }, 0);
            } catch (e) { console.warn(e); }
        }

        async function saveCertConfig() {
            certBusy.value = true;
            try {
                await api('/api/cert/config', {
                    method: 'PUT',
                    body: JSON.stringify(certCfg.value),
                });
                alert(t('cert.saveOk'));
                await loadCertConfig();
                await loadCertStatus();
            } catch (e) { alert(t('cert.saveFail') + '：' + e.message); }
            finally { certBusy.value = false; }
        }

        async function regenerateCert() {
            if (!confirm(t('cert.regenConfirm'))) return;
            certBusy.value = true;
            try {
                await api('/api/cert/regenerate', { method: 'POST' });
                alert(t('cert.regenOk'));
                await loadCertStatus();
            } catch (e) { alert(t('cert.regenFail') + '：' + e.message); }
            finally { certBusy.value = false; }
        }

        function copyFingerprint() {
            if (!certInfo.value || !certInfo.value.fingerprint) return;
            navigator.clipboard.writeText(certInfo.value.fingerprint).then(() => {
                alert(t('cert.copyOk'));
            }).catch(() => {
                alert(t('cert.copyFail'));
            });
        }

        async function loadMetrics() {
            try {
                const data = await api('/api/metrics');
                updateCharts(data || []);
            } catch (e) {
                console.warn('metrics error', e);
            }
        }

        function updateCharts(data) {
            if (!onlineChart.value && !trafficChart.value) return;

            const labels = data.map(d => {
                const t2 = new Date(d.time * 1000);
                return `${String(t2.getHours()).padStart(2, '0')}:${String(t2.getMinutes()).padStart(2, '0')}`;
            });
            const onlineData = data.map(d => d.online);
            const trafficIn = data.map(d => d.totalIn / 1024 / 1024);
            const trafficOut = data.map(d => d.totalOut / 1024 / 1024);

            const gridColor = 'rgba(255, 255, 255, 0.055)';
            const tickColor = '#94a3b8';
            const colorAccent = '#22d3ee';
            const colorAccent2 = '#8b5cf6';

            if (!onlineChartInst && onlineChart.value) {
                onlineChartInst = new Chart(onlineChart.value, {
                    type: 'line',
                    data: {
                        labels,
                        datasets: [{
                            label: t('monitor.onlineChart'),
                            data: onlineData,
                            borderColor: colorAccent,
                            backgroundColor: 'rgba(34, 211, 238, 0.12)',
                            tension: 0.3,
                            fill: true,
                            pointRadius: 0,
                            borderWidth: 2,
                        }],
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { grid: { color: gridColor }, ticks: { color: tickColor, maxTicksLimit: 8 } },
                            y: { grid: { color: gridColor }, ticks: { color: tickColor, precision: 0 }, beginAtZero: true },
                        },
                    },
                });
            } else if (onlineChartInst) {
                onlineChartInst.data.labels = labels;
                onlineChartInst.data.datasets[0].data = onlineData;
                onlineChartInst.data.datasets[0].label = t('monitor.onlineChart');
                onlineChartInst.update('none');
            }

            if (!trafficChartInst && trafficChart.value) {
                trafficChartInst = new Chart(trafficChart.value, {
                    type: 'line',
                    data: {
                        labels,
                        datasets: [
                            {
                                label: t('monitor.upLabel'),
                                data: trafficIn,
                                borderColor: colorAccent,
                                backgroundColor: 'rgba(34, 211, 238, 0.08)',
                                tension: 0.3,
                                pointRadius: 0,
                                borderWidth: 2,
                            },
                            {
                                label: t('monitor.downLabel'),
                                data: trafficOut,
                                borderColor: colorAccent2,
                                backgroundColor: 'rgba(139, 92, 246, 0.08)',
                                tension: 0.3,
                                pointRadius: 0,
                                borderWidth: 2,
                            },
                        ],
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: { color: tickColor, boxWidth: 12, padding: 12 },
                            },
                        },
                        scales: {
                            x: { grid: { color: gridColor }, ticks: { color: tickColor, maxTicksLimit: 8 } },
                            y: { grid: { color: gridColor }, ticks: { color: tickColor }, beginAtZero: true },
                        },
                    },
                });
            } else if (trafficChartInst) {
                trafficChartInst.data.labels = labels;
                trafficChartInst.data.datasets[0].data = trafficIn;
                trafficChartInst.data.datasets[1].data = trafficOut;
                trafficChartInst.data.datasets[0].label = t('monitor.upLabel');
                trafficChartInst.data.datasets[1].label = t('monitor.downLabel');
                trafficChartInst.update('none');
            }
        }

        function connectSSE() {
            if (es) es.close();
            es = new EventSource('/api/events?token=' + encodeURIComponent(token.value));
            es.onmessage = (ev) => {
                try {
                    const d = JSON.parse(ev.data);
                    if (d.clients) clients.value = d.clients;
                    if (d.server) server.value = d.server;
                } catch (e) {}
            };
            es.onerror = () => console.warn('SSE error, will retry');
        }

        async function startServer() {
            busy.value = true;
            try {
                await api('/api/server/start', { method: 'POST' });
                await loadServer(); await syncCfg(true);
                await loadCertStatus();
            } catch (e) { alert(t('server.startFail') + '：' + e.message); }
            finally { busy.value = false; }
        }
        async function stopServer() {
            if (!confirm(t('server.stopConfirm'))) return;
            busy.value = true;
            try {
                await api('/api/server/stop', { method: 'POST' });
                await loadServer(); await syncCfg(true);
            } catch (e) { alert(t('server.stopFail') + '：' + e.message); }
            finally { busy.value = false; }
        }
        async function restartServer() {
            if (!confirm(t('server.restartConfirm'))) return;
            busy.value = true;
            try {
                await api('/api/server/restart', { method: 'POST' });
                await loadServer(); await syncCfg(true);
                await loadCertStatus();
            } catch (e) { alert(t('server.restartFail') + '：' + e.message); }
            finally { busy.value = false; }
        }

        function validatePortRanges(raw, label) {
            const items = (raw || '').trim().split(/[,\s]+/).map(s => s.trim()).filter(s => s.length > 0);
            for (const item of items) {
                const m = item.match(/^(\d+)(?:\s*-\s*(\d+))?$/);
                if (!m) {
                    alert(t('config.errRangeFormat', { label, item }));
                    return null;
                }
                const lo = parseInt(m[1], 10);
                const hi = m[2] ? parseInt(m[2], 10) : lo;
                if (lo < 1 || lo > 65535 || hi < 1 || hi > 65535) {
                    alert(t('config.errRangeOOR', { label, item }));
                    return null;
                }
                if (lo > hi) {
                    alert(t('config.errRangeOrder', { label, item }));
                    return null;
                }
            }
            return items;
        }

        async function saveConfig() {
            const c = cfg.value;
            if (!c.port || c.port < 1 || c.port > 65535) { alert(t('config.errPort')); return; }
            if (!c.ipPoolStart || !c.ipPoolEnd) { alert(t('config.errIp')); return; }
            if (!c.subnetMask) { alert(t('config.errMask')); return; }
            if (c.serverTunEnabled) {
                if (!c.serverTunIP || !c.serverTunMask) {
                    alert(t('config.errTun'));
                    return;
                }
            }

            const tcpPortsRaw = (c.tcpSplitPortsInput || '').trim();
            const tcpPorts = tcpPortsRaw
                .split(/[,\s]+/)
                .map(s => parseInt(s, 10))
                .filter(n => !isNaN(n) && n > 0 && n <= 65535);
            if (c.tcpSplitEnabled && tcpPorts.length === 0) {
                alert(t('config.errTcp'));
                return;
            }
            const tcpPortsUnique = [...new Set(tcpPorts)];

            const udpRelRanges = validatePortRanges(c.udpReliablePortsInput, t('config.udpReliablePorts'));
            if (udpRelRanges === null) return;
            if (c.udpReliableEnabled && udpRelRanges.length === 0) {
                alert(t('config.errUdpRel'));
                return;
            }

            const udpUnrelRanges = validatePortRanges(c.udpUnreliablePortsInput, t('config.udpUnreliablePorts'));
            if (udpUnrelRanges === null) return;
            if (c.udpUnreliableEnabled && udpUnrelRanges.length === 0) {
                alert(t('config.errUdpUnrel'));
                return;
            }

            if (c.obfsEnabled) {
                const psk = (c.obfsPassword || '').trim();
                if (psk.length < 4) {
                    alert(t('config.errObfs', { len: psk.length }));
                    return;
                }
            }

            const body = { ...c };
            delete body.tcpSplitPortsInput;
            delete body.udpReliablePortsInput;
            delete body.udpUnreliablePortsInput;
            body.tcpSplitPorts = tcpPortsUnique;
            body.udpReliablePorts = udpRelRanges;
            body.udpUnreliablePorts = udpUnrelRanges;

            busy.value = true;
            try {
                await api('/api/server/config', { method: 'PUT', body: JSON.stringify(body) });
                alert(t('config.saveOk'));
                await loadServer(); await syncCfg(true);
            } catch (e) { alert(t('config.saveFail') + '：' + e.message); }
            finally { busy.value = false; }
        }

        function openCreateUser() {
            editUser.value = { creating: true, username: '', password: '', maxGB: 0, expireAt: '', note: '', enabled: true };
        }
        function openEditUser(u) {
            editUser.value = {
                creating: false, username: u.username, password: '',
                maxGB: u.maxBytes ? Math.round(u.maxBytes / (1024**3) * 100) / 100 : 0,
                expireAt: u.expireAt && u.expireAt !== '0001-01-01T00:00:00Z' ? toLocalDatetime(u.expireAt) : '',
                note: u.note || '', enabled: u.enabled,
            };
        }
        function toLocalDatetime(iso) {
            const d = new Date(iso); const pad = n => String(n).padStart(2, '0');
            return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        }
        async function saveUser() {
            const u = editUser.value;
            if (u.creating && (!u.username || !u.password)) { alert(t('users.saveEmpty')); return; }
            const body = {
                username: u.username, password: u.password, enabled: u.enabled,
                maxBytes: Math.round((u.maxGB || 0) * (1024**3)),
                expireAt: u.expireAt ? new Date(u.expireAt).toISOString() : '0001-01-01T00:00:00Z',
                note: u.note || '',
            };
            try {
                if (u.creating) await api('/api/users', { method: 'POST', body: JSON.stringify(body) });
                else await api('/api/users/' + encodeURIComponent(u.username), { method: 'PUT', body: JSON.stringify(body) });
                editUser.value = null; await loadUsers();
            } catch (e) { alert(t('users.saveFail') + '：' + e.message); }
        }
        async function deleteUser(u) {
            if (!confirm(t('users.deleteConfirm', { name: u.username }))) return;
            try { await api('/api/users/' + encodeURIComponent(u.username), { method: 'DELETE' }); await loadUsers(); }
            catch (e) { alert(t('users.deleteFail') + '：' + e.message); }
        }
        // ⭐ 一个账号可以被多个客户端共用，因此按 VIP 精确踢出单个连接；
        //    vip 为空时退回「踢掉该账号的全部连接」。
        async function kick(username, vip) {
            const label = vip ? `${username}（${vip}）` : username;
            if (!confirm(t('clients.kickConfirm', { name: label }))) return;
            let url = '/api/clients/kick?username=' + encodeURIComponent(username || '');
            if (vip) url += '&vip=' + encodeURIComponent(vip);
            try { await api(url, { method: 'POST' }); }
            catch (e) { alert(t('clients.kickFail') + '：' + e.message); }
        }
        async function changePassword() {
            const f = pwdForm.value;
            if (!f.oldPassword || !f.newPassword) { alert(t('settings.pwdEmpty')); return; }
            if (f.newPassword.length < 6) { alert(t('settings.pwdTooShort')); return; }
            if (f.newPassword !== f.confirmPassword) { alert(t('settings.pwdMismatch')); return; }
            try {
                await api('/api/change-password', {
                    method: 'POST',
                    body: JSON.stringify({ oldPassword: f.oldPassword, newPassword: f.newPassword }),
                });
                alert(t('settings.pwdChanged'));
                doLogout(false);
            } catch (e) { alert(t('settings.pwdChangeFail') + '：' + e.message); }
        }

        function formatBytes(n) {
            if (!n) return '0 B';
            const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
            while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
            return n.toFixed(i === 0 ? 0 : 2) + ' ' + u[i];
        }
        function formatUptime(s) {
            if (!s) return '—';
            const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
            if (d > 0) return `${d}d ${h}h ${m}m`;
            if (h > 0) return `${h}h ${m}m`;
            return `${m}m ${Math.floor(s % 60)}s`;
        }
        function formatDuration(iso) { if (!iso) return '—'; return formatUptime((Date.now() - new Date(iso).getTime()) / 1000); }
        function formatDate(iso) {
            if (!iso) return '—';
            const d = new Date(iso), pad = n => String(n).padStart(2, '0');
            return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
        }
        function isExpired(iso) { return iso && iso !== '0001-01-01T00:00:00Z' && new Date(iso).getTime() < Date.now(); }
        function parseAddr(addr) {
            if (!addr) return { ip: '—', port: '—' };
            const i = addr.lastIndexOf(':');
            if (i < 0) return { ip: addr, port: '—' };
            return { ip: addr.slice(0, i), port: addr.slice(i + 1) };
        }

        // ⭐ 延迟显示辅助
        function latencyText(ms) {
            if (!ms || ms <= 0) return '—';
            return ms + ' ms';
        }
        function latencyClass(ms) {
            if (!ms || ms <= 0) return '';
            if (ms < 100) return 'ok';
            if (ms < 200) return 'warn';
            return 'err';
        }

        watch(cfg, () => { if (!suppressDirty) dirty.value = true; }, { deep: true });
        watch(certCfg, () => { if (!certSuppressDirty) certDirty.value = true; }, { deep: true });

        watch(tab, async (newTab) => {
            if (newTab !== 'server') {
                if (onlineChartInst) { onlineChartInst.destroy(); onlineChartInst = null; }
                if (trafficChartInst) { trafficChartInst.destroy(); trafficChartInst = null; }
            }
            if (newTab === 'server') {
                await nextTick();
                await loadMetrics();
            }
            if (newTab === 'cert') {
                await loadCertStatus();
                await loadCertConfig();
            }
        });

        onMounted(async () => {
            fetch('/api/version')
                .then(r => r.json())
                .then(d => { if (d && d.version) version.value = d.version; })
                .catch(() => {});

            await checkInitStatus();

            if (!initialized.value) return;

            if (token.value) {
                try {
                    const r = await fetch('/api/me', { headers: { 'Authorization': 'Bearer ' + token.value } });
                    if (r.ok) {
                        const me = await r.json();
                        currentUser.value = me.username;
                        await bootstrap();
                    } else {
                        doLogout(true);
                    }
                } catch (e) { doLogout(true); }
            }

            metricsTicker = setInterval(() => {
                if (token.value && tab.value === 'server') loadMetrics();
            }, 10000);
        });

        onUnmounted(() => {
            if (es) es.close();
            if (metricsTicker) clearInterval(metricsTicker);
            if (onlineChartInst) { onlineChartInst.destroy(); onlineChartInst = null; }
            if (trafficChartInst) { trafficChartInst.destroy(); trafficChartInst = null; }
        });

        return {
            languages, langOpen, currentLangLabel, changeLang,
            locale,

            generateObfsPassword,

            initChecked, initialized,
            setupForm, setupMsg, setupOk, setupBusy, doSetup,
            version, token, currentUser, loginForm, loginMsg, loginOk, logging,
            tab, clients, users, editUser, busy, server, cfg, dirty, pwdForm,
            geo, geoCountriesInput, geoSaving,
            perf, perfSaving,
            certInfo, certStatusError, certCfg, certDirty, certBusy,
            loadCertStatus, loadCertConfig, saveCertConfig, regenerateCert, copyFingerprint,
            onlineChart, trafficChart,
            login, logout, startServer, stopServer, restartServer, saveConfig, resetConfig, syncCfg,
            openCreateUser, openEditUser, saveUser, deleteUser, kick, changePassword,
            loadGeo, saveGeo,
            loadPerformance, savePerformance,
            loadMetrics,
            openExternal,
            formatBytes, formatUptime, formatDuration, formatDate, isExpired, parseAddr,
            latencyText, latencyClass,
        };
    }
});

app.use(i18n);
app.mount('#app');