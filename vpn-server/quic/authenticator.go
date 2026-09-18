package quic

//vpn-server\quic\authenticator.go

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpn-server/store"
)

const (
	maxFailCount    = 5
	banDuration     = 10 * time.Minute
	cleanupInterval = 5 * time.Minute
)

// ⭐ 版本号标记：auth 字符串末尾附加 ":vn=X.Y.Z"
const versionMarker = ":vn="

type IPAllocator struct {
	mu         sync.Mutex
	usedIPs    map[string]bool
	freeIPs    []string
	nextIP     net.IP
	startIP    net.IP
	endIP      net.IP
	subnetMask net.IPMask
	clientIP   map[string]string
	deviceIP   map[string]string

	// ⭐ P2-1: 反向索引，断线释放 O(1)
	vipToDevice map[string]string
	vipToClient map[string]string
}

func NewIPAllocator() *IPAllocator {
	start := net.ParseIP("10.0.0.100")
	end := net.ParseIP("10.0.0.200")
	next := make(net.IP, len(start))
	copy(next, start)

	return &IPAllocator{
		usedIPs:     make(map[string]bool),
		freeIPs:     []string{},
		clientIP:    make(map[string]string),
		deviceIP:    make(map[string]string),
		vipToDevice: make(map[string]string),
		vipToClient: make(map[string]string),
		startIP:     start,
		endIP:       end,
		nextIP:      next,
		subnetMask:  net.CIDRMask(24, 32),
	}
}

func (a *IPAllocator) SetIPPool(start, end string) error {
	startIP := net.ParseIP(start)
	endIP := net.ParseIP(end)
	if startIP == nil || endIP == nil {
		return fmt.Errorf("无效 IP 地址")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.startIP = startIP
	a.endIP = endIP
	a.nextIP = make(net.IP, len(startIP))
	copy(a.nextIP, startIP)
	a.usedIPs = make(map[string]bool)
	a.freeIPs = []string{}
	a.clientIP = make(map[string]string)
	a.deviceIP = make(map[string]string)
	a.vipToDevice = make(map[string]string)
	a.vipToClient = make(map[string]string)
	log.Printf("IP池已更新: %s - %s", start, end)
	return nil
}

func (a *IPAllocator) SetSubnetMask(mask string) error {
	parsed := net.ParseIP(mask)
	if parsed == nil {
		return fmt.Errorf("无效子网掩码: %s", mask)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.subnetMask = net.IPMask(parsed.To4())
	log.Printf("子网掩码已更新: %s", mask)
	return nil
}

func (a *IPAllocator) GetSubnetMask() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return net.IP(a.subnetMask).String()
}

func (a *IPAllocator) Allocate(clientAddr string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if vip, ok := a.clientIP[clientAddr]; ok {
		return vip
	}
	vip := a.pickFreeLocked()
	if vip == "" {
		return ""
	}
	a.clientIP[clientAddr] = vip
	a.vipToClient[vip] = clientAddr
	return vip
}

func (a *IPAllocator) AllocateByDeviceID(deviceID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if vip, ok := a.deviceIP[deviceID]; ok {
		return vip
	}
	vip := a.pickFreeLocked()
	if vip == "" {
		return ""
	}
	a.deviceIP[deviceID] = vip
	a.vipToDevice[vip] = deviceID
	return vip
}

func (a *IPAllocator) pickFreeLocked() string {
	var vip string
	if len(a.freeIPs) > 0 {
		vip = a.freeIPs[len(a.freeIPs)-1]
		a.freeIPs = a.freeIPs[:len(a.freeIPs)-1]
	} else {
		for a.nextIP != nil && ipLessOrEqual(a.nextIP, a.endIP) {
			ipStr := a.nextIP.String()
			if !a.usedIPs[ipStr] {
				vip = ipStr
				a.nextIP = nextIP(a.nextIP)
				break
			}
			a.nextIP = nextIP(a.nextIP)
		}
	}
	if vip == "" {
		return ""
	}
	a.usedIPs[vip] = true
	return vip
}

func (a *IPAllocator) ReleaseByVirtualIP(virtualIP string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	released := false

	if deviceID, ok := a.vipToDevice[virtualIP]; ok {
		delete(a.vipToDevice, virtualIP)
		delete(a.deviceIP, deviceID)
		released = true
		log.Printf("♻️ 释放IP %s（设备 %s）", virtualIP, deviceID)
	}
	if client, ok := a.vipToClient[virtualIP]; ok {
		delete(a.vipToClient, virtualIP)
		delete(a.clientIP, client)
		released = true
		log.Printf("♻️ 释放IP %s（客户端 %s）", virtualIP, client)
	}

	if !released {
		return
	}

	if a.usedIPs[virtualIP] {
		delete(a.usedIPs, virtualIP)
		for _, ip := range a.freeIPs {
			if ip == virtualIP {
				return
			}
		}
		a.freeIPs = append(a.freeIPs, virtualIP)
	}
}

func (a *IPAllocator) GetIP(clientIP string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.clientIP[clientIP]
}

func (a *IPAllocator) GetClientByIP(virtualIP string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.vipToClient[virtualIP]
}

func ipLessOrEqual(a, b net.IP) bool {
	a = a.To4()
	b = b.To4()
	if a == nil || b == nil {
		return false
	}
	for i := 0; i < 4; i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return true
}

func nextIP(ip net.IP) net.IP {
	ip = ip.To4()
	if ip == nil {
		return nil
	}
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

// ========== 版本工具 ==========

// parseVersion 解析 "X.Y.Z" 格式
func parseVersion(v string) ([]int, bool) {
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nil, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		nums[i] = n
	}
	return nums, true
}

// compareVersions 返回 -1（a<b）, 0（a==b）, 1（a>b）
// 任一版本格式无效时返回 0
func compareVersions(a, b string) int {
	aParts, aOK := parseVersion(a)
	bParts, bOK := parseVersion(b)
	if !aOK || !bOK {
		return 0
	}
	for i := 0; i < 3; i++ {
		if aParts[i] < bParts[i] {
			return -1
		}
		if aParts[i] > bParts[i] {
			return 1
		}
	}
	return 0
}

// isVersionUnlimited 判断某个版本限制值是否表示"不限制"
func isVersionUnlimited(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || v == "0.0.0"
}

// extractVersionAndStrip 从 auth 字符串末尾提取版本号
// 输入 "user:pass:vn=0.2.0" → 返回 ("user:pass", "0.2.0")
// 输入 "user:pass"           → 返回 ("user:pass", "")
// 输入 "user:pass:vn=bad"    → 返回 ("user:pass:vn=bad", "")（格式无效视为无版本）
func extractVersionAndStrip(auth string) (string, string) {
	idx := strings.LastIndex(auth, versionMarker)
	if idx < 0 {
		return auth, ""
	}
	version := auth[idx+len(versionMarker):]
	if _, ok := parseVersion(version); !ok {
		// 格式无效，视为没有版本号
		return auth, ""
	}
	return auth[:idx], version
}

// ========== 认证器 ==========

type CustomAuthenticator struct {
	userStore   *store.Store
	ipAllocator *IPAllocator

	// ⭐ 客户端版本范围
	minClientVersion string
	maxClientVersion string

	mu          sync.Mutex
	failCount   map[string]int
	bannedUntil map[string]time.Time
}

// ⭐ 签名变更：新增 minVer, maxVer 参数
func NewCustomAuthenticatorWithAllocator(users *store.Store, allocator *IPAllocator,
	minVer, maxVer string) *CustomAuthenticator {
	auth := &CustomAuthenticator{
		userStore:        users,
		ipAllocator:      allocator,
		minClientVersion: strings.TrimSpace(minVer),
		maxClientVersion: strings.TrimSpace(maxVer),
		failCount:        make(map[string]int),
		bannedUntil:      make(map[string]time.Time),
	}
	if !isVersionUnlimited(auth.minClientVersion) || !isVersionUnlimited(auth.maxClientVersion) {
		log.Printf("🔒 [版本校验] 已启用：客户端版本必须 ∈ [%s, %s]",
			displayVer(auth.minClientVersion), displayVer(auth.maxClientVersion))
	} else {
		log.Printf("🔓 [版本校验] 未启用（接受任意版本客户端）")
	}
	auth.startCleanupLoop()
	return auth
}

func displayVer(v string) string {
	if isVersionUnlimited(v) {
		return "任意"
	}
	return v
}

func (a *CustomAuthenticator) startCleanupLoop() {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			a.mu.Lock()
			now := time.Now()
			for ip, until := range a.bannedUntil {
				if now.After(until) {
					delete(a.bannedUntil, ip)
					delete(a.failCount, ip)
				}
			}
			a.mu.Unlock()
		}
	}()
}

func (a *CustomAuthenticator) isBanned(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	until, ok := a.bannedUntil[ip]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(a.bannedUntil, ip)
		delete(a.failCount, ip)
		return false
	}
	return true
}

func (a *CustomAuthenticator) recordFailure(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.failCount[ip]++
	if a.failCount[ip] >= maxFailCount {
		a.bannedUntil[ip] = time.Now().Add(banDuration)
		log.Printf("🚫 [安全] IP %s 连续认证失败 %d 次，封禁 %v",
			ip, a.failCount[ip], banDuration)
	} else {
		log.Printf("⚠️ [安全] IP %s 认证失败 (%d/%d)",
			ip, a.failCount[ip], maxFailCount)
	}
}

func (a *CustomAuthenticator) recordSuccess(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.failCount, ip)
	delete(a.bannedUntil, ip)
}

// parseAuth 解析认证字符串（不含版本段）
// 有冒号 → 多用户模式，返回 (username, password, true)
// 无冒号 → 单用户模式，返回 ("", password, false)
func parseAuth(auth string) (string, string, bool) {
	if i := strings.Index(auth, ":"); i >= 0 {
		return auth[:i], auth[i+1:], true
	}
	return "", auth, false
}

// ⭐ checkVersion 校验客户端版本
func (a *CustomAuthenticator) checkVersion(clientIP, clientVersion string) bool {
	// 1. 未配置任何限制 → 全部放行（向后兼容）
	if isVersionUnlimited(a.minClientVersion) && isVersionUnlimited(a.maxClientVersion) {
		return true
	}

	// 2. 配置了限制但客户端没带版本 → 拒绝
	if clientVersion == "" {
		a.recordFailure(clientIP)
		log.Printf("🚫 [安全] IP %s 未携带版本号，服务端要求 [%s, %s]",
			clientIP, displayVer(a.minClientVersion), displayVer(a.maxClientVersion))
		return false
	}

	// 3. 校验下限
	if !isVersionUnlimited(a.minClientVersion) {
		if compareVersions(clientVersion, a.minClientVersion) < 0 {
			a.recordFailure(clientIP)
			log.Printf("🚫 [安全] 客户端版本 %s 低于最低要求 %s (来自 %s)",
				clientVersion, a.minClientVersion, clientIP)
			return false
		}
	}

	// 4. 校验上限
	if !isVersionUnlimited(a.maxClientVersion) {
		if compareVersions(clientVersion, a.maxClientVersion) > 0 {
			a.recordFailure(clientIP)
			log.Printf("🚫 [安全] 客户端版本 %s 高于最高允许 %s (来自 %s)",
				clientVersion, a.maxClientVersion, clientIP)
			return false
		}
	}

	return true
}

func (a *CustomAuthenticator) Authenticate(addr net.Addr, auth string, tx uint64) (bool, string) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return false, ""
	}
	clientIP := udpAddr.IP.String()

	if a.isBanned(clientIP) {
		log.Printf("🚫 [安全] 拒绝已封禁 IP: %s", clientIP)
		return false, ""
	}

	// ⭐ 先提取版本号
	cleanAuth, clientVersion := extractVersionAndStrip(auth)

	// ⭐ 版本校验
	if !a.checkVersion(clientIP, clientVersion) {
		return false, ""
	}

	// 解析用户名密码
	username, password, isMultiUser := parseAuth(cleanAuth)

	if isMultiUser {
		return a.authMultiUser(clientIP, username, password, clientVersion)
	}
	return a.authSingleUser(clientIP, password, clientVersion)
}

func (a *CustomAuthenticator) authMultiUser(clientIP, username, password, clientVersion string) (bool, string) {
	user, ok := a.userStore.Get(username)
	if !ok {
		a.recordFailure(clientIP)
		log.Printf("⚠️ [安全] 用户不存在: %s (来自 %s)", username, clientIP)
		return false, ""
	}
	if !user.Enabled {
		a.recordFailure(clientIP)
		log.Printf("⚠️ [安全] 用户已禁用: %s", username)
		return false, ""
	}
	if user.Password != password {
		a.recordFailure(clientIP)
		return false, ""
	}
	if !user.ExpireAt.IsZero() && time.Now().After(user.ExpireAt) {
		a.recordFailure(clientIP)
		log.Printf("⚠️ [安全] 用户已过期: %s", username)
		return false, ""
	}
	if user.MaxBytes > 0 && user.UsedBytes >= user.MaxBytes {
		a.recordFailure(clientIP)
		log.Printf("⚠️ [安全] 用户流量已用尽: %s (%d/%d)", username, user.UsedBytes, user.MaxBytes)
		return false, ""
	}

	a.recordSuccess(clientIP)

	vip := a.ipAllocator.AllocateByDeviceID(username)
	if vip == "" {
		log.Printf("⚠️ [安全] 用户 %s 认证通过但无可用 IP", username)
		return false, ""
	}
	log.Printf("✅ [认证] 多用户模式: %s → VIP %s (版本=%s, 来自 %s)",
		username, vip, versionForLog(clientVersion), clientIP)
	return true, vip
}

func (a *CustomAuthenticator) authSingleUser(clientIP, password, clientVersion string) (bool, string) {
	globalPwd := a.userStore.GetGlobalPassword()
	if password != globalPwd {
		a.recordFailure(clientIP)
		return false, ""
	}

	a.recordSuccess(clientIP)

	vip := a.ipAllocator.Allocate(clientIP)
	if vip == "" {
		log.Printf("⚠️ [安全] IP %s 认证通过但无可用 IP", clientIP)
		return false, ""
	}
	log.Printf("✅ [认证] 单用户模式: %s → VIP %s (版本=%s)",
		clientIP, vip, versionForLog(clientVersion))
	return true, vip
}

func versionForLog(v string) string {
	if v == "" {
		return "未提供"
	}
	return v
}

func (a *CustomAuthenticator) GetIPAllocator() *IPAllocator {
	return a.ipAllocator
}
