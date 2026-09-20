package quic

//vpn-server\quic\authenticator.go

import (
	"crypto/subtle"
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

// ⭐ 安全审计 S7：DHCP 租约的生命周期管理
const (
	// dhcpLeaseTTL 未被数据面认领的租约存活时间。
	// 正常客户端从拿到 IP 到建立数据面只需几秒；超过这个时间
	// 说明是「申请了 IP 却从不使用」的行为，应当回收。
	dhcpLeaseTTL = 5 * time.Minute
	// leaseReapInterval 租约回收扫描间隔
	leaseReapInterval = 30 * time.Second
)

// ⭐ 安全审计 S1：数据面会话（服务端自己记录的身份）
const (
	// dataPlaneSessionTTL 认证通过后允许建立数据面的时间窗。
	// 认证与数据面注册之间只有几秒，10 分钟非常宽松。
	dataPlaneSessionTTL = 10 * time.Minute
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
	deviceIP   map[string]string

	// ⭐ P2-1: 反向索引，断线释放 O(1)
	vipToDevice map[string]string

	// ⭐ 安全审计 S7：租约表 vip -> 过期时刻。
	//    零值表示「已被活跃数据面会话占用，不参与回收」。
	//    客户端自报的 deviceID 无法作为可信身份，但至少要让
	//    「申请了 IP 却从不建立数据面」的租约自动过期 ——
	//    否则一个已认证用户只要不断用新的 deviceID 申请，
	//    就能把整个地址池占满，让所有正常用户无法认证。
	leases map[string]time.Time
	// leaseTTL 未被数据面认领的租约存活时间（做成字段便于测试）
	leaseTTL time.Duration
}

func NewIPAllocator() *IPAllocator {
	start := net.ParseIP("10.0.0.100")
	end := net.ParseIP("10.0.0.200")
	next := make(net.IP, len(start))
	copy(next, start)

	a := &IPAllocator{
		usedIPs:     make(map[string]bool),
		freeIPs:     []string{},
		deviceIP:    make(map[string]string),
		vipToDevice: make(map[string]string),
		leases:      make(map[string]time.Time),
		leaseTTL:    dhcpLeaseTTL,
		startIP:     start,
		endIP:       end,
		nextIP:      next,
		subnetMask:  net.CIDRMask(24, 32),
	}
	go a.leaseReapLoop()
	return a
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
	a.deviceIP = make(map[string]string)
	a.vipToDevice = make(map[string]string)
	a.leases = make(map[string]time.Time)
	log.Printf("IP池已更新: %s - %s", start, end)
	return nil
}

// SetSubnetMask 设置子网掩码。
// ⭐ 安全审计 S19：必须要求 IPv4（To4() != nil），否则 net.IPMask(nil)
// 会让 GetSubnetMask() 返回 "<nil>" 并被下发到客户端，导致所有客户端连不上。
func (a *IPAllocator) SetSubnetMask(mask string) error {
	parsed := net.ParseIP(mask)
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("无效子网掩码（必须是 IPv4）: %s", mask)
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

// AllocateByDeviceID 按 deviceID 分配（或复用）一个 VIP。
//
// ⚠️ 安全审计 S1/S7：deviceID 由客户端自报，**不能作为可信身份**。
// 它只用于「同一设备重连时拿回同一个地址」。真正的身份校验在
// AuthorizeDataPlane 里用「QUIC 对端 IP + 用户名」完成。
func (a *IPAllocator) AllocateByDeviceID(deviceID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if vip, ok := a.deviceIP[deviceID]; ok {
		a.renewLeaseLocked(vip) // ⭐ S7：重复申请时续租
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
	// ⭐ 安全审计 S7：分配即产生租约，未被数据面认领的会在 TTL 后被回收
	a.leases[vip] = time.Now().Add(a.leaseTTL)
	return vip
}

// ---------- 租约管理（安全审计 S7） ----------

// renewLeaseLocked 续租。已绑定活跃会话（零值）的租约保持不变。
func (a *IPAllocator) renewLeaseLocked(vip string) {
	if exp, ok := a.leases[vip]; ok && exp.IsZero() {
		return
	}
	a.leases[vip] = time.Now().Add(a.leaseTTL)
}

// MarkLeaseActive 把租约标记为「已被活跃数据面会话占用」，之后不再被回收，
// 直到 ReleaseByVirtualIP 显式释放。
func (a *IPAllocator) MarkLeaseActive(vip string) {
	if vip == "" {
		return
	}
	a.mu.Lock()
	if _, ok := a.leases[vip]; ok {
		a.leases[vip] = time.Time{}
	}
	a.mu.Unlock()
}

// IsLeased 该 VIP 当前是否已通过 DHCP 租出。
// ⭐ 安全审计 S1：数据面用它拒绝「客户端凭空捏造」的 VIP ——
// 只有服务端真的分配过的地址才允许注册。
func (a *IPAllocator) IsLeased(vip string) bool {
	if vip == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.usedIPs[vip]
}

// LeaseCount 当前租约数（监控/日志用）
func (a *IPAllocator) LeaseCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.leases)
}

func (a *IPAllocator) leaseReapLoop() {
	ticker := time.NewTicker(leaseReapInterval)
	defer ticker.Stop()
	for range ticker.C {
		a.reapExpiredLeases()
	}
}

// reapExpiredLeases 回收「申请了 IP 但一直没建立数据面」的租约。
// 这是 S7 里「地址池被单个用户打空」的兜底：即使攻击者拿到合法账号，
// 也只能短暂占用地址，且必须先通过认证。
func (a *IPAllocator) reapExpiredLeases() {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()

	released := 0
	for vip, exp := range a.leases {
		if exp.IsZero() || now.Before(exp) {
			continue // 已绑定活跃会话，或还没到期
		}
		log.Printf("♻️ [IP池] 回收过期租约 %s（分配后未建立数据面）", vip)
		a.releaseVIPLocked(vip)
		released++
	}
	if released > 0 {
		log.Printf("♻️ [IP池] 本轮回收 %d 个租约，剩余租约 %d 个", released, len(a.leases))
	}
}

func (a *IPAllocator) ReleaseByVirtualIP(virtualIP string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.releaseVIPLocked(virtualIP)
}

// releaseVIPLocked 释放单个 VIP（调用方必须已持有 a.mu）
func (a *IPAllocator) releaseVIPLocked(virtualIP string) {
	released := false

	if deviceID, ok := a.vipToDevice[virtualIP]; ok {
		delete(a.vipToDevice, virtualIP)
		delete(a.deviceIP, deviceID)
		released = true
		log.Printf("♻️ 释放IP %s（设备 %s）", virtualIP, deviceID)
	}

	// ⭐ 安全审计 S7：租约记录必须一并清掉，
	//    否则回收循环会反复看到这条记录（内存只增不减）。
	delete(a.leases, virtualIP)

	if a.usedIPs[virtualIP] {
		delete(a.usedIPs, virtualIP)
		a.appendFreeLocked(virtualIP)
		return
	}

	if !released {
		return
	}
}

func (a *IPAllocator) appendFreeLocked(virtualIP string) {
	for _, ip := range a.freeIPs {
		if ip == virtualIP {
			return
		}
	}
	a.freeIPs = append(a.freeIPs, virtualIP)
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

// 数据面授权模型（安全审计 S1）
//
// ⭐ 问题背景：数据面（h3-data / h3-ctrl）的注册帧是
// `类型\n模式\n用户名\nVIP`，**全部由客户端自报**，而这两条连接从不经过
// 认证器。服务端原来直接采信，于是「不需要口令就能入网」「注册别人的 VIP
// 就能劫持对方」都成立。
//
// ⭐ 现在的模型由两张表组成，全部只依赖服务端侧事实：
//
//	authorizedKeys : peerIP\x00用户名 -> 授权到期时刻
//	   认证成功即写入，数据面注册时刷新。peerIP 来自 QUIC 连接，不可伪造；
//	   用户名必须真的用正确口令认证过。
//	vipOwner : VIP -> peerIP\x00用户名
//	   VIP 必须是服务端真的通过 DHCP 租出过的地址（IPAllocator.IsLeased），
//	   且一旦被某个 key 占用，别的 key 不能抢占。
//
// ⭐ 为什么 key 用「peerIP + 用户名」而不是「每个连接一个会话」：
// 一个账号**允许被多个客户端共用**（这正是需求）。用 (peerIP, 用户名) 作 key
// 可以天然支持：
//   - 不同公网 IP 的多个客户端：key 不同，各自绑定自己的 VIP；
//   - 同一出口 IP（同一路由器下）的多个客户端：**同一个 key**，各自绑定
//     自己的 VIP —— 因为 vipOwner 是「VIP -> key」的多对一关系，
//     一个 key 可以合法拥有多个 VIP。
//
// 因此这里不再有「一个会话只能绑一个 VIP」的限制。
//
// ⚠️ 残留风险（需要协议升级才能完全消除）：同一个 NAT 后面的两个用户共享
// 出口 IP，因此 A 可能冒充 B（前提是 B 也刚从同一出口认证过）。
// 彻底解决需要在注册帧里携带服务端签发的一次性票据。
type CustomAuthenticator struct {
	userStore   *store.Store
	ipAllocator *IPAllocator

	// ⭐ 客户端版本范围
	minClientVersion string
	maxClientVersion string

	mu          sync.Mutex
	failCount   map[string]int
	bannedUntil map[string]time.Time

	// ⭐ 安全审计 S1：数据面授权表
	// key = peerIP + "\x00" + username -> 授权到期时刻
	authorizedKeys map[string]time.Time
	// ⭐ VIP 归属：vip -> key（一个 key 可以拥有多个 VIP，
	// 以支持同一账号 / 同一出口 IP 的多客户端并发）
	vipOwner map[string]string
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
		authorizedKeys:   make(map[string]time.Time),
		vipOwner:         make(map[string]string),
	}
	if !isVersionUnlimited(auth.minClientVersion) || !isVersionUnlimited(auth.maxClientVersion) {
		log.Printf("🔒 [版本校验] 已启用：客户端版本必须 ∈ [%s, %s]",
			displayVer(auth.minClientVersion), displayVer(auth.maxClientVersion))
	} else {
		log.Printf("🔓 [版本校验] 未启用（接受任意版本客户端）")
	}
	log.Printf("🔐 [认证] 仅支持多用户模式（用户名:密码），全局密码已移除")
	log.Printf("👥 [认证] 同一账号允许被多个客户端共用（含同一 NAT 下的多台设备）")
	auth.startCleanupLoop()
	return auth
}

// ========== 数据面授权（安全审计 S1） ==========

func sessionKey(peerIP, username string) string {
	return peerIP + "\x00" + username
}

// registerSession 认证成功后登记/刷新数据面授权。
//
// ⭐ 只写一个「到期时刻」，不再保存每连接状态 —— 因此同一账号
// 在同一出口 IP 下的多个客户端天然共享同一条授权记录，互不影响。
func (a *CustomAuthenticator) registerSession(peerIP, username string) {
	key := sessionKey(peerIP, username)

	a.mu.Lock()
	defer a.mu.Unlock()

	a.authorizedKeys[key] = time.Now().Add(dataPlaneSessionTTL)
}

// AuthorizeDataPlane 校验数据面注册帧。
//
// 全部使用服务端侧信息：
//   - peerIP 来自 QUIC 连接，客户端无法伪造；
//   - 该 (peerIP, 用户名) 必须有一次未过期的成功认证；
//   - vip 必须是服务端真的通过 DHCP 租出过的地址；
//   - 该 vip 不能被**别的** key 占用（同一个 key 可以拥有多个 vip，
//     这样同一账号 / 同一出口 IP 下的多个客户端才能并存）。
//
// 返回的 mode 由服务端决定，调用方必须使用它而不是客户端自报值。
func (a *CustomAuthenticator) AuthorizeDataPlane(peerIP, username, vip string) (mode string, ok bool) {
	if username == "" || vip == "" {
		return "", false
	}

	key := sessionKey(peerIP, username)
	now := time.Now()

	a.mu.Lock()
	defer a.mu.Unlock()

	expireAt, exists := a.authorizedKeys[key]
	if !exists {
		return "", false
	}
	if now.After(expireAt) {
		delete(a.authorizedKeys, key)
		return "", false
	}

	// VIP 必须是服务端真的分配过的地址（客户端不能凭空捏造）。
	// 注意：这里必须走 IsLeased()（它自己持 allocator 的锁），
	// 不能直接读 usedIPs 字段，否则会与 IPAllocator 的锁产生数据竞争。
	if a.ipAllocator == nil || !a.ipAllocator.IsLeased(vip) {
		return "", false
	}

	// 同一个 key 可以拥有多个 VIP；但别的 key 不能抢占已被占用的 VIP。
	if owner, taken := a.vipOwner[vip]; taken && owner != key {
		log.Printf("🚫 [安全] VIP %s 已被其它身份占用，拒绝 %s 抢占", vip, key)
		return "", false
	}
	a.vipOwner[vip] = key

	// 续期：客户端保持在线时不会因为 TTL 到期而被踢
	a.authorizedKeys[key] = now.Add(dataPlaneSessionTTL)

	// 身份一旦与 VIP 绑定，就说明该地址确实在被使用：
	// 把租约标记为活跃，避免它被回收循环误判为「申请后未使用」。
	a.ipAllocator.MarkLeaseActive(vip)

	// 全局密码已移除，认证成功的会话一律是多用户模式
	return "multi", true
}

// releaseSession 某个数据面连接断开时释放它占用的 VIP。
//
// ⭐ 只释放 **这一个** VIP，不影响同一账号/同一出口 IP 下其它客户端的 VIP；
// 授权记录本身交给 TTL 过期（其它客户端可能还在用）。
func (a *CustomAuthenticator) releaseSession(peerIP, username, vip string) {
	if vip == "" {
		return
	}
	key := sessionKey(peerIP, username)

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.vipOwner[vip] == key {
		delete(a.vipOwner, vip)
	}
}

// AuthorizedKeyCount 当前有效的授权记录数（监控/日志用）
func (a *CustomAuthenticator) AuthorizedKeyCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.authorizedKeys)
}

// BoundVIPCount 当前已绑定的 VIP 数（= 在线数据面连接数，监控/日志用）
func (a *CustomAuthenticator) BoundVIPCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.vipOwner)
}

// SessionCount 当前有效的授权记录数（等价于「有多少个不同的出口 IP+账号」）
func (a *CustomAuthenticator) SessionCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.authorizedKeys)
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
			// ⭐ S1：清理过期的数据面授权与已失效的 VIP 归属
			for key, until := range a.authorizedKeys {
				if now.After(until) {
					delete(a.authorizedKeys, key)
				}
			}
			// VIP 归属只在对应租约已经被释放后才清理 ——
			// 否则会把长连接仍在使用的 VIP 释放掉，让别的身份抢占。
			for vip := range a.vipOwner {
				if a.ipAllocator != nil && !a.ipAllocator.IsLeased(vip) {
					delete(a.vipOwner, vip)
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

// parseAuth 解析认证字符串（不含版本段）。
// 有冒号 → 多用户模式，返回 (username, password, true)；
// 无冒号 → 返回 ("", password, false)。后者已不再被接受
// （全局密码/单用户模式已移除），但保留该返回值以便日志区分。
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

	// ⭐ 全局密码（单用户模式）已移除：所有客户端都必须以
	// 「用户名:密码」认证，与面板的「用户管理」一一对应。
	if !isMultiUser {
		a.recordFailure(clientIP)
		log.Printf("🚫 [安全] 认证串不含用户名（单用户模式已停用）(来自 %s)", clientIP)
		return false, ""
	}
	return a.authMultiUser(clientIP, username, password, clientVersion)
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
	if !constTimeEqual(user.Password, password) {
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

	// ⭐ 安全审计 S1：登记数据面会话。
	//    VIP 不再在这里分配 —— hy-core 的 Authenticate 返回值只作为
	//    authID 用于日志，**不会发给客户端**，所以原来那次
	//    AllocateByDeviceID(username) 纯属浪费地址（客户端实际用的是
	//    DHCP 分配的地址）。现在 VIP 完全由 DHCP 分配，
	//    数据面注册时再用 AuthorizeDataPlane 校验并绑定。
	a.registerSession(clientIP, username)

	log.Printf("✅ [认证] 用户 %s 通过 (版本=%s, 来自 %s)，等待数据面注册",
		username, versionForLog(clientVersion), clientIP)

	// 返回值即 hy-core 的 authID，只用于事件/流量日志 —— 用用户名最自然
	return true, username
}

// constTimeEqual 常量时间比较，避免按字节比较带来的计时侧信道。
func constTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
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
