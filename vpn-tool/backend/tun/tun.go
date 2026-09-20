package tun

//客户端tun.go

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

const tunReadBufSize = 65535

type TUNDevice struct {
	device tun.Device
	name   string
	ip     string
	mask   string
	mtu    int

	// ⭐ 安全审计 S40：记录本设备添加过的路由。
	//    原来的 Close() 只关设备，`route add` 加进去的路由（甚至 -p 持久化项）
	//    从不删除，断开后会把相关网段持续黑洞化，或让流量继续指向已消失的隧道。
	routeMu     sync.Mutex
	addedRoutes []addedRoute

	readBufs  [][]byte
	readSizes []int
	writeBufs [][]byte
}

type addedRoute struct {
	network string
	mask    string
}

func (t *TUNDevice) recordRoute(network, mask string) {
	if network == "" {
		return
	}
	t.routeMu.Lock()
	t.addedRoutes = append(t.addedRoutes, addedRoute{network: network, mask: mask})
	t.routeMu.Unlock()
}

// removeRoutes 删除本设备添加过的全部路由（幂等）。
// `route delete <net> mask <mask>` 会同时移除活动路由与持久化条目。
func (t *TUNDevice) removeRoutes() {
	t.routeMu.Lock()
	routes := t.addedRoutes
	t.addedRoutes = nil
	t.routeMu.Unlock()

	for _, r := range routes {
		cmd := newHiddenCmd("route", "delete", r.network, "mask", r.mask)
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Printf("⚠️ [路由] 清理 %s mask %s 失败: %v (%s)",
				r.network, r.mask, err, strings.TrimSpace(string(out)))
		} else {
			log.Printf("🧹 [路由] 已清理 %s mask %s", r.network, r.mask)
		}
	}
}

func CreateTUN(name, ip, mask string, mtu int) (*TUNDevice, error) {
	log.Printf("🔍 [诊断] 创建 TUN 设备: %s, IP: %s, 掩码: %s, MTU: %d", name, ip, mask, mtu)

	if runtime.GOOS == "windows" {
		setupStaticGUID()
	}

	tunDev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("创建 TUN 失败: %v", err)
	}

	realName, err := tunDev.Name()
	if err != nil {
		// ⭐ 安全审计 S39：错误路径必须关闭已创建的设备，
		//    否则 wintun 适配器/会话会泄漏，反复重试会累积残留适配器。
		_ = tunDev.Close()
		return nil, fmt.Errorf("获取设备名失败: %v", err)
	}
	log.Printf("✅ [诊断] 设备真实名称: %s", realName)

	if runtime.GOOS == "windows" {
		enableCmd := newHiddenCmd("netsh", "interface", "set", "interface", realName, "enable")
		_ = enableCmd.Run()
	}

	dev := &TUNDevice{
		device:    tunDev,
		name:      realName,
		ip:        ip,
		mask:      mask,
		mtu:       mtu,
		readBufs:  [][]byte{make([]byte, tunReadBufSize)},
		readSizes: []int{0},
		writeBufs: [][]byte{nil},
	}

	if err := dev.setIP(ip, mask); err != nil {
		// ⭐ 安全审计 S39：同上，避免泄漏设备
		_ = tunDev.Close()
		return nil, err
	}

	// ⭐ 关键：wintun 的 CreateTUN 接收了 mtu 参数但没有真正应用到网卡上。
	//    必须在设置 IP 之后用 netsh 显式设置 MTU，否则内核认为 MTU=65535，
	//    TCP 协商出 MSS=65495，导致每个 HTTP 响应被切成巨大的 IP 包，
	//    进入 QUIC 隧道后又被分片成几十个 UDP 包，丢一片就要全部重传。
	if err := setInterfaceMTU(realName, mtu); err != nil {
		log.Printf("⚠️ [TUN] 设置 MTU=%d 失败（继续，性能可能受影响）: %v", mtu, err)
	} else {
		log.Printf("✅ [TUN] 已设置 %s MTU=%d", realName, mtu)
	}

	if runtime.GOOS == "windows" {
		time.Sleep(500 * time.Millisecond)
		if err := addRoute(realName, ip, mask); err != nil {
			log.Printf("⚠️ 添加路由失败: %v", err)
		} else {
			log.Printf("✅ 路由已添加")
			// ⭐ 安全审计 S40：登记以便 Close() 时清理
			dev.recordRoute(calculateNetwork(ip, mask), mask)
		}
		_ = clearDefaultGateway(realName)
	}

	log.Printf("✅ TUN 设备创建成功: %s, IP: %s, 掩码: %s, MTU: %d", realName, ip, mask, mtu)
	return dev, nil
}

// ⭐ setInterfaceMTU 用 netsh 设置网卡 MTU
// Windows 上需要管理员权限；store=persistent 让设置在网卡存活期间保持
// 非 Windows 平台由 CreateTUN/ip link 处理，这里直接返回
func setInterfaceMTU(ifaceName string, mtu int) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	cmd := newHiddenCmd("netsh", "interface", "ipv4", "set", "subinterface",
		ifaceName,
		fmt.Sprintf("mtu=%d", mtu),
		"store=persistent",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh 设置 MTU 失败: %v, output=%s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (t *TUNDevice) setIP(ip, mask string) error {
	switch runtime.GOOS {
	case "linux":
		prefix := maskToPrefix(mask)
		cmds := [][]string{
			{"ip", "addr", "add", ip + "/" + prefix, "dev", t.name},
			{"ip", "link", "set", "dev", t.name, "up"},
		}
		for _, cmdArgs := range cmds {
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("执行 %s 失败: %v", cmdArgs, err)
			}
		}
	case "darwin":
		cmd := exec.Command("ifconfig", t.name, "inet", ip, mask, "up")
		if err := cmd.Run(); err != nil {
			return err
		}
	case "windows":
		cmd := newHiddenCmd("netsh", "interface", "ip", "set", "address",
			t.name, "static", ip, mask)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("设置 IP 失败: %v", err)
		}
		_ = clearDefaultGateway(t.name)
	default:
		return fmt.Errorf("不支持的系统: %s", runtime.GOOS)
	}
	return nil
}

func clearDefaultGateway(ifaceName string) error {
	cmd := newHiddenCmd("netsh", "interface", "ip", "set", "address",
		ifaceName, "static", "", "")
	_ = cmd.Run()
	return nil
}

func addRoute(ifaceName, ip, mask string) error {
	network := calculateNetwork(ip, mask)
	if network == "" {
		return fmt.Errorf("计算网络地址失败")
	}
	prefix := maskToPrefix(mask)

	idx, err := getInterfaceIndex(ifaceName)
	if err != nil {
		log.Printf("⚠️ [路由] 无法获取接口索引 (%v)，改用 netsh", err)
		return addRouteViaNetsh(network, prefix, ifaceName)
	}
	log.Printf("🔍 [路由] 接口 %s 的索引为 %d", ifaceName, idx)

	delCmd := newHiddenCmd("route", "delete", network)
	_ = delCmd.Run()

	addCmd := newHiddenCmd("route", "add", network, "mask", mask,
		ip, "if", strconv.Itoa(idx), "metric", "1", "-p")
	output, err := addCmd.CombinedOutput()
	if err == nil {
		log.Printf("✅ [路由] route add 成功: %s/%s via %s (if %d)", network, prefix, ip, idx)
		return nil
	}
	log.Printf("⚠️ [路由] route add 失败 (%v)，输出: %s，改用 netsh", err, string(output))

	return addRouteViaNetsh(network, prefix, ifaceName)
}

func addRouteViaNetsh(network, prefix, ifaceName string) error {
	cmd := newHiddenCmd("netsh", "interface", "ipv4", "add", "route",
		network+"/"+prefix, ifaceName, "0.0.0.0", "metric=1", "store=active")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh 添加路由失败: %v, output: %s", err, string(output))
	}
	log.Printf("✅ [路由] netsh 添加成功: %s/%s on-link", network, prefix)
	return nil
}

func maskToPrefix(mask string) string {
	ipMask := net.ParseIP(mask)
	if ipMask == nil {
		return "24"
	}
	ones, _ := net.IPMask(ipMask.To4()).Size()
	return strconv.Itoa(ones)
}

func calculateNetwork(ip, mask string) string {
	ipAddr := net.ParseIP(ip)
	maskAddr := net.ParseIP(mask)
	if ipAddr == nil || maskAddr == nil {
		return ""
	}
	ip4 := ipAddr.To4()
	mask4 := maskAddr.To4()
	if ip4 == nil || mask4 == nil {
		return ""
	}
	network := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		network[i] = ip4[i] & mask4[i]
	}
	return network.String()
}

func getInterfaceIndex(name string) (int, error) {
	cmd := newHiddenCmd("netsh", "interface", "ip", "show", "interfaces")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("执行 netsh 失败: %v", err)
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 && strings.Contains(line, name) {
			idx, err := strconv.Atoi(fields[0])
			if err == nil {
				return idx, nil
			}
		}
	}
	return 0, fmt.Errorf("未找到接口 %s", name)
}

func (t *TUNDevice) Read() ([]byte, error) {
	n, err := t.device.Read(t.readBufs, t.readSizes, 0)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	return t.readBufs[0][:t.readSizes[0]], nil
}

func (t *TUNDevice) Write(data []byte) error {
	t.writeBufs[0] = data
	_, err := t.device.Write(t.writeBufs, 0)
	return err
}

func (t *TUNDevice) Close() error {
	// ⭐ 安全审计 S40：先清理本设备添加过的路由，再关闭设备。
	//    顺序很重要：设备关掉之后 route 命令仍能执行，但把清理放在前面
	//    可以保证即使 device.Close() 出错，路由也不会残留。
	t.removeRoutes()
	if t.device != nil {
		return t.device.Close()
	}
	return nil
}

func (t *TUNDevice) GetName() string {
	return t.name
}

// 保留 syscall 引用，避免 import 未使用（在其他平台构建时）
var _ = syscall.SysProcAttr{}
