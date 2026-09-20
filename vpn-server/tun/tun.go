package tun

//服务端tun.go

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

	// ⭐ 安全审计 S11：writeBufs 是共享切片，
	//    而 TunWriteLoop 会用 4 个 worker 并发调用 Write。
	//    原来的 t.writeBufs[0] = data 是无同步写，会导致
	//    「A 设好缓冲区、B 又覆盖、A 才真正写出去」→ 错包/丢包。
	writeMu sync.Mutex

	// readBufs/readSizes 目前只有单个读者（ServerTunReadLoop），
	// 但仍加锁保护，避免将来新增读者时踩同样的坑。
	readMu    sync.Mutex
	readBufs  [][]byte
	readSizes []int
	writeBufs [][]byte
}

func CreateTUN(name, ip, mask string, mtu int) (*TUNDevice, error) {
	log.Printf("🔍 [服务端 TUN] 创建: name=%s ip=%s mask=%s mtu=%d", name, ip, mask, mtu)

	if runtime.GOOS == "windows" {
		setupStaticGUID()
	}

	tunDev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("创建 TUN 失败: %v", err)
	}

	realName, err := tunDev.Name()
	if err != nil {
		return nil, fmt.Errorf("获取设备名失败: %v", err)
	}
	log.Printf("✅ [服务端 TUN] 真实名称: %s", realName)

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
		return nil, err
	}

	// ⭐ 关键：wintun 的 CreateTUN 接收了 mtu 参数但没有真正应用到网卡上。
	//    必须在设置 IP 之后用 netsh 显式设置 MTU，否则内核认为 MTU=65535，
	//    TCP 协商出 MSS=65495，服务端 TUN 转发的包会变成 64KB 巨包，
	//    进入 QUIC 隧道后被分片，丢一片整包重传。
	if err := setInterfaceMTU(realName, mtu); err != nil {
		log.Printf("⚠️ [服务端 TUN] 设置 MTU=%d 失败（继续，性能可能受影响）: %v", mtu, err)
	} else {
		log.Printf("✅ [服务端 TUN] 已设置 %s MTU=%d", realName, mtu)
	}

	if runtime.GOOS == "windows" {
		time.Sleep(500 * time.Millisecond)
		if err := addSubnetRoute(realName, ip, mask); err != nil {
			log.Printf("⚠️ [服务端 TUN] 添加路由失败: %v", err)
		} else {
			log.Printf("✅ [服务端 TUN] 路由已添加: %s/24", ip)
		}
	}

	log.Printf("✅ [服务端 TUN] 创建成功: %s, IP: %s, 掩码: %s, MTU: %d", realName, ip, mask, mtu)
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

func addSubnetRoute(ifaceName, ip, mask string) error {
	network := calculateNetwork(ip, mask)
	if network == "" {
		return fmt.Errorf("计算网络地址失败")
	}
	prefix := maskToPrefix(mask)

	idx, err := getInterfaceIndex(ifaceName)
	if err != nil {
		log.Printf("⚠️ [服务端 TUN] 无法获取接口索引 (%v)，改用 netsh", err)
		return addRouteViaNetsh(network, prefix, ifaceName)
	}
	log.Printf("🔍 [服务端 TUN] 接口 %s 索引 %d", ifaceName, idx)

	delCmd := newHiddenCmd("route", "delete", network)
	_ = delCmd.Run()

	addCmd := newHiddenCmd("route", "add", network, "mask", mask,
		ip, "if", strconv.Itoa(idx), "metric", "1")
	output, err := addCmd.CombinedOutput()
	if err == nil {
		log.Printf("✅ [服务端 TUN] route add 成功: %s/%s via %s (if %d)", network, prefix, ip, idx)
		return nil
	}
	log.Printf("⚠️ [服务端 TUN] route add 失败 (%v)，改用 netsh，输出: %s", err, string(output))
	return addRouteViaNetsh(network, prefix, ifaceName)
}

func addRouteViaNetsh(network, prefix, ifaceName string) error {
	cmd := newHiddenCmd("netsh", "interface", "ipv4", "add", "route",
		network+"/"+prefix, ifaceName, "0.0.0.0", "metric=1", "store=active")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh 添加路由失败: %v, output: %s", err, string(output))
	}
	log.Printf("✅ [服务端 TUN] netsh 添加成功: %s/%s on-link", network, prefix)
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
	t.readMu.Lock()
	defer t.readMu.Unlock()
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
	// ⭐ 安全审计 S11：串行化对 writeBufs / device.Write 的访问。
	//    调用方（TunWriteLoop 的多个 worker）不得并发进入这里。
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	t.writeBufs[0] = data
	_, err := t.device.Write(t.writeBufs, 0)
	return err
}

func (t *TUNDevice) Close() error {
	if t.device != nil {
		return t.device.Close()
	}
	return nil
}

func (t *TUNDevice) GetName() string { return t.name }
func (t *TUNDevice) GetIP() string   { return t.ip }
