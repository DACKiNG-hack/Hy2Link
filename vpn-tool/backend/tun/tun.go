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

	readBufs  [][]byte
	readSizes []int
	writeBufs [][]byte
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
		return nil, err
	}

	if runtime.GOOS == "windows" {
		time.Sleep(500 * time.Millisecond)
		if err := addRoute(realName, ip, mask); err != nil {
			log.Printf("⚠️ 添加路由失败: %v", err)
		} else {
			log.Printf("✅ 路由已添加")
		}
		_ = clearDefaultGateway(realName)
	}

	log.Printf("✅ TUN 设备创建成功: %s, IP: %s, 掩码: %s", realName, ip, mask)
	return dev, nil
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
