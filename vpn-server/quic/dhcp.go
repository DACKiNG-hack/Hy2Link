package quic

// vpn-server/quic/dhcp.go

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
)

type DHCPOutbound struct {
	ipAllocator     *IPAllocator
	tcpSplitEnabled bool
	tcpSplitPorts   []int

	udpReliableEnabled   bool
	udpReliablePorts     []string
	udpUnreliableEnabled bool
	udpUnreliablePorts   []string

	// ⭐ 新增
	certMode       string
	serverHostname string
}

func NewDHCPOutbound(
	ipAllocator *IPAllocator,
	tcpSplitEnabled bool,
	tcpSplitPorts []int,
	udpReliableEnabled bool,
	udpReliablePorts []string,
	udpUnreliableEnabled bool,
	udpUnreliablePorts []string,
	certMode string, // ⭐ 新增
	serverHostname string, // ⭐ 新增
) *DHCPOutbound {
	return &DHCPOutbound{
		ipAllocator:          ipAllocator,
		tcpSplitEnabled:      tcpSplitEnabled,
		tcpSplitPorts:        tcpSplitPorts,
		udpReliableEnabled:   udpReliableEnabled,
		udpReliablePorts:     udpReliablePorts,
		udpUnreliableEnabled: udpUnreliableEnabled,
		udpUnreliablePorts:   udpUnreliablePorts,
		certMode:             certMode,
		serverHostname:       serverHostname,
	}
}

func (o *DHCPOutbound) TCP(reqAddr string) (net.Conn, error) {
	if reqAddr == "10.0.0.1:9999" {
		return newDHCPConn(o), nil
	}
	return nil, fmt.Errorf("TCP not supported")
}

func (o *DHCPOutbound) UDP(reqAddr string) (server.UDPConn, error) {
	return nil, fmt.Errorf("UDP not supported")
}

func (o *DHCPOutbound) CheckUDP(reqAddr string) error {
	return nil
}

type dhcpConn struct {
	out       *DHCPOutbound
	mu        sync.Mutex
	deviceID  string
	ip        string
	mask      string
	ready     bool
	responded bool
	err       error
	cond      *sync.Cond
}

func newDHCPConn(o *DHCPOutbound) *dhcpConn {
	c := &dhcpConn{out: o}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *dhcpConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.responded {
		return 0, io.EOF
	}

	for !c.ready && c.err == nil {
		c.cond.Wait()
	}
	if c.err != nil {
		return 0, c.err
	}
	if c.ip == "" {
		return 0, fmt.Errorf("no IP assigned")
	}

	o := c.out

	tcpSplit := "off"
	tcpPortsStr := ""
	if o.tcpSplitEnabled {
		tcpSplit = "on"
		if len(o.tcpSplitPorts) > 0 {
			ss := make([]string, 0, len(o.tcpSplitPorts))
			for _, p := range o.tcpSplitPorts {
				ss = append(ss, strconv.Itoa(p))
			}
			tcpPortsStr = strings.Join(ss, "|")
		}
	}

	udpRel := "off"
	udpRelStr := ""
	if o.udpReliableEnabled {
		udpRel = "on"
		if len(o.udpReliablePorts) > 0 {
			udpRelStr = strings.Join(o.udpReliablePorts, "|")
		}
	}

	udpUnrel := "off"
	udpUnrelStr := ""
	if o.udpUnreliableEnabled {
		udpUnrel = "on"
		if len(o.udpUnreliablePorts) > 0 {
			udpUnrelStr = strings.Join(o.udpUnreliablePorts, "|")
		}
	}

	// ⭐ 10 段：
	// ip,mask,tcpSplit,tcpPorts,udpRel,udpRelRanges,udpUnrel,udpUnrelRanges,certMode,serverHostname
	response := c.ip + "," + c.mask + "," + tcpSplit + "," + tcpPortsStr +
		"," + udpRel + "," + udpRelStr + "," + udpUnrel + "," + udpUnrelStr +
		"," + o.certMode + "," + o.serverHostname + "\n"

	n = copy(b, []byte(response))
	c.responded = true
	c.ready = false
	return n, nil
}

func (c *dhcpConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data := strings.TrimSpace(string(b))
	log.Printf("🔍 DHCP Write: %q", data)

	if strings.Contains(data, "\n") {
		parts := strings.SplitN(data, "\n", 2)
		if len(parts) < 2 {
			c.err = fmt.Errorf("invalid request")
			c.cond.Broadcast()
			return 0, c.err
		}
		c.deviceID = strings.TrimSpace(parts[0])
		cmd := strings.TrimSpace(parts[1])
		if cmd != "REQUEST_IP" {
			c.err = fmt.Errorf("invalid command: %s", cmd)
			c.cond.Broadcast()
			return 0, c.err
		}
	} else {
		if data != "REQUEST_IP" {
			c.err = fmt.Errorf("invalid command: %s", data)
			c.cond.Broadcast()
			return 0, c.err
		}
		c.deviceID = fmt.Sprintf("client-%d", time.Now().UnixNano())
	}

	ip := c.out.ipAllocator.AllocateByDeviceID(c.deviceID)
	if ip == "" {
		c.err = fmt.Errorf("no IP available")
		c.cond.Broadcast()
		return 0, c.err
	}
	c.ip = ip
	c.mask = c.out.ipAllocator.GetSubnetMask()
	c.ready = true
	c.cond.Broadcast()

	log.Printf("✅ DHCP 分配: IP=%s, 掩码=%s, TCP=%v(%v), UDP可靠=%v(%v), UDP不可靠=%v(%v), 证书=%s(%s), 设备=%s",
		c.ip, c.mask,
		c.out.tcpSplitEnabled, c.out.tcpSplitPorts,
		c.out.udpReliableEnabled, c.out.udpReliablePorts,
		c.out.udpUnreliableEnabled, c.out.udpUnreliablePorts,
		c.out.certMode, c.out.serverHostname,
		c.deviceID)
	return len(b), nil
}

func (c *dhcpConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.responded {
		time.Sleep(200 * time.Millisecond)
	}
	c.err = fmt.Errorf("closed")
	c.cond.Broadcast()
	return nil
}

func (c *dhcpConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999}
}

func (c *dhcpConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999}
}

func (c *dhcpConn) SetDeadline(t time.Time) error      { return nil }
func (c *dhcpConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dhcpConn) SetWriteDeadline(t time.Time) error { return nil }
