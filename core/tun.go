// Package core TUN 设备处理
// 使用 gVisor 原生 Go 网络栈实现 TUN → SOCKS5 转发
package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID       = 1
	channelSize = 512
)

// 缓冲池
var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 2048)
	},
}

// DNS 缓冲池（512 字节，用于 DNS 查询）
var dnsBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 512)
	},
}

// TunEngine TUN 引擎
type TunEngine struct {
	fd        int
	file      *os.File
	stack     *stack.Stack
	ep        *channel.Endpoint
	transport *WebSocketTransport // 直接引用 transport，不走 SOCKS5
	mtu       uint32
	running   atomic.Bool
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

var (
	tunEngine       *TunEngine
	tunMu           sync.Mutex
	globalTransport *WebSocketTransport // 全局 transport，供 TUN 直接使用
	transportMu     sync.RWMutex
)

// ======================== FakeDNS 配置 ========================

const (
	// FakeDNS IP 范围: 198.18.0.0/15 (RFC 2544, 131072 个 IP)
	// 从 198.18.0.0 到 198.19.255.255
	FakeDNSPrefix = "198.18.0.0/15"
	FakeDNSStart  = 0xC6120001 // 198.18.0.1
	FakeDNSEnd    = 0xC613FFFF // 198.19.255.255 (131071 个可用 IP)
)

var (
	// 域名 -> FakeIP 映射
	fakeDNSMap = make(map[string]net.IP)
	// FakeIP -> 域名 反向映射
	fakeDNSReverse = make(map[string]string)
	// FakeDNS 互斥锁
	fakeDNSMu sync.RWMutex
	// 当前分配的 FakeIP 索引 (Ring Buffer)
	fakeDNSIndex uint32 = FakeDNSStart
)

// SetGlobalTransport 设置全局 transport（由 Client 调用）
func SetGlobalTransport(t *WebSocketTransport) {
	transportMu.Lock()
	defer transportMu.Unlock()
	globalTransport = t
	logInfo("[TUN] 全局 transport 已设置")
}

// GetGlobalTransport 获取全局 transport
func GetGlobalTransport() *WebSocketTransport {
	transportMu.RLock()
	defer transportMu.RUnlock()
	return globalTransport
}

// ======================== FakeDNS 函数 ========================

// allocateFakeIP 为域名分配 FakeIP (Ring Buffer 实现，防止内存泄漏)
func allocateFakeIP(domain string) net.IP {
	fakeDNSMu.Lock()
	defer fakeDNSMu.Unlock()

	// 1. 检查域名是否已分配
	if ip, exists := fakeDNSMap[domain]; exists {
		return ip
	}

	// 2. 分配新的 FakeIP
	ip := uint32ToIP(fakeDNSIndex)

	// 3. Ring Buffer: 检查这个 IP 是否已分配给其他域名
	// 如果是，删除旧映射（LRU 淘汰）
	if oldDomain, exists := fakeDNSReverse[ip.String()]; exists {
		delete(fakeDNSMap, oldDomain)
		logInfo("[FakeDNS] 复用 IP: %s (旧域名: %s)", ip.String(), oldDomain)
	}

	// 4. 建立新映射
	fakeDNSMap[domain] = ip
	fakeDNSReverse[ip.String()] = domain

	// 5. 移动游标，循环使用
	fakeDNSIndex++
	if fakeDNSIndex > FakeDNSEnd {
		fakeDNSIndex = FakeDNSStart
		logInfo("[FakeDNS] IP 池已循环一圈，从头开始")
	}

	logInfo("[FakeDNS] 分配: %s -> %s", domain, ip.String())
	return ip
}

// uint32ToIP 将 uint32 转换为 net.IP
func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(n >> 24)
	ip[1] = byte(n >> 16)
	ip[2] = byte(n >> 8)
	ip[3] = byte(n)
	return ip
}

// isFakeIP 检查 IP 是否是 FakeIP (198.18.0.0/15)
func isFakeIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip = ip.To4()
	if ip == nil {
		return false
	}

	// 检查是否在 198.18.0.0/15 范围内
	// 198.18.0.0 - 198.19.255.255
	return ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)
}

// resolveFakeDomain 反查 FakeIP 对应的真实域名
func resolveFakeDomain(ipStr string) string {
	fakeDNSMu.RLock()
	defer fakeDNSMu.RUnlock()

	if domain, exists := fakeDNSReverse[ipStr]; exists {
		return domain
	}
	return ipStr // 如果找不到，返回原 IP
}

// parseDNSQuery 使用 miekg/dns 库解析 DNS 查询
func parseDNSQuery(packet []byte) (string, *dns.Msg) {
	msg := new(dns.Msg)
	if err := msg.Unpack(packet); err != nil {
		return "", nil
	}

	if len(msg.Question) == 0 {
		return "", nil
	}

	// 提取域名（去掉末尾的点）
	domain := msg.Question[0].Name
	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}

	return domain, msg
}

// buildDNSResponse 使用 miekg/dns 库构造 DNS 响应
func buildDNSResponse(query *dns.Msg, domain string, ip net.IP) []byte {
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Authoritative = true

	// 构造 A 记录
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   query.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    1, // TTL = 1 秒，防止客户端缓存导致 IP 复用冲突
		},
		A: ip,
	}
	resp.Answer = append(resp.Answer, rr)

	// 序列化
	out, err := resp.Pack()
	if err != nil {
		return nil
	}

	return out
}

// StartTun 启动 TUN 设备处理
func StartTun(fd int, proxyAddr string, mtu int) error {
	tunMu.Lock()
	defer tunMu.Unlock()

	if tunEngine != nil && tunEngine.running.Load() {
		stopTunLocked()
	}

	if fd < 0 {
		return errors.New("invalid TUN fd")
	}
	if proxyAddr == "" {
		return errors.New("proxy address required")
	}
	if mtu <= 0 {
		mtu = 1500
	}

	logInfo("[TUN] 启动 gVisor 网络栈，代理: %s, MTU: %d", proxyAddr, mtu)

	file := os.NewFile(uintptr(fd), "tun")
	if file == nil {
		return errors.New("failed to create file from fd")
	}

	// 创建 gVisor 网络栈
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	}
	s := stack.New(opts)

	// 创建通道端点
	ep := channel.New(channelSize, uint32(mtu), "")

	// 创建 NIC
	if err := s.CreateNIC(nicID, ep); err != nil {
		s.Close()
		return fmt.Errorf("create NIC: %v", err)
	}

	// 设置路由
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	// 启用混杂模式和欺骗
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)

	ctx, cancel := context.WithCancel(context.Background())

	// 获取全局 transport
	transport := GetGlobalTransport()
	if transport == nil {
		return errors.New("global transport not set")
	}

	engine := &TunEngine{
		fd:        fd,
		file:      file,
		stack:     s,
		ep:        ep,
		transport: transport,
		mtu:       uint32(mtu),
		ctx:       ctx,
		cancel:    cancel,
	}
	engine.running.Store(true)
	tunEngine = engine

	// 启动协程
	engine.wg.Add(4)
	go engine.readFromTun()
	go engine.writeToTun()
	go engine.handleTCP()
	go engine.handleUDP()

	logInfo("[TUN] gVisor 网络栈已启动 (TCP + UDP)")
	return nil
}

// readFromTun 从 TUN 读取 IP 包注入网络栈
func (t *TunEngine) readFromTun() {
	defer t.wg.Done()

	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		bufPtr := bufPool.Get().([]byte)
		buf := bufPtr[:t.mtu]

		t.file.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := t.file.Read(buf)
		if err != nil {
			bufPool.Put(bufPtr)
			if os.IsTimeout(err) {
				continue
			}
			if t.running.Load() {
				logError("[TUN] 读取错误: %v", err)
			}
			return
		}

		if n > 0 {
			data := buf[:n]
			var proto tcpip.NetworkProtocolNumber
			switch data[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				bufPool.Put(bufPtr)
				continue
			}

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(data),
			})
			t.ep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}

		bufPool.Put(bufPtr)
	}
}

// writeToTun 从网络栈读取 IP 包写入 TUN
func (t *TunEngine) writeToTun() {
	defer t.wg.Done()

	for {
		pkt := t.ep.ReadContext(t.ctx)
		if pkt == nil {
			return
		}

		view := pkt.ToView()
		data := view.AsSlice()
		if len(data) > 0 {
			t.file.Write(data)
		}
		pkt.DecRef()
	}
}

// handleTCP 处理 TCP 连接
func (t *TunEngine) handleTCP() {
	defer t.wg.Done()

	fwd := tcp.NewForwarder(t.stack, 0, 65535, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		// 修复：使用 RemoteAddress (真实目标) 而不是 LocalAddress (VPN 内部地址)
		dstAddr := fmt.Sprintf("%s:%d", id.RemoteAddress.String(), id.RemotePort)

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			logError("[TCP] CreateEndpoint 失败: %v", err)
			return
		}
		r.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)
		go t.forwardTCP(conn, dstAddr)
	})

	// 将 forwarder 注册到协议栈，处理所有 TCP 包
	t.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	logInfo("[TUN] TCP 转发器已注册")
}

// forwardTCP 直接通过 transport 转发 TCP（零拷贝）
func (t *TunEngine) forwardTCP(local net.Conn, dstAddr string) {
	defer local.Close()

	// FakeDNS 反查：如果目标是 FakeIP，替换为真实域名
	host, port, _ := net.SplitHostPort(dstAddr)
	if isFakeIP(host) {
		domain := resolveFakeDomain(host)
		if domain != host {
			dstAddr = fmt.Sprintf("%s:%s", domain, port)
			logInfo("[FakeDNS] TCP 反查: %s -> %s", host, domain)
		}
	}

	logInfo("[TCP] 直接转发: %s", dstAddr)

	// 直接调用 transport.Dial()，不走 SOCKS5
	tunnelConn, err := t.transport.Dial()
	if err != nil {
		logError("[TCP] 建立隧道失败 %s: %v", dstAddr, err)
		return
	}
	defer tunnelConn.Close()

	// 发送 CONNECT 请求到远程服务器
	if err := tunnelConn.Connect(dstAddr, nil); err != nil {
		logError("[TCP] CONNECT 失败 %s: %v", dstAddr, err)
		return
	}

	logInfo("[TCP] 隧道已建立: %s", dstAddr)

	// 使用适配器使 TunnelConn 兼容 io.ReadWriteCloser
	tunnel := NewTunnelConnAdapter(tunnelConn)

	// 双向转发（内存直接对接）
	var wg sync.WaitGroup
	wg.Add(2)

	// local -> tunnel
	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		io.CopyBuffer(tunnel, local, buf)
		tunnel.CloseWrite()
	}()

	// tunnel -> local
	go func() {
		defer wg.Done()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)
		io.CopyBuffer(local, tunnel, buf)
		local.(*gonet.TCPConn).CloseWrite()
	}()

	wg.Wait()
}

// socks5Handshake SOCKS5 握手
func socks5Handshake(conn net.Conn, dstAddr string) error {
	conn.Write([]byte{0x05, 0x01, 0x00})

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return errors.New("socks5 auth failed")
	}

	host, portStr, _ := net.SplitHostPort(dstAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))
	conn.Write(req)

	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp[:4]); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: %d", resp[1])
	}

	switch resp[3] {
	case 0x01:
		io.ReadFull(conn, resp[:6])
	case 0x03:
		io.ReadFull(conn, resp[:1])
		io.ReadFull(conn, make([]byte, int(resp[0])+2))
	case 0x04:
		io.ReadFull(conn, resp[:18])
	}

	return nil
}

// handleUDP 处理 UDP 连接 (DNS 等)
func (t *TunEngine) handleUDP() {
	defer t.wg.Done()

	fwd := udp.NewForwarder(t.stack, func(r *udp.ForwarderRequest) {
		id := r.ID()
		dstAddr := fmt.Sprintf("%s:%d", id.RemoteAddress.String(), id.RemotePort)

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			logError("[UDP] CreateEndpoint 失败: %v", err)
			return
		}

		conn := gonet.NewUDPConn(t.stack, &wq, ep)

		// 拦截 DNS 请求 (端口 53)
		if id.RemotePort == 53 {
			go t.handleDNS(conn, id.RemoteAddress.String())
			return
		}

		// 其他 UDP 正常转发
		go t.forwardUDP(conn, dstAddr)
	})

	// 将 forwarder 注册到协议栈，处理所有 UDP 包
	t.stack.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
	logInfo("[TUN] UDP 转发器已注册 (FakeDNS 已启用)")
}

// handleDNS 处理 DNS 查询，返回 FakeIP
func (t *TunEngine) handleDNS(conn *gonet.UDPConn, dnsServer string) {
	defer conn.Close()

	buf := dnsBufPool.Get().([]byte)
	defer dnsBufPool.Put(buf)

	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return
	}

	// 解析 DNS 查询
	domain, query := parseDNSQuery(buf[:n])
	if domain == "" || query == nil {
		logError("[FakeDNS] 解析 DNS 查询失败")
		return
	}

	if len(query.Question) == 0 {
		return
	}

	// 对于非 A 记录查询（特别是 AAAA），立即回复空响应，防止客户端超时等待
	if query.Question[0].Qtype != dns.TypeA {
		resp := new(dns.Msg)
		resp.SetReply(query)
		resp.Rcode = dns.RcodeSuccess // 域名存在，但没有该类型记录 (NODATA)

		if out, err := resp.Pack(); err == nil {
			conn.Write(out)
		}
		logInfo("[FakeDNS] 非 A 记录查询 (%s)，返回 NODATA", dns.TypeToString[query.Question[0].Qtype])
		return
	}

	// 分配 FakeIP
	fakeIP := allocateFakeIP(domain)

	// 构造 DNS 响应
	response := buildDNSResponse(query, domain, fakeIP)
	if response == nil {
		logError("[FakeDNS] 构造 DNS 响应失败")
		return
	}

	// 发送响应
	if _, err := conn.Write(response); err != nil {
		logError("[FakeDNS] 发送响应失败: %v", err)
		return
	}

	logInfo("[FakeDNS] %s -> %s (DNS: %s)", domain, fakeIP.String(), dnsServer)
}

// forwardUDP 直接通过 transport 转发 UDP（零拷贝）
func (t *TunEngine) forwardUDP(local *gonet.UDPConn, dstAddr string) {
	defer local.Close()

	// FakeDNS 反查：如果目标是 FakeIP，替换为真实域名
	host, port, _ := net.SplitHostPort(dstAddr)
	if isFakeIP(host) {
		domain := resolveFakeDomain(host)
		if domain != host {
			dstAddr = fmt.Sprintf("%s:%s", domain, port)
			logInfo("[FakeDNS] UDP 反查: %s -> %s", host, domain)
		}
	}

	logInfo("[UDP] 直接转发: %s", dstAddr)

	// 直接调用 transport.Dial()，不走 SOCKS5
	tunnelConn, err := t.transport.Dial()
	if err != nil {
		logError("[UDP] 建立隧道失败 %s: %v", dstAddr, err)
		return
	}
	defer tunnelConn.Close()

	// 发送 UDP CONNECT 请求到远程服务器
	// 使用特殊标记告诉服务器这是 UDP 连接
	if err := tunnelConn.Connect("udp://"+dstAddr, nil); err != nil {
		logError("[UDP] CONNECT 失败 %s: %v", dstAddr, err)
		return
	}

	logInfo("[UDP] 隧道已建立: %s", dstAddr)

	// 双向转发（内存直接对接）
	done := make(chan struct{}, 2)

	// local -> tunnel
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 2048)
		for {
			n, _, err := local.ReadFrom(buf)
			if err != nil {
				break
			}

			if err := tunnelConn.Write(buf[:n]); err != nil {
				logError("[UDP] 发送失败 %s: %v", dstAddr, err)
				break
			}
		}
	}()

	// tunnel -> local
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			data, err := tunnelConn.Read()
			if err != nil {
				break
			}

			if _, err := local.Write(data); err != nil {
				logError("[UDP] 写回失败 %s: %v", dstAddr, err)
				break
			}
		}
	}()

	// 等待任一方向结束
	<-done
	logInfo("[UDP] 连接关闭: %s", dstAddr)
}

// socks5UDPAssociate SOCKS5 UDP ASSOCIATE 握手，返回 UDP 中继地址
func socks5UDPAssociate(conn net.Conn) (string, error) {
	// 认证
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 256)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return "", errors.New("socks5 auth failed")
	}

	// UDP ASSOCIATE 请求
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(req)

	// 读取响应头
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", err
	}
	if buf[1] != 0x00 {
		return "", fmt.Errorf("socks5 udp associate failed: %d", buf[1])
	}

	// 解析绑定地址 (UDP 中继地址)
	atyp := buf[3]
	var host string
	var port int

	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:6]); err != nil {
			return "", err
		}
		host = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
		port = int(buf[4])<<8 | int(buf[5])
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", err
		}
		length := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:length+2]); err != nil {
			return "", err
		}
		host = string(buf[:length])
		port = int(buf[length])<<8 | int(buf[length+1])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:18]); err != nil {
			return "", err
		}
		host = net.IP(buf[:16]).String()
		port = int(buf[16])<<8 | int(buf[17])
	default:
		return "", fmt.Errorf("unknown address type: %d", atyp)
	}

	return fmt.Sprintf("%s:%d", host, port), nil
}

// buildSocks5UDPPacket 构建 SOCKS5 UDP 数据包
func buildSocks5UDPPacket(dstAddr string, data []byte) []byte {
	host, portStr, _ := net.SplitHostPort(dstAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	packet := []byte{0x00, 0x00, 0x00} // RSV, FRAG

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			packet = append(packet, 0x01)
			packet = append(packet, ip4...)
		} else {
			packet = append(packet, 0x04)
			packet = append(packet, ip.To16()...)
		}
	} else {
		packet = append(packet, 0x03, byte(len(host)))
		packet = append(packet, []byte(host)...)
	}

	packet = append(packet, byte(port>>8), byte(port))
	packet = append(packet, data...)
	return packet
}

// parseSocks5UDPPacket 解析 SOCKS5 UDP 数据包
func parseSocks5UDPPacket(packet []byte) []byte {
	if len(packet) < 10 {
		return nil
	}

	offset := 3 // 跳过 RSV, FRAG
	atyp := packet[offset]
	offset++

	switch atyp {
	case 0x01: // IPv4
		offset += 4
	case 0x03: // Domain
		length := int(packet[offset])
		offset += 1 + length
	case 0x04: // IPv6
		offset += 16
	default:
		return nil
	}

	offset += 2 // 跳过端口

	if offset >= len(packet) {
		return nil
	}

	return packet[offset:]
}

// StopTun 停止 TUN
func StopTun() {
	tunMu.Lock()
	defer tunMu.Unlock()
	stopTunLocked()
}

func stopTunLocked() {
	if tunEngine == nil {
		return
	}

	engine := tunEngine
	if !engine.running.Swap(false) {
		return
	}

	engine.cancel()

	if engine.stack != nil {
		engine.stack.Close()
	}

	engine.wg.Wait()
	engine.file = nil
	tunEngine = nil

	logInfo("[TUN] gVisor 网络栈已停止")
}

// IsTunRunning 检查运行状态
func IsTunRunning() bool {
	tunMu.Lock()
	defer tunMu.Unlock()
	return tunEngine != nil && tunEngine.running.Load()
}
