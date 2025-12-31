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

// TunEngine TUN 引擎
type TunEngine struct {
	fd        int
	file      *os.File
	stack     *stack.Stack
	ep        *channel.Endpoint
	proxyAddr string
	mtu       uint32
	running   atomic.Bool
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

var (
	tunEngine *TunEngine
	tunMu     sync.Mutex
)

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

	engine := &TunEngine{
		fd:        fd,
		file:      file,
		stack:     s,
		ep:        ep,
		proxyAddr: proxyAddr,
		mtu:       uint32(mtu),
		ctx:       ctx,
		cancel:    cancel,
	}
	engine.running.Store(true)
	tunEngine = engine

	// 启动协程
	engine.wg.Add(3)
	go engine.readFromTun()
	go engine.writeToTun()
	go engine.handleTCP()

	logInfo("[TUN] gVisor 网络栈已启动")
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
		dstAddr := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)
		go t.forwardTCP(conn, dstAddr)
	})

	// 将 forwarder 注册到协议栈，处理所有 TCP 包
	t.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
}

// forwardTCP 通过 SOCKS5 转发 TCP
func (t *TunEngine) forwardTCP(local net.Conn, dstAddr string) {
	defer local.Close()

	proxy, err := net.DialTimeout("tcp", t.proxyAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer proxy.Close()

	if err := socks5Handshake(proxy, dstAddr); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(proxy, local)
	}()

	go func() {
		defer wg.Done()
		io.Copy(local, proxy)
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
