// Package core 提供 Android 客户端的核心网络功能
// 使用 gomobile 编译为 AAR 供 Android 应用调用
package core

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

// ======================== 日志回调 ========================

// Logger 日志回调接口（供 Android 端实现）
type Logger interface {
	Log(level int, message string)
}

var logger Logger

// SetLogger 设置日志回调
func SetLogger(l Logger) {
	logger = l
}

// ======================== Socket 保护（VPN 必须）========================

// SocketProtector Socket 保护接口（防止 VPN 流量循环）
type SocketProtector interface {
	// Protect 保护 socket fd，使其流量不经过 VPN
	Protect(fd int) bool
}

var socketProtector SocketProtector

// SetSocketProtector 设置 socket 保护器（由 Android VpnService 实现）
func SetSocketProtector(p SocketProtector) {
	socketProtector = p
	logInfo("Socket 保护器已设置")
}

// protectSocket 保护 socket（内部调用）
func protectSocket(fd int) bool {
	if socketProtector == nil {
		logError("警告: Socket 保护器未设置，VPN 可能无法正常工作")
		return false
	}
	return socketProtector.Protect(fd)
}

func logInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Println(msg)
	if logger != nil {
		logger.Log(0, msg)
	}
}

func logError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Println("[ERROR] " + msg)
	if logger != nil {
		logger.Log(1, msg)
	}
}

// ======================== 配置 ========================

// Config 客户端配置
type Config struct {
	// 服务器地址 (host:port/path)
	ServerAddr string
	// 固定 IP（可选，用于绕过 DNS 污染）
	ServerIP string
	// 认证 Token
	Token string
	// 是否启用 ECH
	EnableECH bool
	// ECH 域名（用于获取 ECH 配置）
	ECHDomain string
	// 是否启用 Yamux 多路复用
	EnableYamux bool
	// DNS 服务器（用于获取 ECH 配置）
	DNSServer string
	// 本地 SOCKS5 监听地址
	LocalAddr string
}

// ======================== 核心客户端 ========================

// ======================== OOM 防护配置 ========================

const (
	// 最大并发连接数
	MaxConnections = 256
	// 单连接最大缓冲区 (64KB)
	MaxBufferSize = 64 * 1024
	// 内存警告阈值 (100MB)
	MemoryWarningThreshold = 100 * 1024 * 1024
	// 内存临界阈值 (200MB)
	MemoryCriticalThreshold = 200 * 1024 * 1024
)

// 连接计数器
var (
	activeConnections int32
	connectionsMu     sync.Mutex
	lowMemoryMode     bool
)

// GetActiveConnections 获取当前活跃连接数
func GetActiveConnections() int {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()
	return int(activeConnections)
}

// SetLowMemoryMode 设置低内存模式（由 Android 端调用）
func SetLowMemoryMode(enabled bool) {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()
	lowMemoryMode = enabled
	if enabled {
		logInfo("已启用低内存模式，将限制新连接")
	}
}

// IsLowMemoryMode 检查是否处于低内存模式
func IsLowMemoryMode() bool {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()
	return lowMemoryMode
}

// acquireConnection 获取连接许可
func acquireConnection() bool {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()
	
	// 低内存模式下，限制为一半连接数
	maxConn := int32(MaxConnections)
	if lowMemoryMode {
		maxConn = MaxConnections / 2
	}
	
	if activeConnections >= maxConn {
		logError("连接数已达上限: %d/%d", activeConnections, maxConn)
		return false
	}
	activeConnections++
	return true
}

// releaseConnection 释放连接许可
func releaseConnection() {
	connectionsMu.Lock()
	defer connectionsMu.Unlock()
	if activeConnections > 0 {
		activeConnections--
	}
}

// ======================== 核心客户端 ========================

// Client 核心客户端
type Client struct {
	config    *Config
	transport *WebSocketTransport
	listener  net.Listener
	running   bool
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc

	// ECH 配置缓存
	echConfig   []byte
	echConfigMu sync.RWMutex
}

// NewClient 创建新客户端
func NewClient(cfg *Config) *Client {
	return &Client{
		config: cfg,
	}
}

// Start 启动客户端
func Start(cfg *Config) (*Client, error) {
	c := NewClient(cfg)
	if err := c.Start(); err != nil {
		return nil, err
	}
	return c, nil
}

// Start 启动代理服务
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return errors.New("client already running")
	}

	// 获取 ECH 配置
	if c.config.EnableECH {
		logInfo("[启动] 正在获取 ECH 配置...")
		echBytes, err := c.fetchECHConfig()
		if err != nil {
			logError("获取 ECH 配置失败: %v", err)
			return fmt.Errorf("获取 ECH 配置失败: %w", err)
		}
		c.echConfig = echBytes
		logInfo("[ECH] 配置已加载，长度: %d 字节", len(echBytes))
	}

	// 创建传输层
	c.transport = NewWebSocketTransport(
		c.config.ServerAddr,
		c.config.ServerIP,
		c.config.Token,
		c.config.EnableECH,
		c.config.EnableYamux,
		c.echConfig,
	)

	logInfo("[传输层] 使用 %s 模式: %s (ECH: %v, Yamux: %v)",
		c.transport.Name(),
		c.config.ServerAddr,
		c.config.EnableECH,
		c.config.EnableYamux)

	// 启动本地 SOCKS5 代理
	var err error
	c.listener, err = net.Listen("tcp", c.config.LocalAddr)
	if err != nil {
		return fmt.Errorf("监听失败: %w", err)
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.running = true

	logInfo("[代理] 服务器启动: %s", c.config.LocalAddr)

	go c.acceptLoop()

	return nil
}

// Stop 停止客户端
func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return
	}

	c.running = false
	if c.cancel != nil {
		c.cancel()
	}
	if c.listener != nil {
		c.listener.Close()
	}
	if c.transport != nil {
		c.transport.Close()
	}

	logInfo("[代理] 服务已停止")
}

// IsRunning 返回运行状态
func (c *Client) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// GetLocalAddr 返回本地监听地址
func (c *Client) GetLocalAddr() string {
	if c.listener != nil {
		return c.listener.Addr().String()
	}
	return ""
}

// ======================== 连接测试 ========================

// TestResult 连接测试结果
type TestResult struct {
	Success  bool
	Latency  int64  // 毫秒
	Error    string
	HttpCode int
}

// TestConnection 测试代理连接（通过代理访问测试网站）
func (c *Client) TestConnection(testURL string) *TestResult {
	if testURL == "" {
		testURL = "https://cloudflare.com"
	}

	localAddr := c.GetLocalAddr()
	if localAddr == "" {
		return &TestResult{Success: false, Error: "代理未启动"}
	}

	return testProxyConnection(localAddr, testURL)
}

// TestProxy 测试指定代理地址的连接
func TestProxy(proxyAddr, testURL string) *TestResult {
	if testURL == "" {
		testURL = "https://cloudflare.com"
	}
	return testProxyConnection(proxyAddr, testURL)
}

func testProxyConnection(proxyAddr, testURL string) *TestResult {
	start := time.Now()

	// 创建 SOCKS5 代理拨号器
	dialer, err := newSocks5Dialer(proxyAddr)
	if err != nil {
		return &TestResult{Success: false, Error: fmt.Sprintf("创建代理失败: %v", err)}
	}

	// 创建 HTTP 客户端
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	// 发送请求
	resp, err := client.Get(testURL)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return &TestResult{
			Success: false,
			Latency: latency,
			Error:   err.Error(),
		}
	}
	defer resp.Body.Close()

	return &TestResult{
		Success:  resp.StatusCode >= 200 && resp.StatusCode < 400,
		Latency:  latency,
		HttpCode: resp.StatusCode,
	}
}

// 简单的 SOCKS5 拨号器
type socks5Dialer struct {
	proxyAddr string
}

func newSocks5Dialer(proxyAddr string) (*socks5Dialer, error) {
	return &socks5Dialer{proxyAddr: proxyAddr}, nil
}

func (d *socks5Dialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", d.proxyAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// SOCKS5 握手
	// 发送: VER NMETHODS METHODS
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}

	// 读取响应: VER METHOD
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		conn.Close()
		return nil, errors.New("SOCKS5 握手失败")
	}

	// 解析目标地址
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)

	// 发送 CONNECT 请求
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// 读取响应
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp[:4]); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 连接失败: %d", resp[1])
	}

	// 跳过绑定地址
	switch resp[3] {
	case 0x01: // IPv4
		io.ReadFull(conn, resp[:6])
	case 0x03: // Domain
		io.ReadFull(conn, resp[:1])
		io.ReadFull(conn, make([]byte, int(resp[0])+2))
	case 0x04: // IPv6
		io.ReadFull(conn, resp[:18])
	}

	return conn, nil
}

func (c *Client) acceptLoop() {
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			if c.running {
				logError("Accept 错误: %v", err)
			}
			return
		}
		go c.handleConnection(conn)
	}
}

func (c *Client) handleConnection(conn net.Conn) {
	// OOM 防护：检查连接数限制
	if !acquireConnection() {
		conn.Close()
		return
	}
	defer releaseConnection()
	defer conn.Close()

	// 解析 SOCKS5 请求
	target, initialData, err := parseSocks5(conn)
	if err != nil {
		logError("SOCKS5 解析错误: %v", err)
		return
	}

	logInfo("[SOCKS5] %s -> %s", conn.RemoteAddr(), target)

	// 建立隧道连接
	tunnel, err := c.transport.Dial()
	if err != nil {
		logError("隧道连接失败: %v", err)
		return
	}
	defer tunnel.Close()

	// 发送 CONNECT 请求
	if err := tunnel.Connect(target, initialData); err != nil {
		logError("CONNECT 失败: %v", err)
		return
	}

	logInfo("[代理] %s 已连接: %s", conn.RemoteAddr(), target)

	// 双向转发
	relay(conn, tunnel)
}

// fetchECHConfig 获取 ECH 配置（通过 DoH 查询 HTTPS 记录）
func (c *Client) fetchECHConfig() ([]byte, error) {
	domain := c.config.ECHDomain
	if domain == "" {
		domain = "cloudflare-ech.com"
	}

	dnsServer := c.config.DNSServer
	if dnsServer == "" {
		dnsServer = "dns.alidns.com/dns-query"
	}

	return queryECHConfigDoH(domain, dnsServer)
}

// ======================== SOCKS5 协议解析 ========================

func parseSocks5(conn net.Conn) (string, []byte, error) {
	buf := make([]byte, 256)

	// 读取版本和方法数
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", nil, err
	}

	if buf[0] != 0x05 {
		return "", nil, errors.New("不支持的 SOCKS 版本")
	}

	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return "", nil, err
	}

	// 回复：无需认证
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", nil, err
	}

	// 读取请求
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", nil, err
	}

	if buf[0] != 0x05 || buf[1] != 0x01 {
		return "", nil, errors.New("不支持的 SOCKS5 命令")
	}

	var host string
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return "", nil, err
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // 域名
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", nil, err
		}
		domainLen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return "", nil, err
		}
		host = string(buf[:domainLen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return "", nil, err
		}
		host = net.IP(buf[:16]).String()
	default:
		return "", nil, errors.New("不支持的地址类型")
	}

	// 读取端口
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", nil, err
	}
	port := int(buf[0])<<8 | int(buf[1])

	target := fmt.Sprintf("%s:%d", host, port)

	// 回复成功
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(reply); err != nil {
		return "", nil, err
	}

	return target, nil, nil
}

// ======================== 数据转发 ========================

func relay(local net.Conn, tunnel TunnelConn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// local -> tunnel
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if err != nil {
				return
			}
			if err := tunnel.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	// tunnel -> local
	go func() {
		defer wg.Done()
		for {
			data, err := tunnel.Read()
			if err != nil {
				return
			}
			if _, err := local.Write(data); err != nil {
				return
			}
		}
	}()

	wg.Wait()
}

// ======================== ECH DoH 查询（从 Windows 内核移植） ========================

const typeHTTPS = 65

// queryECHConfigDoH 通过 DoH 查询 HTTPS 记录获取 ECH 配置
func queryECHConfigDoH(domain, dnsServer string) ([]byte, error) {
	echBase64, err := queryHTTPSRecord(domain, dnsServer)
	if err != nil {
		return nil, fmt.Errorf("DNS 查询失败: %w", err)
	}
	if echBase64 == "" {
		return nil, errors.New("未找到 ECH 参数")
	}
	raw, err := base64.StdEncoding.DecodeString(echBase64)
	if err != nil {
		return nil, fmt.Errorf("ECH 解码失败: %w", err)
	}
	return raw, nil
}

// queryHTTPSRecord 通过 DoH 查询 HTTPS 记录
func queryHTTPSRecord(domain, dnsServer string) (string, error) {
	dohURL := dnsServer
	if !strings.HasPrefix(dohURL, "https://") && !strings.HasPrefix(dohURL, "http://") {
		dohURL = "https://" + dohURL
	}
	return queryDoH(domain, dohURL)
}

// queryDoH 执行 DoH 查询（用于获取 ECH 配置）
func queryDoH(domain, dohURL string) (string, error) {
	u, err := url.Parse(dohURL)
	if err != nil {
		return "", fmt.Errorf("无效的 DoH URL: %v", err)
	}

	dnsQuery := buildDNSQuery(domain, typeHTTPS)
	dnsBase64 := base64.RawURLEncoding.EncodeToString(dnsQuery)

	q := u.Query()
	q.Set("dns", dnsBase64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("DoH 请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH 服务器返回错误: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 DoH 响应失败: %v", err)
	}

	return parseDNSResponse(body)
}

func buildDNSQuery(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 512)
	query = append(query, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return query
}

func parseDNSResponse(response []byte) (string, error) {
	if len(response) < 12 {
		return "", errors.New("响应过短")
	}
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount == 0 {
		return "", errors.New("无应答记录")
	}

	offset := 12
	for offset < len(response) && response[offset] != 0 {
		offset += int(response[offset]) + 1
	}
	offset += 5

	for i := 0; i < int(ancount); i++ {
		if offset >= len(response) {
			break
		}
		if response[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(response) && response[offset] != 0 {
				offset += int(response[offset]) + 1
			}
			offset++
		}
		if offset+10 > len(response) {
			break
		}
		rrType := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 8
		dataLen := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2
		if offset+int(dataLen) > len(response) {
			break
		}
		data := response[offset : offset+int(dataLen)]
		offset += int(dataLen)

		if rrType == typeHTTPS {
			if ech := parseHTTPSRecord(data); ech != "" {
				return ech, nil
			}
		}
	}
	return "", nil
}

func parseHTTPSRecord(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	offset := 2
	if offset < len(data) && data[offset] == 0 {
		offset++
	} else {
		for offset < len(data) && data[offset] != 0 {
			offset += int(data[offset]) + 1
		}
		offset++
	}
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		if offset+int(length) > len(data) {
			break
		}
		value := data[offset : offset+int(length)]
		offset += int(length)
		if key == 5 { // ECH 参数
			return base64.StdEncoding.EncodeToString(value)
		}
	}
	return ""
}

// ======================== WebSocket Transport ========================

type TunnelConn interface {
	Connect(target string, initialData []byte) error
	Read() ([]byte, error)
	Write(data []byte) error
	Close() error
}

type WebSocketTransport struct {
	serverAddr string
	serverIP   string
	token      string
	useECH     bool
	useYamux   bool
	echConfig  []byte

	sessionMu sync.Mutex
	session   *yamux.Session
	wsConn    *websocket.Conn
}

func NewWebSocketTransport(serverAddr, serverIP, token string, useECH, useYamux bool, echConfig []byte) *WebSocketTransport {
	return &WebSocketTransport{
		serverAddr: serverAddr,
		serverIP:   serverIP,
		token:      token,
		useECH:     useECH,
		useYamux:   useYamux,
		echConfig:  echConfig,
	}
}

func (t *WebSocketTransport) Name() string {
	var name string
	if t.useYamux {
		name = "WebSocket+Yamux"
	} else {
		name = "WebSocket"
	}
	if t.useECH {
		name += "+ECH"
	} else {
		name += "+TLS"
	}
	return name
}

func (t *WebSocketTransport) Close() {
	t.sessionMu.Lock()
	defer t.sessionMu.Unlock()

	if t.session != nil {
		t.session.Close()
		t.session = nil
	}
	if t.wsConn != nil {
		t.wsConn.Close()
		t.wsConn = nil
	}
}

func (t *WebSocketTransport) Dial() (TunnelConn, error) {
	if !t.useYamux {
		return t.dialSimple()
	}

	t.sessionMu.Lock()
	defer t.sessionMu.Unlock()

	// 复用现有 session
	if t.session != nil && !t.session.IsClosed() {
		stream, err := t.session.Open()
		if err == nil {
			return &YamuxStreamConn{stream: stream.(*yamux.Stream)}, nil
		}
		logInfo("[Yamux] session.Open 失败，重建连接: %v", err)
		t.session.Close()
		if t.wsConn != nil {
			t.wsConn.Close()
		}
		t.session = nil
		t.wsConn = nil
	}

	// 建立新连接
	wsConn, err := t.dialWebSocket()
	if err != nil {
		return nil, err
	}

	wsNetConn := &wsConnAdapter{conn: wsConn}

	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second

	session, err := yamux.Client(wsNetConn, cfg)
	if err != nil {
		wsConn.Close()
		return nil, fmt.Errorf("yamux session error: %w", err)
	}

	t.session = session
	t.wsConn = wsConn

	stream, err := session.Open()
	if err != nil {
		session.Close()
		wsConn.Close()
		t.session = nil
		t.wsConn = nil
		return nil, fmt.Errorf("yamux stream error: %w", err)
	}

	logInfo("[Yamux] 新建 session 并打开 stream")
	return &YamuxStreamConn{stream: stream.(*yamux.Stream)}, nil
}

func (t *WebSocketTransport) dialSimple() (TunnelConn, error) {
	wsConn, err := t.dialWebSocket()
	if err != nil {
		return nil, err
	}
	logInfo("[WebSocket] 新建简单协议连接")
	return &SimpleWSConn{conn: wsConn}, nil
}

func (t *WebSocketTransport) dialWebSocket() (*websocket.Conn, error) {
	host, port, path, err := parseServerAddr(t.serverAddr)
	if err != nil {
		return nil, err
	}

	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	var tlsCfg *tls.Config

	if t.useECH && len(t.echConfig) > 0 {
		tlsCfg, err = buildTLSConfigWithECH(host, t.echConfig)
		if err != nil {
			return nil, err
		}
	} else {
		tlsCfg = &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS13,
		}
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 10 * time.Second,
	}

	if t.token != "" {
		dialer.Subprotocols = []string{t.token}
	}

	// 自定义 Dial 以支持 socket 保护（VPN 必须）
	dialer.NetDial = func(network, address string) (net.Conn, error) {
		targetAddr := address
		if t.serverIP != "" {
			_, p, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			targetAddr = net.JoinHostPort(t.serverIP, p)
		}
		
		conn, err := net.DialTimeout(network, targetAddr, 10*time.Second)
		if err != nil {
			return nil, err
		}
		
		// 保护 socket，防止 VPN 流量循环
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if file, err := tcpConn.File(); err == nil {
				fd := int(file.Fd())
				if !protectSocket(fd) {
					logError("警告: 无法保护 socket fd=%d", fd)
				}
				file.Close() // File() 会复制 fd，需要关闭
			}
		}
		
		return conn, nil
	}

	wsConn, _, err := dialer.Dial(wsURL, nil)
	return wsConn, err
}

func parseServerAddr(addr string) (host, port, path string, err error) {
	// 解析 host:port/path 格式
	path = "/"
	if idx := strings.Index(addr, "/"); idx != -1 {
		path = addr[idx:]
		addr = addr[:idx]
	}

	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		// 没有端口，默认 443
		host = addr
		port = "443"
		err = nil
	}

	return
}

func buildTLSConfigWithECH(serverName string, echConfig []byte) (*tls.Config, error) {
	// Go 1.23+ 原生支持 ECH
	return &tls.Config{
		ServerName:                     serverName,
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: echConfig,
		EncryptedClientHelloRejectionVerify: func(cs tls.ConnectionState) error {
			return errors.New("服务器拒绝 ECH")
		},
	}, nil
}

// ======================== WebSocket 连接实现 ========================

type SimpleWSConn struct {
	conn      *websocket.Conn
	connected bool
	mu        sync.Mutex
}

func (c *SimpleWSConn) Connect(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	connectMsg := fmt.Sprintf("CONNECT:%s|%s", target, string(initialData))
	if err := c.conn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil {
		return err
	}

	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return err
	}

	response := string(msg)
	if strings.HasPrefix(response, "ERROR:") {
		return errors.New(response)
	}
	if response != "CONNECTED" {
		return fmt.Errorf("unexpected response: %s", response)
	}

	c.connected = true
	return nil
}

func (c *SimpleWSConn) Read() ([]byte, error) {
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	if len(msg) > 0 {
		str := string(msg)
		if str == "PING" {
			c.conn.WriteMessage(websocket.TextMessage, []byte("PONG"))
			return c.Read()
		}
		if str == "PONG" {
			return c.Read()
		}
	}

	return msg, nil
}

func (c *SimpleWSConn) Write(data []byte) error {
	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (c *SimpleWSConn) Close() error {
	return c.conn.Close()
}

// ======================== Yamux Stream 连接实现 ========================

type YamuxStreamConn struct {
	stream    *yamux.Stream
	connected bool
}

func (c *YamuxStreamConn) Connect(target string, initialData []byte) error {
	// Yamux 协议：发送 "host:port\n" + 可选的初始数据（与 Windows 内核一致）
	connectMsg := target + "\n"
	if _, err := c.stream.Write([]byte(connectMsg)); err != nil {
		return err
	}
	// 如果有初始数据，一并发送
	if len(initialData) > 0 {
		if _, err := c.stream.Write(initialData); err != nil {
			return err
		}
	}
	c.connected = true
	return nil
}

func (c *YamuxStreamConn) Read() ([]byte, error) {
	buf := make([]byte, 32*1024)
	n, err := c.stream.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (c *YamuxStreamConn) Write(data []byte) error {
	_, err := c.stream.Write(data)
	return err
}

func (c *YamuxStreamConn) Close() error {
	return c.stream.Close()
}

// ======================== WebSocket -> net.Conn 适配器 ========================

type wsConnAdapter struct {
	conn       *websocket.Conn
	readBuf    []byte
	readOffset int
	mu         sync.Mutex
}

func (w *wsConnAdapter) Read(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.readOffset < len(w.readBuf) {
		n := copy(b, w.readBuf[w.readOffset:])
		w.readOffset += n
		return n, nil
	}

	_, msg, err := w.conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	n := copy(b, msg)
	if n < len(msg) {
		w.readBuf = msg
		w.readOffset = n
	} else {
		w.readBuf = nil
		w.readOffset = 0
	}

	return n, nil
}

func (w *wsConnAdapter) Write(b []byte) (int, error) {
	err := w.conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsConnAdapter) Close() error {
	return w.conn.Close()
}

func (w *wsConnAdapter) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *wsConnAdapter) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

func (w *wsConnAdapter) SetDeadline(t time.Time) error {
	if err := w.conn.SetReadDeadline(t); err != nil {
		return err
	}
	return w.conn.SetWriteDeadline(t)
}

func (w *wsConnAdapter) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

func (w *wsConnAdapter) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

// ======================== 导出给 Android 的简化接口 ========================

// Version 返回版本号
func Version() string {
	return "1.0.0"
}

// StartProxy 启动代理（简化接口）
// echDomain: ECH 查询域名（如 "cloudflare-ech.com"）
// echDohServer: ECH 用的 DOH 服务器地址（如 "dns.alidns.com/dns-query"，无需 https://）
func StartProxy(serverAddr, serverIP, token, localAddr string, enableECH, enableYamux bool, echDomain, echDohServer string) (string, error) {
	if echDomain == "" {
		echDomain = "cloudflare-ech.com"
	}
	if echDohServer == "" {
		echDohServer = "dns.alidns.com/dns-query"
	}
	// 自动补全 https:// 前缀
	if !strings.HasPrefix(echDohServer, "https://") && !strings.HasPrefix(echDohServer, "http://") {
		echDohServer = "https://" + echDohServer
	}
	cfg := &Config{
		ServerAddr:  serverAddr,
		ServerIP:    serverIP,
		Token:       token,
		LocalAddr:   localAddr,
		EnableECH:   enableECH,
		EnableYamux: enableYamux,
		ECHDomain:   echDomain,
		DNSServer:   echDohServer,
	}

	client, err := Start(cfg)
	if err != nil {
		return "", err
	}

	return client.GetLocalAddr(), nil
}

// EncodeBase64 Base64 编码（工具函数）
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 Base64 解码（工具函数）
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
