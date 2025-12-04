package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/asciimoth/socks/common"
	"github.com/asciimoth/socks/internal"
)

func PassAll(_, _ string) bool {
	return true
}

func DirectLoopback(_, address string) bool {
	if address == "localhost" {
		return false
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return true
	}
	if host == "localhost" {
		return false
	}
	if net.ParseIP(host).IsLoopback() {
		return false
	}
	return true
}

// Static type assertions
var (
	_ net.Conn       = &packetConn5{}
	_ net.PacketConn = &packetConn5{}
)

type packetConn5 struct {
	conn          net.Conn
	defaultHeader []byte
	pool          common.BufferPool
	onclose       func()
}

func (pc *packetConn5) Close() error {
	pc.onclose()
	return pc.conn.Close()
}

func (pc *packetConn5) LocalAddr() net.Addr {
	return pc.conn.LocalAddr()
}

func (pc *packetConn5) RemoteAddr() net.Addr {
	return pc.conn.RemoteAddr() // TODO: Add alt RemoteAddr
}

func (pc *packetConn5) SetDeadline(t time.Time) error {
	return pc.conn.SetDeadline(t)
}

func (pc *packetConn5) SetReadDeadline(t time.Time) error {
	return pc.conn.SetReadDeadline(t)
}

func (pc *packetConn5) SetWriteDeadline(t time.Time) error {
	return pc.conn.SetWriteDeadline(t)
}

func (pc *packetConn5) Write(b []byte) (n int, err error) {
	buf := common.GetBuffer(pc.pool, len(pc.defaultHeader)+len(b))
	defer common.PutBuffer(pc.pool, buf)
	buf = buf[:0]

	buf = append(buf, pc.defaultHeader...)
	buf = append(buf, b...)

	n, err = pc.conn.Write(buf)
	if err != nil {
		return 0, err
	}
	n = max(0, n-len(pc.defaultHeader))
	return n, nil
}

func (pc *packetConn5) Read(b []byte) (n int, err error) {
	n, _, err = internal.Read5UDP(pc.pool, pc.conn, b, false)
	return
}

func (pc *packetConn5) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return internal.Read5UDP(pc.pool, pc.conn, p, true)
}

func (pc *packetConn5) WriteToIpPort(p []byte, ip net.IP, port uint16) (n int, err error) {
	return internal.Write5ToUDPaddr(pc.pool, pc.conn, p, ip, port)
}

func (pc *packetConn5) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return internal.Write5ToUDPFQDN(pc.pool, pc.conn, p, addr.String())
}

type Credentials struct {
	User     string
	Password string
}

type listener5 struct {
	addr net.Addr
	conn net.Conn
}

func (l *listener5) Addr() net.Addr {
	return l.addr
}

func (l *listener5) Close() error {
	return l.conn.Close()
}

func (l *listener5) Accept() (net.Conn, error) {
	// TODO: Use addr & port as RemoteAddr
	_, err := internal.Read5TCPResponse(l.conn)
	if err != nil {
		l.conn.Close()
	}
	return l.conn, err
}

type Client5 struct {
	ProxyNet    string
	ProxyAddr   string
	Dialer      common.Dialer
	Credentials *Credentials
	Resolver    common.Resolver
	Pool        common.BufferPool
}

func (c *Client5) dialer() common.Dialer {
	if c.Dialer == nil {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	return c.Dialer
}

func (c *Client5) proxynet() string {
	if c.ProxyNet == "" {
		return "tcp"
	}
	return c.ProxyNet
}

func (c *Client5) proxyaddr() string {
	if !strings.Contains(c.ProxyAddr, ":") {
		// Default port
		return net.JoinHostPort(c.ProxyAddr, "1080")
	}
	return c.ProxyAddr
}

func (c *Client5) resolver() common.Resolver {
	if c.Resolver == nil {
		return net.DefaultResolver
	}
	return c.Resolver
}

func (c *Client5) lookupPort(ctx context.Context, network, strport string) (port int, err error) {
	port, err = strconv.Atoi(strport)
	if err == nil {
		return port, nil
	}
	// TODO: If strport is "" -> err missinng port
	port, err = c.resolver().LookupPort(ctx, network, strport)
	return port, err
}

func (c *Client5) request(ctx context.Context, cmd common.Cmd, network, address string) ([]byte, error) {
	// TODO: Check network type
	host, strport, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("too long hostname: %s", host)
	}
	port, err := c.lookupPort(ctx, network, strport)
	if err != nil {
		// TODO: Better error
		return nil, err
	}
	atyp := common.DomAddr
	addrlen := len([]byte(host)) + 1
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			atyp = common.IP4Addr
			addrlen = 4
		} else {
			atyp = common.IP6Addr
			addrlen = 16
		}
	}
	request := make([]byte, 0, 6+addrlen)
	request = append(request, common.V5, byte(cmd), 0, byte(atyp))
	switch atyp {
	case common.IP4Addr:
		request = append(request, ip.To4()...)
	case common.IP6Addr:
		request = append(request, ip.To16()...)
	case common.DomAddr:
		request = append(request, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))

	return request, nil
}

func (c *Client5) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "udp4" || network == "udp6" || network == "udp" {
		return c.dialPacket(ctx, network, address)
	}

	// TODO: Check network
	// TODO: Filter addr
	proxy, err := c.dialer()(ctx, c.proxynet(), c.proxyaddr())
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	err = internal.Run5Auth(proxy, &c.Credentials.User, &c.Credentials.Password)
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	request, err := c.request(ctx, common.CmdConnect, network, address)
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	reply, err := internal.Read5TCPResponse(proxy)
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	if reply.Rep != common.SuccReply {
		return nil, fmt.Errorf("reply status: %s", reply.Rep.String())
	}

	return proxy, nil
}

// To listen, address = "0.0.0.0:0"
func (c *Client5) DialPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	// TODO: Filter addr
	// TODO: Check network
	return c.dialPacket(ctx, network, address)
}

func (c *Client5) dialPacket(ctx context.Context, network, address string) (*packetConn5, error) {
	if address == "" {
		if network == "udp6" {
			address = "[::]:0"
		} else {
			address = "0.0.0.0:0"
		}
	}

	header, err := internal.BuildHeader5UDP(address)
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	proxy, err := c.dialer()(ctx, c.proxynet(), c.proxyaddr())
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	err = internal.Run5Auth(proxy, &c.Credentials.User, &c.Credentials.Password)
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	request, err := c.request(ctx, common.CmdUDPAssoc, network, address)
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	reply, err := internal.Read5TCPResponse(proxy)
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	if reply.Rep != common.SuccReply {
		return nil, fmt.Errorf("reply status: %s", reply.Rep.String())
	}

	onclose := func() {
		_ = proxy.Close()
	}

	udpaddr := reply.ToNetAddr(network)

	udpconn, err := c.dialer()(ctx, udpaddr.Network(), udpaddr.String())

	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	return &packetConn5{
		conn:          udpconn,
		defaultHeader: header,
		pool:          c.Pool,
		onclose:       onclose,
	}, nil
}

func (c *Client5) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	// TODO: Filter

	proxy, err := c.dialer()(ctx, c.proxynet(), c.proxyaddr())
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	err = internal.Run5Auth(proxy, &c.Credentials.User, &c.Credentials.Password)
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	request, err := c.request(ctx, common.CmdBind, network, address)
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	reply, err := internal.Read5TCPResponse(proxy)
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	if reply.Rep != common.SuccReply {
		return nil, fmt.Errorf("reply status: %s", reply.Rep.String())
	}

	return &listener5{
		conn: proxy,
		addr: reply.ToNetAddr(network),
	}, nil
}

type listener4 struct {
	addr internal.NetAddr
	conn net.Conn
}

func (l *listener4) Addr() net.Addr {
	return l.addr
}

func (l *listener4) Close() error {
	return l.conn.Close()
}

func (l *listener4) Accept() (net.Conn, error) {
	_, _, err := internal.Read4TCPResponse(l.conn)
	if err != nil {
		l.conn.Close()
	}
	return l.conn, err
}

type Client4 struct {
	// Resolve hostname locally instead of passing it to proxy
	// For socks4 LocalResolve == false means socks4a
	LocalResolve bool
	UserID       string
	ProxyNet     string
	ProxyAddr    string
	// Function to dial connection to socks server
	Dialer         common.Dialer
	DirectListener common.Listener
	Resolver       common.Resolver
	DirectFilter   common.DirectFilter
}

func (c *Client4) dialFilter(network, address string) bool {
	filter := c.DirectFilter
	if filter == nil {
		filter = DirectLoopback
	}
	return filter(network, address)
}

func (c *Client4) listener() common.Listener {
	if c.DirectListener == nil {
		return (&net.ListenConfig{}).Listen
	}
	return c.DirectListener
}

func (c *Client4) resolver() common.Resolver {
	if c.Resolver == nil {
		return net.DefaultResolver
	}
	return c.Resolver
}

func (c *Client4) dialer() common.Dialer {
	if c.Dialer == nil {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	return c.Dialer
}

func (c *Client4) lookupPort(ctx context.Context, network, strport string) (port int, err error) {
	// TODO: If strport is "" -> err missinng port
	port, err = strconv.Atoi(strport)
	if err == nil {
		return port, nil
	}
	port, err = c.resolver().LookupPort(ctx, network, strport)
	return port, err
}

func (c *Client4) proxynet() string {
	if c.ProxyNet == "" {
		return "tcp4"
	}
	return c.ProxyNet
}

func (c *Client4) proxyaddr() string {
	if !strings.Contains(c.ProxyAddr, ":") {
		// Default port
		return net.JoinHostPort(c.ProxyAddr, "1080")
	}
	return c.ProxyAddr
}

func (c *Client4) request(ctx context.Context, cmd common.Cmd, network, address string) (net.Conn, net.IP, uint16, error) {
	if network != "tcp4" && network != "tcp" {
		// TODO: Better error
		return nil, nil, 0, net.UnknownNetworkError(network)
	}

	host, strport, err := net.SplitHostPort(address)
	if err != nil {
		// TODO: Better error
		return nil, nil, 0, err
	}
	port, err := c.lookupPort(ctx, "tcp4", strport)
	if err != nil {
		// TODO: Better error
		return nil, nil, 0, err
	}
	var request []byte = nil
	if !c.LocalResolve {
		// request = c.request4a(cmd, host, uint16(port))
		request = internal.Make4aTCPRequest(cmd, host, uint16(port), c.UserID)
	} else {
		ips, err := c.resolver().LookupIP(ctx, "ip4", host)
		if err != nil {
			// TODO: Better error
			return nil, nil, 0, err
		}
		// request = c.request4(cmd, ips[0].To4(), uint16(port))
		request = internal.Make4TCPRequest(cmd, ips[0].To4(), uint16(port), c.UserID)
	}

	proxy, err := c.dialer()(ctx, c.proxynet(), c.proxyaddr())
	if err != nil {
		// TODO: Better error
		return nil, nil, 0, err
	}

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		proxy.Close()
		// TODO: Better error
		return nil, nil, 0, err
	}

	incIp, incPort, err := internal.Read4TCPResponse(proxy)
	if err != nil {
		proxy.Close()
		return nil, nil, 0, err
	}

	// Use server host:port if returned one is 0.0.0.0
	if incIp.IsUnspecified() {
		h, p, err := net.SplitHostPort(proxy.RemoteAddr().String())
		if err == nil {
			incIp = net.ParseIP(h)
			pp, err := strconv.Atoi(p)
			if err == nil {
				incPort = uint16(pp)
			}
		}
	}
	return proxy, incIp, incPort, nil
}

func (c *Client4) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if !c.dialFilter(network, address) {
		return c.listener()(ctx, network, address)
	}
	conn, ip, port, err := c.request(ctx, common.CmdBind, network, address)
	if err != nil {
		return nil, err
	}

	return &listener4{
		conn: conn,
		addr: internal.NetAddr{
			Net: "tcp4",
			Host: net.JoinHostPort(
				ip.String(),
				strconv.Itoa(int(port)),
			),
		},
	}, nil
}

func (c *Client4) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if !c.dialFilter(network, address) {
		return c.dialer()(ctx, network, address)
	}
	conn, _, _, err := c.request(ctx, common.CmdConnect, network, address)
	if err != nil {
		return nil, err
	}
	return conn, err
}
