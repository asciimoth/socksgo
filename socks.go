package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/asciimoth/socks/common"
	"github.com/asciimoth/socks/internal"
	"github.com/xtaci/smux"
)

var networks = []string{
	"tcp", "tcp4", "tcp6",
	"udp", "udp4", "udp6",
}

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

type ClientConfig struct {
	GostMbind       bool
	GostUDPTun      bool
	SpawnUDPProbber bool
	Dialer          common.Dialer
	DirectListener  common.Listener
	Resolver        common.Resolver
	// Resolve hostname locally instead of passing it to proxy
	// For socks4 LocalResolve == false means socks4a
	LocalResolve bool
	DirectFilter common.DirectFilter
	Credentials  *Credentials
	Pool         common.BufferPool
}

func (cc *ClientConfig) pool() common.BufferPool {
	if cc == nil {
		return nil
	}
	return cc.Pool
}

func (cc *ClientConfig) isGostUDPTun() bool {
	if cc == nil {
		return false
	}
	return cc.GostUDPTun
}

func (cc *ClientConfig) isGostMbind() bool {
	if cc == nil {
		return false
	}
	return cc.GostMbind
}

func (cc *ClientConfig) isSpawnUDPProbber() bool {
	if cc == nil {
		return false
	}
	return cc.SpawnUDPProbber
}

func (cc *ClientConfig) user() string {
	if cc == nil {
		return ""
	}
	if cc.Credentials == nil {
		return ""
	}
	return cc.Credentials.User
}

func (cc *ClientConfig) nuser() *string {
	if cc == nil || cc.Credentials == nil {
		return nil
	}
	return &cc.Credentials.User
}

func (cc *ClientConfig) npass() *string {
	if cc == nil || cc.Credentials == nil {
		return nil
	}
	return &cc.Credentials.Password
}

func (cc *ClientConfig) dialFilter(network, address string) bool {
	filter := DirectLoopback
	if cc != nil && cc.DirectFilter != nil {
		filter = cc.DirectFilter
	}
	return filter(network, address)
}

func (cc *ClientConfig) listener() common.Listener {
	if cc == nil || cc.DirectListener == nil {
		return (&net.ListenConfig{}).Listen
	}
	return cc.DirectListener
}

func (cc *ClientConfig) resolver() common.Resolver {
	if cc == nil || cc.Resolver == nil {
		return net.DefaultResolver
	}
	return cc.Resolver
}

func (cc *ClientConfig) dialer() common.Dialer {
	if cc == nil || cc.Dialer == nil {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	return cc.Dialer
}

func (cc *ClientConfig) lookupPort(ctx context.Context, network, strport string) (port int, err error) {
	// TODO: If strport is "" -> err missinng port
	port, err = strconv.Atoi(strport)
	if err == nil {
		return port, nil
	}
	port, err = cc.resolver().LookupPort(ctx, network, strport)
	return port, err
}

type packetConn5 struct {
	conn          net.Conn
	defaultHeader []byte
	pool          common.BufferPool
	onclose       func()
	gostTun       bool // If enabled, defaultHeader should bt provided without RSV
	la, ra        net.Addr
}

func (pc *packetConn5) Close() error {
	pc.onclose()
	return pc.conn.Close()
}

func (pc *packetConn5) LocalAddr() net.Addr {
	if pc.la != nil {
		return pc.la
	}
	return pc.conn.LocalAddr()
}

func (pc *packetConn5) RemoteAddr() net.Addr {
	if pc.la != nil {
		return pc.ra
	}
	return pc.conn.RemoteAddr()
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
	if pc.gostTun && len(b) > 65535 {
		b = b[:65535]
	}

	buf := internal.GetBuffer(pc.pool, len(pc.defaultHeader)+len(b))
	defer internal.PutBuffer(pc.pool, buf)
	buf = buf[:0]

	if pc.gostTun {
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(b)))
	}
	buf = append(buf, pc.defaultHeader...)
	buf = append(buf, b...)

	n, err = pc.conn.Write(buf)
	if err != nil {
		return 0, err
	}
	if pc.gostTun {
		n = max(0, n-len(pc.defaultHeader)-2)
	} else {
		n = max(0, n-len(pc.defaultHeader))
	}
	return n, nil
}

func (pc *packetConn5) Read(b []byte) (n int, err error) {
	if pc.gostTun {
		n, _, err = internal.Read5UDPTun(pc.pool, pc.conn, b, false)
	} else {
		n, _, err = internal.Read5UDP(pc.pool, pc.conn, b, false)
	}
	return
}

// TODO: ReadFromUDP, WrtiteToUDP with FQDN packets ignoring

func (pc *packetConn5) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if pc.gostTun {
		return internal.Read5UDPTun(pc.pool, pc.conn, p, true)
	}
	return internal.Read5UDP(pc.pool, pc.conn, p, true)
}

func (pc *packetConn5) WriteToIpPort(p []byte, ip net.IP, port uint16) (n int, err error) {
	return internal.Write5ToUDPaddr(pc.pool, pc.conn, p, ip, port, pc.gostTun)
}

func (pc *packetConn5) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return internal.Write5ToUDPFQDN(pc.pool, pc.conn, p, addr.String(), pc.gostTun)
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

type listener5mux struct {
	addr    net.Addr
	session *smux.Session
}

func (l *listener5mux) Addr() net.Addr {
	return l.addr
}

func (l *listener5mux) Close() error {
	return l.session.Close()
}

func (l *listener5mux) Accept() (net.Conn, error) {
	// TODO: Use addr & port as RemoteAddr
	return l.session.AcceptStream()
}

type Client5 struct {
	ProxyNet  string
	ProxyAddr string
	Config    *ClientConfig
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

func (c *Client5) request(ctx context.Context, cmd common.Cmd, network, address string) (net.Conn, internal.Socks5Reply, error) {
	var reply internal.Socks5Reply

	if !slices.Contains(networks, network) {
		// TODO: Better error
		return nil, reply, net.UnknownNetworkError(network)
	}

	host, strport, err := net.SplitHostPort(address)
	if err != nil {
		// TODO: Better error
		return nil, reply, err
	}
	port, err := c.Config.lookupPort(ctx, network, strport)
	if err != nil {
		// TODO: Better error
		return nil, reply, err
	}

	proxy, err := c.Config.dialer()(ctx, c.proxynet(), c.proxyaddr())
	if err != nil {
		// TODO: Better error
		return nil, reply, err
	}

	err = internal.Run5Auth(proxy, c.Config.nuser(), c.Config.npass())
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, reply, err
	}

	// request, err := c.request(ctx, common.CmdConnect, network, address)
	request, err := internal.Make5Request(cmd, host, uint16(port))
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, reply, err
	}

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, reply, err
	}

	reply, err = internal.Read5TCPResponse(proxy)
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, reply, err
	}

	if reply.Rep != common.SuccReply {
		// TODO: Better error
		proxy.Close()
		return nil, reply, fmt.Errorf("reply status: %s", reply.Rep.String())
	}

	return proxy, reply, nil
}

func (c *Client5) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "udp4" || network == "udp6" || network == "udp" {
		return c.dialPacket(ctx, network, address)
	}

	proxy, _, err := c.request(ctx, common.CmdConnect, network, address)
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	return proxy, nil
}

// To listen, address = "0.0.0.0:0"
func (c *Client5) DialPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	// TODO: Filter addr
	// TODO: Check network type
	if c.Config.isGostUDPTun() {
		return c.setupUDPTun(ctx, network, "", address)
	}
	return c.dialPacket(ctx, network, address)
}

func (c *Client5) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	// TODO: Filter addr
	// TODO: Check network type
	if c.Config.isGostUDPTun() {
		return c.setupUDPTun(ctx, network, address, "")
	}
	// Standart UDP ASSOC doesn't support listen addr specification
	return c.dialPacket(ctx, network, "")
}

func (c *Client5) dialPacket(ctx context.Context, network, address string) (*packetConn5, error) {
	if address == "" {
		if network == "udp6" {
			address = "[::]:0"
		} else {
			address = "0.0.0.0:0"
		}
	}

	header, err := internal.BuildHeader5UDP(address, false)
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	proxy, reply, err := c.request(ctx, common.CmdUDPAssoc, network, address)
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	onclose := func() {
		_ = proxy.Close()
	}

	udpaddr := reply.ToNetAddr(network)

	udpconn, err := c.Config.dialer()(ctx, udpaddr.Network(), udpaddr.String())

	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	pc := &packetConn5{
		conn:          udpconn,
		defaultHeader: header,
		pool:          c.Config.pool(),
		onclose:       onclose,
	}

	if c.Config.isSpawnUDPProbber() {
		go func() {
			buf := []byte{0}
			for {
				_, err := proxy.Read(buf)
				if err != nil {
					_ = proxy.Close()
					_ = pc.Close()
					return
				}
			}
		}()
	}

	return pc, nil
}

func (c *Client5) setupUDPTun(ctx context.Context, network, laddr, raddr string) (*packetConn5, error) {
	var (
		header []byte
		err    error
	)
	if raddr != "" {
		header, err = internal.BuildHeader5UDP(raddr, true)
		if err != nil {
			// TODO: Better error
			return nil, err
		}
	}
	if laddr == "" {
		if network == "udp6" {
			laddr = "[::]:0"
		} else {
			laddr = "0.0.0.0:0"
		}
	}

	proxy, reply, err := c.request(ctx, common.CmdGostUDPTun, network, laddr)
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	var n net.Addr
	if reply.IsUnspecified() {
		h, _, err := net.SplitHostPort(proxy.RemoteAddr().String())
		if err != nil {
			// TODO: Better error
			proxy.Close()
			return nil, err
		}
		n = internal.NetAddr{
			Host: net.JoinHostPort(h, strconv.Itoa(int(reply.Port))),
			Net:  proxy.RemoteAddr().Network(),
		}
	} else {
		n = reply.ToNetAddr(network)
	}

	return &packetConn5{
		conn:          proxy,
		defaultHeader: header,
		pool:          c.Config.pool(),
		gostTun:       true,
		la:            n,
	}, nil
}

func (c *Client5) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	// TODO: Check network
	// TODO: Filter

	cmd := common.CmdBind
	if c.Config.isGostMbind() {
		cmd = common.CmdGostMuxBind
	}

	proxy, reply, err := c.request(ctx, cmd, network, address)
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	if c.Config.isGostMbind() {
		session, err := smux.Server(proxy, nil)
		if err != nil {
			// TODO: Better error
			proxy.Close()
			return nil, err
		}
		return &listener5mux{
			session: session,
			addr:    reply.ToNetAddr(network),
		}, nil
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
	ProxyNet  string
	ProxyAddr string
	Config    *ClientConfig
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
	port, err := c.Config.lookupPort(ctx, "tcp4", strport)
	if err != nil {
		// TODO: Better error
		return nil, nil, 0, err
	}
	var request []byte = nil
	if !c.Config.LocalResolve {
		// request = c.request4a(cmd, host, uint16(port))
		request = internal.Make4aTCPRequest(cmd, host, uint16(port), c.Config.user())
	} else {
		ips, err := c.Config.resolver().LookupIP(ctx, "ip4", host)
		if err != nil {
			// TODO: Better error
			return nil, nil, 0, err
		}
		// request = c.request4(cmd, ips[0].To4(), uint16(port))
		request = internal.Make4TCPRequest(cmd, ips[0].To4(), uint16(port), c.Config.user())
	}

	proxy, err := c.Config.dialer()(ctx, c.proxynet(), c.proxyaddr())
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
	if !c.Config.dialFilter(network, address) {
		return c.Config.listener()(ctx, network, address)
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
	if !c.Config.dialFilter(network, address) {
		return c.Config.dialer()(ctx, network, address)
	}
	conn, _, _, err := c.request(ctx, common.CmdConnect, network, address)
	if err != nil {
		return nil, err
	}
	return conn, err
}
