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
)

const (
	V4 = 0x04
	V5 = 0x05

	V4Name  = "socks4"
	V4aName = "socks4a"
	V5aName = "socks5"

	CmdConnect  Cmd = 0x01
	CmdBind     Cmd = 0x02
	CmdUDPAssoc Cmd = 0x03

	Cmdr4Granted       CmdResp4 = 90
	Cmdr4Rejected      CmdResp4 = 91
	Cmdr4IdentRequired CmdResp4 = 92
	Cmdr4IdentFailed   CmdResp4 = 93

	NoAuth    AuthMethod = 0x0
	GSSAuth   AuthMethod = 0x1
	PassAuth  AuthMethod = 0x02
	NoAccAuth AuthMethod = 0xff

	IP4Addr AddrType = 0x01
	IP6Addr AddrType = 0x04
	DomAddr AddrType = 0x03

	SuccReply        ReplyStatus = 0x0
	FailReply        ReplyStatus = 0x1
	DisallowReply    ReplyStatus = 0x2
	NetUnreachReply  ReplyStatus = 0x3
	HostUnreachReply ReplyStatus = 0x4
	ConnRefusedReply ReplyStatus = 0x5
	TTLExpiredReply  ReplyStatus = 0x6
	CmdNotSuppReply  ReplyStatus = 0x7
	AddrNotSuppReply ReplyStatus = 0x8
)

// TODO: Implement splitHostPort(address string) (string, int, error)

type Resolver interface {
	LookupPort(ctx context.Context, network, service string) (port int, err error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

type Dialer = func(ctx context.Context, network, address string) (net.Conn, error)

type Listener = func(ctx context.Context, network, address string) (net.Listener, error)

// Return true if dial should go through a proxy, false if direct
type DirectFilter = func(network, address string) bool

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

type ReplyStatus uint8

func (r ReplyStatus) String() string {
	switch r {
	case SuccReply:
		return "succeeded"
	case FailReply:
		return "general SOCKS server failure"
	case DisallowReply:
		return "connection not allowed by ruleset"
	case NetUnreachReply:
		return "hetwork unreachable"
	case HostUnreachReply:
		return "host unreachable"
	case ConnRefusedReply:
		return "connection refused"
	case TTLExpiredReply:
		return "TTL expired"
	case CmdNotSuppReply:
		return "command not supported"
	case AddrNotSuppReply:
		return "address type not supported"
	default:
		return "reply code no" + strconv.Itoa(int(r))
	}
}

type AddrType uint8

func (a AddrType) String() string {
	switch a {
	case IP4Addr:
		return "IPv4 addr"
	case IP6Addr:
		return "IPv6 addr"
	case DomAddr:
		return "domain name addr"
	default:
		return "addr type no" + strconv.Itoa(int(a))
	}
}

type AuthMethod uint8

func (a AuthMethod) String() string {
	if a >= 0x3 && a <= 0x7f {
		return "IANA assiged auth"
	}
	if a >= 0x80 && a <= 0xfe {
		return "private auth method"
	}
	switch a {
	case NoAuth:
		return "no auth required"
	case GSSAuth:
		return "GSS auth"
	case PassAuth:
		return "user-pass auth"
	case NoAccAuth:
		return "no acceptable auth methods"
	default:
		return "auth method no" + strconv.Itoa(int(a))
	}
}

type Cmd uint8

func (cmd Cmd) String() string {
	switch cmd {
	case CmdConnect:
		return "cmd connect"
	case CmdBind:
		return "cmd bind"
	case CmdUDPAssoc:
		return "cmd UDP associate"
	default:
		return "cmd no" + strconv.Itoa(int(cmd))
	}
}

type CmdResp4 uint8

func (cmd CmdResp4) String() string {
	switch cmd {
	case Cmdr4Granted:
		return "request granted"
	case Cmdr4Rejected:
		return "request rejected or failed"
	case Cmdr4IdentFailed:
		return "request rejected becasue socks server cannot connect to identd on the client"
	case Cmdr4IdentRequired:
		return "request rejected because the client program and identd report different user-ids"
	default:
		return "socks response cmd no" + strconv.Itoa(int(cmd))
	}
}

type addr struct {
	Net  string
	Host string
}

func (a addr) Network() string {
	return a.Net
}

func (a addr) String() string {
	return a.Host
}

// type conn struct {
// 	net.Conn
// 	LAddr net.Addr
// 	RAddr net.Addr
// }
//
// func (c *conn) RemoteAddr() net.Addr {
// 	if c.RAddr == nil {
// 		return c.Conn.RemoteAddr()
// 	}
// 	return c.RAddr
// }
//
// func (c *conn) LocalAddr() net.Addr {
// 	if c.LAddr == nil {
// 		return c.Conn.LocalAddr()
// 	}
// 	return c.LAddr
// }

type Credentials struct {
	User, Password string
}

// NOTE: Do we need this?
func readBytes(conn net.Conn, count int) ([]byte, error) {
	pack := make([]byte, count)
	_, err := io.ReadFull(conn, pack)
	if err != nil {
		return nil, err
	}
	return pack, nil
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
	_, err := readResponse5(l.conn)
	if err != nil {
		l.conn.Close()
	}
	return l.conn, err
}

type reply5 struct {
	Rep  ReplyStatus
	Atyp AddrType
	Addr []byte
	Port uint16
}

func (r reply5) toNetAddr(network string) net.Addr {
	switch r.Atyp {
	case IP4Addr:
		n := "tcp4"
		if strings.HasPrefix(network, "udp") {
			n = "udp4"
		}
		return addr{
			Net:  n,
			Host: net.JoinHostPort(net.IP(r.Addr).To4().String(), strconv.Itoa(int(r.Port))),
		}
	case IP6Addr:
		n := "tcp6"
		if strings.HasPrefix(network, "udp") {
			n = "udp6"
		}
		return addr{
			Net:  n,
			Host: net.JoinHostPort(net.IP(r.Addr).To16().String(), strconv.Itoa(int(r.Port))),
		}
	case DomAddr:
		return addr{
			Net:  network,
			Host: string(r.Addr),
		}
	}
	return nil
}

func readResponse5(conn net.Conn) (reply5, error) {
	header, err := readBytes(conn, 4)
	if err != nil {
		return reply5{}, err
	}
	// TODO: Check that first byte is 0x05
	rep := ReplyStatus(header[1])
	atyp := AddrType(header[3])
	if rep != SuccReply {
		return reply5{}, fmt.Errorf("%s", rep.String())
	}
	var addr []byte
	var port uint16
	switch atyp {
	case IP4Addr:
		host, err := readBytes(conn, 6)
		if err != nil {
			return reply5{}, err
		}
		addr = host[0:4]
		port = binary.BigEndian.Uint16(host[4:6])
	case IP6Addr:
		host, err := readBytes(conn, 18)
		if err != nil {
			return reply5{}, err
		}
		addr = host[0:16]
		port = binary.BigEndian.Uint16(host[16:18])
	case DomAddr:
		// TODO: Optimise
		ln, err := readBytes(conn, 1)
		if err != nil {
			return reply5{}, err
		}
		addr, err = readBytes(conn, int(ln[0]))
		if err != nil {
			return reply5{}, err
		}
	default:
		return reply5{}, fmt.Errorf("unknown address type: %s", atyp.String())
	}
	return reply5{
		Rep:  rep,
		Atyp: atyp,
		Addr: addr,
		Port: port,
	}, nil
}

type Client5 struct {
	ProxyNet    string
	ProxyAddr   string
	Dialer      Dialer
	Credentials *Credentials
	Resolver    Resolver
}

func (c *Client5) dialer() Dialer {
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

func (c *Client5) resolver() Resolver {
	if c.Resolver == nil {
		return net.DefaultResolver
	}
	return c.Resolver
}

func (c *Client5) lookupPort(ctx context.Context, network, strport string) (port int, err error) {
	// TODO: If strport is "" -> err missinng port
	port, err = strconv.Atoi(strport)
	if err == nil {
		return port, nil
	}
	port, err = c.resolver().LookupPort(ctx, network, strport)
	return port, err
}

func (c *Client5) passAuth(conn net.Conn) error {
	user := []byte(c.Credentials.User)
	pass := []byte(c.Credentials.Password)
	if len(user) > 255 {
		return fmt.Errorf("too big username: %d bytes", len(user))
	}
	if len(pass) > 255 {
		return fmt.Errorf("too big password: %d bytes", len(pass))
	}

	pack := make([]byte, 0, 3+len(user)+len(pass))
	pack = append(pack, 1)
	pack = append(pack, byte(len(user)))
	pack = append(pack, user...)
	pack = append(pack, byte(len(pass)))
	pack = append(pack, pass...)

	_, err := io.Copy(conn, bytes.NewReader(pack))
	if err != nil {
		// TODO: Better error
		return err
	}

	var resp [2]byte
	i, err := conn.Read(resp[:])
	if err != nil {
		// TODO: Better error
		return err
	} else if i != 2 {
		// TODO: Better error
		return fmt.Errorf("Unexpected EOF")
	}

	if resp[1] != 0 {
		// TODO: Better error
		return fmt.Errorf("user/pass auth failed")
	}

	return nil
}

func (c *Client5) auth(conn net.Conn) error {
	var pack []byte
	if c.Credentials == nil {
		pack = []byte{V5, 1, byte(NoAuth)}
	} else {
		pack = []byte{V5, 2, byte(NoAuth), byte(PassAuth)}
	}
	_, err := io.Copy(conn, bytes.NewReader(pack))
	if err != nil {
		// TODO: Better error
		return err
	}
	var resp [2]byte
	i, err := conn.Read(resp[:])
	if err != nil {
		return err
	} else if i != 2 {
		// TODO: Better error
		return fmt.Errorf("Unexpected EOF")
	}
	method := AuthMethod(resp[1])
	switch method {
	case NoAuth:
		return nil
	case PassAuth:
		if c.Credentials == nil {
			// TODO: Better error
			return fmt.Errorf("wrong auth method reqested by server: %s", method)
		}
		return c.passAuth(conn)
	default:
		// TODO: Better error
		return fmt.Errorf("wrong auth method reqested by server: %s", method)
	}
}

func (c *Client5) request(ctx context.Context, cmd Cmd, network, address string) ([]byte, error) {
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
	atyp := DomAddr
	addrlen := len([]byte(host)) + 1
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			atyp = IP4Addr
			addrlen = 4
		} else {
			atyp = IP6Addr
			addrlen = 16
		}
	}
	request := make([]byte, 0, 6+addrlen)
	request = append(request, V5, byte(cmd), 0, byte(atyp))
	switch atyp {
	case IP4Addr:
		request = append(request, ip.To4()...)
	case IP6Addr:
		request = append(request, ip.To16()...)
	case DomAddr:
		request = append(request, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))

	return request, nil
}

func (c *Client5) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	// TODO: Filter
	proxy, err := c.dialer()(ctx, c.proxynet(), c.proxyaddr())
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	err = c.auth(proxy)
	if err != nil {
		proxy.Close()
		return nil, err
	}

	request, err := c.request(ctx, CmdConnect, network, address)
	if err != nil {
		proxy.Close()
		return nil, err
	}

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	_, err = readResponse5(proxy)
	if err != nil {
		proxy.Close()
		return nil, err
	}

	return proxy, nil
}

func (c *Client5) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	// TODO: Filter

	proxy, err := c.dialer()(ctx, c.proxynet(), c.proxyaddr())
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	err = c.auth(proxy)
	if err != nil {
		proxy.Close()
		return nil, err
	}

	request, err := c.request(ctx, CmdBind, network, address)
	if err != nil {
		proxy.Close()
		return nil, err
	}

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	reply, err := readResponse5(proxy)
	if err != nil {
		proxy.Close()
		return nil, err
	}

	return &listener5{
		conn: proxy,
		addr: reply.toNetAddr(network),
	}, nil
}

func readResponse4(conn net.Conn) (net.IP, uint16, error) {
	var resp [8]byte
	i, err := conn.Read(resp[:])
	if err != nil {
		return nil, 0, err
	} else if i != 8 {
		// TODO: Better error
		return nil, 0, fmt.Errorf("Unexpected EOF")
	}

	switch CmdResp4(resp[1]) {
	case Cmdr4Granted:
		return net.IP(resp[4:8]), binary.BigEndian.Uint16(resp[2:4]), nil
	default:
		// TODO: Better error
		return nil, 0, fmt.Errorf("%s", CmdResp4(resp[1]).String())
	}
}

type listener4 struct {
	addr addr
	conn net.Conn
}

func (l *listener4) Addr() net.Addr {
	return l.addr
}

func (l *listener4) Close() error {
	return l.conn.Close()
}

func (l *listener4) Accept() (net.Conn, error) {
	_, _, err := readResponse4(l.conn)
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
	Dialer         Dialer
	DirectListener Listener
	Resolver       Resolver
	DirectFilter   DirectFilter
}

func (c *Client4) dialFilter(network, address string) bool {
	filter := c.DirectFilter
	if filter == nil {
		filter = DirectLoopback
	}
	return filter(network, address)
}

func (c *Client4) listener() Listener {
	if c.DirectListener == nil {
		return (&net.ListenConfig{}).Listen
	}
	return c.DirectListener
}

func (c *Client4) resolver() Resolver {
	if c.Resolver == nil {
		return net.DefaultResolver
	}
	return c.Resolver
}

func (c *Client4) dialer() Dialer {
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

func (c *Client4) request4(cmd Cmd, ip4 net.IP, port uint16) []byte {
	request := make([]byte, 0, 9+len(c.UserID))
	request = append(request, V4)
	request = append(request, byte(cmd))
	request = binary.BigEndian.AppendUint16(request, port)
	request = append(request, ip4...)
	request = append(request, []byte(c.UserID)...)
	request = append(request, 0)
	return request
}

func (c *Client4) request4a(cmd Cmd, host string, port uint16) []byte {
	request := make([]byte, 0, 10+len(c.UserID)+len(host))
	request = append(request, V4)
	request = append(request, byte(cmd))
	request = binary.BigEndian.AppendUint16(request, port)
	request = append(request, 0, 0, 0, 1)
	request = append(request, []byte(c.UserID)...)
	request = append(request, 0)
	request = append(request, []byte(host)...)
	request = append(request, 0)
	return request
}

func (c *Client4) request(ctx context.Context, cmd Cmd, network, address string) (net.Conn, net.IP, uint16, error) {
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
		request = c.request4a(cmd, host, uint16(port))
	} else {
		ips, err := c.resolver().LookupIP(ctx, "ip4", host)
		if err != nil {
			// TODO: Better error
			return nil, nil, 0, err
		}
		request = c.request4(cmd, ips[0].To4(), uint16(port))
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

	incIp, incPort, err := readResponse4(proxy)
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
	conn, ip, port, err := c.request(ctx, CmdBind, network, address)
	if err != nil {
		return nil, err
	}

	return &listener4{
		conn: conn,
		addr: addr{
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
	conn, _, _, err := c.request(ctx, CmdConnect, network, address)
	if err != nil {
		return nil, err
	}
	return conn, err
}
