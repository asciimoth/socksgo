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

	CmdConnect Cmd = 0x01
	CmdBind    Cmd = 0x02

	Cmdr4Granted       CmdResp4 = 90
	Cmdr4Rejected      CmdResp4 = 91
	Cmdr4IdentRequired CmdResp4 = 92
	Cmdr4IdentFailed   CmdResp4 = 93
)

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

type Cmd uint8

func (cmd Cmd) String() string {
	switch cmd {
	case CmdConnect:
		return "cmd connect"
	case CmdBind:
		return "cmd bind"
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
