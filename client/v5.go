package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/asciimoth/socks/common"
	"github.com/asciimoth/socks/internal"
	"github.com/xtaci/smux"
)

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
	gostTun       bool // If enabled, defaultHeader should bt provided without RSV
	la, ra        net.Addr
}

func (pc *packetConn5) Close() error {
	if pc.onclose != nil {
		pc.onclose()
	}
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
	Config
}

func (c *Client5) request(
	ctx context.Context,
	cmd common.Cmd,
	network, address string,
) (net.Conn, internal.Socks5Reply, error) {
	var reply internal.Socks5Reply

	nettyp, ok := networks[network]

	if !ok {
		// TODO: Better error
		return nil, reply, net.UnknownNetworkError(network)
	}

	host, strport, err := net.SplitHostPort(address)
	if err != nil {
		// TODO: Better error
		return nil, reply, err
	}

	port, err := c.lookupPort(ctx, network, strport)
	if err != nil {
		// TODO: Better error
		return nil, reply, err
	}

	proxy, err := c.dial(ctx)
	if err != nil {
		// TODO: Better error
		return nil, reply, err
	}

	err = internal.Run5Auth(proxy, c.nuser(), c.npass())
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, reply, err
	}

	if c.LocalResolve {
		ips, err := c.resolver().LookupIP(ctx, nettyp, host)
		if err != nil {
			// TODO: Better error
			return nil, reply, err
		}
		host = ips[0].String()
	}

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
	if c.GostUDPTun {
		return c.setupUDPTun(ctx, network, "", address)
	}
	return c.dialPacket(ctx, network, address)
}

func (c *Client5) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	// TODO: Filter addr
	// TODO: Check network type
	if c.GostUDPTun {
		return c.setupUDPTun(ctx, network, address, "")
	}
	// Standart UDP ASSOC doesn't support listen addr specification
	return c.dialPacket(ctx, network, "")
}

func (c *Client5) dialPacket(
	ctx context.Context,
	network, address string,
) (*packetConn5, error) {
	if !c.udpAllowed() {
		// TODO: Better error
		return nil, errors.New("plaintext UDP is disallowed for tls proxies")
	}

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
	reply.Addr.Net = "udp"

	onclose := func() {
		_ = proxy.Close()
	}

	// udpaddr := reply.ToNetAddr(network)

	udpconn, err := c.netDialer()(ctx, network, reply.String())

	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	pc := &packetConn5{
		conn:          udpconn,
		defaultHeader: header,
		pool:          c.Pool,
		onclose:       onclose,
	}

	if c.SpawnUDPProbber {
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

func (c *Client5) setupUDPTun(
	ctx context.Context,
	network, laddr, raddr string,
) (*packetConn5, error) {
	if !c.udpAllowed() {
		// TODO: Better error
		return nil, errors.New("plaintext UDP is disallowed for tls proxies")
	}

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
		n = common.AddrFromDom(h, reply.Port, proxy.RemoteAddr().Network())
	} else {
		n = reply
	}

	return &packetConn5{
		conn:          proxy,
		defaultHeader: header,
		pool:          c.Pool,
		gostTun:       true,
		la:            n,
	}, nil
}

func (c *Client5) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	// TODO: Check network
	// TODO: Filter

	cmd := common.CmdBind
	if c.GostMbind {
		cmd = common.CmdGostMuxBind
	}

	proxy, reply, err := c.request(ctx, cmd, network, address)
	if err != nil {
		// TODO: Better error
		return nil, err
	}
	reply.Addr.Net = network

	if c.GostMbind {
		session, err := smux.Server(proxy, c.Smux.to())
		if err != nil {
			// TODO: Better error
			proxy.Close()
			return nil, err
		}
		return &listener5mux{
			session: session,
			addr:    reply,
		}, nil
	}

	return &listener5{
		conn: proxy,
		addr: reply,
	}, nil
}

func (c *Client5) lookup(
	ctx context.Context,
	cmd common.Cmd,
	network, address string,
) (*internal.Socks5Reply, error) {
	if cmd != common.CmdTorResolvePtr && network != "ip" && network != "ip4" && network != "ip6" {
		return nil, &net.DNSError{
			UnwrapErr:  net.UnknownNetworkError(network),
			Err:        fmt.Sprintf("network type is unsupported: %s", network),
			Name:       address,
			IsNotFound: true,
		}
	}

	if !c.TorLookup {
		return nil, &net.DNSError{
			UnwrapErr: ResolveDisabledErr,
			Err:       ResolveDisabledErr.Error(),
			Name:      address,
		}
	}

	proxy, err := c.dial(ctx)
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	// var err error
	// if proxy == nil {
	// 	proxy, err = c.dialer()(ctx, c.proxynet(), c.proxyaddr())
	// 	if err != nil {
	// 		// TODO: Better error
	// 		return nil, err
	// 	}
	// }

	err = internal.Run5Auth(proxy, c.nuser(), c.npass())
	if err != nil {
		// TODO: Better error
		proxy.Close()
		return nil, err
	}

	request, err := internal.Make5Request(cmd, address, 0)
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
	proxy.Close()

	if err != nil {
		// TODO: Better error
		return nil, err
	}

	if reply.Rep != common.SuccReply {
		// TODO: Better error
		return nil, fmt.Errorf("reply status: %s", reply.Rep.String())
	}

	return &reply, nil
}

func (c *Client5) LookupIP(ctx context.Context, network, address string) ([]net.IP, error) {
	if c.LocalResolve {
		return c.resolver().LookupIP(ctx, network, address)
	}

	if !c.dialFilter(network, address) {
		return c.resolver().LookupIP(ctx, network, address)
	}

	reply, err := c.lookup(ctx, common.CmdTorResolve, network, address)
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	if ip := reply.ToIP(); ip != nil {
		return []net.IP{ip}, nil
	}

	// TODO: Better error
	return nil, fmt.Errorf("wrong addr type in responce: %s", reply.Addr.Type.String())
}

func (c *Client5) LookupAddr(ctx context.Context, address string) ([]string, error) {
	if c.LocalResolve {
		return c.resolver().LookupAddr(ctx, address)
	}

	if !c.dialFilter("", address) {
		return c.resolver().LookupAddr(ctx, address)
	}

	reply, err := c.lookup(ctx, common.CmdTorResolvePtr, "", address)
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	return []string{reply.String()}, nil
}

func (c *Client5) String() string {
	return "[ socks 5 client ]\n" + c.Config.String()
}
