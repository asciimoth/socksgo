package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

func (c *Client) request5(
	ctx context.Context,
	cmd protocol.Cmd,
	address protocol.Addr,
) (
	proxy net.Conn,
	addr protocol.Addr,
	err error,
) {
	var (
		stat protocol.ReplyStatus
	)

	proxy, err = c.Connect(ctx)
	if err != nil {
		return
	}

	proxy, _, err = protocol.RunAuth(proxy, c.Pool, c.Auth)
	if err != nil {
		proxy.Close()
		return
	}

	var request []byte
	request, err = protocol.BuildSocks5TCPRequest(cmd, address, c.Pool)
	if err != nil {
		proxy.Close()
		return
	}
	defer internal.PutBuffer(c.Pool, request)

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		proxy.Close()
		return
	}

	stat, addr, err = protocol.ReadSocks5TCPReply(proxy, c.Pool)
	if err != nil {
		proxy.Close()
		return
	}
	if !stat.Ok() {
		proxy.Close()
		err = RejectdError{stat}
		return
	}

	// Use server host:port if returned one is 0.0.0.0
	if addr.IsUnspecified() {
		proxyAddr := protocol.AddrFromNetAddr(proxy.RemoteAddr())
		proxyAddr.NetTyp = addr.NetTyp
		proxyAddr.Port = addr.Port
		addr = proxyAddr
	}

	return
}

func (c *Client) dialPacket5(
	ctx context.Context,
	addr protocol.Addr,
) (*clientPacketConn5, error) {
	if !c.IsUDPAllowed() {
		return nil, ErrUDPDisallowed
	}

	buf := internal.GetBuffer(c.Pool, protocol.MAX_SOCKS_UDP_HEADER_LEN)
	defer internal.PutBuffer(c.Pool, buf)
	header := protocol.AppendSocks5UDPHeader(buf[:0], 0, addr)

	proxy, naddr, err := c.Request(ctx, protocol.CmdUDPAssoc, addr)
	if err != nil {
		return nil, err
	}
	naddr.NetTyp = "udp"

	onclose := func() {
		_ = proxy.Close()
	}

	udpconn, err := c.GetDialer()(ctx, addr.Network(), naddr.String())
	if err != nil {
		proxy.Close()
		return nil, err
	}

	pc := &clientPacketConn5{
		conn:          udpconn,
		defaultHeader: header,
		pool:          c.Pool,
		onclose:       onclose,
	}

	if !c.DoNotSpawnUDPAsocProbber {
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

func (c *Client) setupUDPTun5(
	ctx context.Context,
	laddr protocol.Addr,
	raddr *protocol.Addr,
) (*clientPacketConn5, error) {
	if !c.IsUDPAllowed() {
		return nil, ErrUDPDisallowed
	}

	var (
		header []byte
		err    error
	)

	if raddr != nil {
		buf := internal.GetBuffer(c.Pool, protocol.MAX_SOCKS_UDP_HEADER_LEN)
		defer internal.PutBuffer(c.Pool, buf)
		header = protocol.AppendSocks5UDPHeader(
			buf[:0],
			1, // We can use any non-zero number here
			*raddr,
		)
	}

	proxy, naddr, err := c.Request(ctx, protocol.CmdGostUDPTun, laddr)
	if err != nil {
		return nil, err
	}
	naddr.NetTyp = "udp"

	if naddr.IsUnspecified() && proxy.RemoteAddr() != nil {
		h, _, err := net.SplitHostPort(proxy.RemoteAddr().String())
		if err != nil {
			proxy.Close()
			return nil, err
		}
		naddr = protocol.AddrFromString(h, naddr.Port, proxy.RemoteAddr().Network())
	}

	return &clientPacketConn5{
		conn:          proxy,
		defaultHeader: header,
		pool:          c.Pool,
		gostTun:       true,
		la:            naddr,
		ra:            raddr,
	}, nil
}

type clientListener5 struct {
	addr net.Addr
	conn net.Conn
	pool protocol.BufferPool
}

func (l *clientListener5) Addr() net.Addr {
	return l.addr
}

func (l *clientListener5) Close() error {
	return l.conn.Close()
}

func (l *clientListener5) Accept() (net.Conn, error) {
	stat, _, err := protocol.ReadSocks5TCPReply(l.conn, l.pool)
	// TODO: Use addr & port as conn.RemoteAddr
	if err != nil {
		l.conn.Close()
	}
	if !stat.Ok() {
		return nil, RejectdError{stat}
	}
	return l.conn, err
}

type clientListener5mux struct {
	addr    net.Addr
	session *smux.Session
}

func (l *clientListener5mux) Addr() net.Addr {
	return l.addr
}

func (l *clientListener5mux) Close() error {
	return l.session.Close()
}

func (l *clientListener5mux) Accept() (net.Conn, error) {
	// TODO: Use addr & port as RemoteAddr
	return l.session.AcceptStream()
}

type clientPacketConn5 struct {
	conn          net.Conn
	defaultHeader []byte
	pool          protocol.BufferPool
	onclose       func()
	// If enabled, defaultHeader should be provided
	gostTun bool
	la, ra  net.Addr
}

func (pc *clientPacketConn5) Write(b []byte) (n int, err error) {
	// Trim b cause we do not support fragmentation
	if pc.gostTun && len(b) > 65535 {
		b = b[:65535]
	}

	buf := internal.GetBuffer(pc.pool, len(pc.defaultHeader)+len(b))
	defer internal.PutBuffer(pc.pool, buf)
	buf = buf[:0]

	if pc.gostTun {
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(b))) // RSV
		buf = append(buf, pc.defaultHeader[2:]...)               // Header without RSV
	} else {
		buf = append(buf, pc.defaultHeader...)
	}
	buf = append(buf, b...)

	n, err = pc.conn.Write(buf)
	if err != nil {
		return 0, err
	}

	n = max(0, n-len(pc.defaultHeader))
	return n, nil
}

func (pc *clientPacketConn5) Read(b []byte) (n int, err error) {
	n, _, err = protocol.ReadSocks5UDPPacket(pc.pool, pc.conn, b, true)
	return
}

// TODO: ReadFromUDP, WrtiteToUDP with FQDN packets ignoring

func (pc *clientPacketConn5) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return protocol.ReadSocks5UDPPacket(pc.pool, pc.conn, p, false)
}

func (pc *clientPacketConn5) WriteToIpPort(p []byte, ip net.IP, port uint16) (n int, err error) {
	return protocol.WriteSocks5UDPPacket(
		pc.pool, pc.conn, protocol.AddrFromIP(ip, port, "udp"), p,
	)
}

func (pc *clientPacketConn5) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return protocol.WriteSocks5UDPPacket(
		pc.pool, pc.conn, protocol.AddrFromNetAddr(addr), p,
	)
}

func (pc *clientPacketConn5) Close() error {
	err := pc.conn.Close()
	if pc.onclose != nil {
		pc.onclose()
	}
	if pc.defaultHeader != nil {
		pc.defaultHeader = nil
		internal.PutBuffer(pc.pool, pc.defaultHeader)
	}
	return err
}

func (pc *clientPacketConn5) LocalAddr() net.Addr {
	if pc.la != nil {
		return pc.la
	}
	return pc.conn.LocalAddr()
}

func (pc *clientPacketConn5) RemoteAddr() net.Addr {
	if pc.la != nil {
		return pc.ra
	}
	return pc.conn.RemoteAddr()
}

func (pc *clientPacketConn5) SetDeadline(t time.Time) error {
	return pc.conn.SetDeadline(t)
}

func (pc *clientPacketConn5) SetReadDeadline(t time.Time) error {
	return pc.conn.SetReadDeadline(t)
}

func (pc *clientPacketConn5) SetWriteDeadline(t time.Time) error {
	return pc.conn.SetWriteDeadline(t)
}
