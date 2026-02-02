package socksgo

import (
	"bytes"
	"context"
	"io"
	"net"

	"github.com/asciimoth/bufpool"
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
		_ = proxy.Close()
		return
	}

	var request []byte
	request, err = protocol.BuildSocks5TCPRequest(cmd, address, c.Pool)
	if err != nil {
		_ = proxy.Close()
		return
	}
	defer bufpool.PutBuffer(c.Pool, request)

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		_ = proxy.Close()
		return
	}

	stat, addr, err = protocol.ReadSocks5TCPReply(proxy, c.Pool)
	if err != nil {
		_ = proxy.Close()
		return
	}
	if !stat.Ok() {
		_ = proxy.Close()
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
) (protocol.Socks5UDPClient, error) {
	if !c.IsUDPAllowed() {
		return nil, ErrUDPDisallowed
	}
	proxy, naddr, err := c.Request(ctx, protocol.CmdUDPAssoc, addr)
	if err != nil {
		return nil, err
	}
	naddr.NetTyp = "udp"

	onclose := func() {
		_ = proxy.Close()
	}

	udpconn, err := c.GetPacketDialer()(ctx, addr.Network(), naddr.String())
	if err != nil {
		_ = proxy.Close()
		return nil, err
	}
	pc := protocol.NewSocks5UDPClientAssoc(udpconn, &addr, c.Pool, onclose)

	if !c.DoNotSpawnUDPAsocProbber {
		go func() {
			buf := []byte{0}
			for {
				_, err := proxy.Read(buf)
				if err != nil {
					_ = proxy.Close()
					_ = udpconn.Close()
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
) (protocol.Socks5UDPClient, error) {
	if !c.IsUDPAllowed() {
		return nil, ErrUDPDisallowed
	}

	var (
		// header []byte
		err error
	)

	proxy, naddr, err := c.Request(ctx, protocol.CmdGostUDPTun, laddr)
	if err != nil {
		return nil, err
	}
	naddr.NetTyp = "udp"

	if naddr.IsUnspecified() && proxy.RemoteAddr() != nil {
		h, _, err := net.SplitHostPort(proxy.RemoteAddr().String())
		if err != nil {
			_ = proxy.Close()
			return nil, err
		}
		naddr = protocol.AddrFromString(
			h,
			naddr.Port,
			proxy.RemoteAddr().Network(),
		)
	}

	return protocol.NewSocks5UDPClientTUN(proxy, naddr, raddr, c.Pool), nil
}

type clientListener5 struct {
	addr net.Addr
	conn net.Conn
	pool bufpool.Pool
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
		_ = l.conn.Close()
	}
	if !stat.Ok() {
		return nil, RejectdError{stat}
	}
	return l.conn, err
}

type clientListener5mux struct {
	addr    net.Addr
	conn    net.Conn
	session *smux.Session
}

func (l *clientListener5mux) Addr() net.Addr {
	return l.addr
}

func (l *clientListener5mux) Close() error {
	err := l.session.Close()
	if err == nil {
		err = l.conn.Close()
	} else {
		_ = l.conn.Close()
	}
	return err
}

func (l *clientListener5mux) Accept() (net.Conn, error) {
	// TODO: Use addr & port as RemoteAddr
	return l.session.AcceptStream()
}
