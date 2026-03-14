package socksgo

import (
	"bytes"
	"context"
	"io"
	"net"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

// resolveUnspecifiedAddr resolves an unspecified address using the proxy's remote address.
// If SplitHostPort fails, returns the original naddr unchanged (graceful degradation).
func resolveUnspecifiedAddr(
	proxy net.Conn,
	naddr protocol.Addr,
) protocol.Addr {
	if !naddr.IsUnspecified() || proxy.RemoteAddr() == nil {
		return naddr
	}
	h, _, err := net.SplitHostPort(proxy.RemoteAddr().String())
	if err != nil {
		// If we can't parse the remote addr, return naddr unchanged
		// This is an extreme edge case - proxy.RemoteAddr() should always be parseable
		return naddr
	}
	return protocol.AddrFromString(h, naddr.Port, proxy.RemoteAddr().Network())
}

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

	proxy, err = c.authenticate(proxy)
	if err != nil {
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

// authenticate performs SOCKS5 authentication and closes the connection on error.
func (c *Client) authenticate(proxy net.Conn) (net.Conn, error) {
	proxy, _, err := protocol.RunAuth(proxy, c.Pool, c.Auth)
	if err != nil {
		_ = proxy.Close()
		return nil, err
	}
	return proxy, nil
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

	proxy, naddr, err := c.Request(ctx, protocol.CmdGostUDPTun, laddr)
	if err != nil {
		return nil, err
	}
	naddr = resolveUnspecifiedAddr(proxy, naddr)
	naddr.NetTyp = "udp"

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
	return internal.JoinNetErrors(l.session.Close(), l.conn.Close())
}

func (l *clientListener5mux) Accept() (net.Conn, error) {
	return l.session.AcceptStream()
}
