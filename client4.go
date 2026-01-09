package socks

import (
	"bytes"
	"context"
	"io"
	"net"

	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
)

func (c *Client) request4(
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

	var request []byte
	request, err = protocol.BuildSocsk4TCPRequest(cmd, address, c.Auth.User(), c.Pool)
	defer internal.PutBuffer(c.Pool, request)

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		proxy.Close()
		return
	}

	stat, addr, err = protocol.ReadSocks4TCPReply(proxy)
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
		addr = proxyAddr
	}
	return
}

type clientListener4 struct {
	addr protocol.Addr
	conn net.Conn
}

func (l *clientListener4) Addr() net.Addr {
	return l.addr
}

func (l *clientListener4) Close() error {
	return l.conn.Close()
}

func (l *clientListener4) Accept() (net.Conn, error) {
	stat, _, err := protocol.ReadSocks4TCPReply(l.conn)
	if err != nil {
		l.conn.Close()
	}
	if !stat.Ok() {
		return nil, RejectdError{stat}
	}
	return l.conn, nil
}
