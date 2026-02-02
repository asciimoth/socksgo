package socksgo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"

	"github.com/asciimoth/bufpool"
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
	request, err = protocol.BuildSocsk4TCPRequest(
		cmd,
		address,
		c.Auth.User(),
		c.Pool,
	)
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

	stat, addr, err = protocol.ReadSocks4TCPReply(proxy)
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
	if addr.IsUnspecified() && addr.Port == 0 {
		proxyAddr := protocol.AddrFromNetAddr(proxy.RemoteAddr())
		proxyAddr.NetTyp = addr.NetTyp
		addr = proxyAddr
	}
	return
}

type clientListener4 struct {
	addr     protocol.Addr
	conn     net.Conn
	accepted bool
}

func (l *clientListener4) Addr() net.Addr {
	return l.addr
}

func (l *clientListener4) Close() error {
	return l.conn.Close()
}

func (l *clientListener4) Accept() (net.Conn, error) {
	if l.accepted {
		return nil, &net.OpError{
			Op:   "accept",
			Net:  "tcp",
			Addr: l.addr,
			Err:  errors.New("use of closed network connection"),
		}
	}
	stat, _, err := protocol.ReadSocks4TCPReply(l.conn)
	l.accepted = true
	if err != nil {
		_ = l.conn.Close()
	}
	if !stat.Ok() {
		return nil, RejectdError{stat}
	}
	return l.conn, nil
}
