package socksgo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo/protocol"
)

var _ gonnect.TCPListener = &clientListener4{}

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

// TCPListener interface implementations

func (l *clientListener4) AcceptTCP() (gonnect.TCPConn, error) {
	conn, err := l.Accept()
	if err != nil {
		return nil, err
	}
	// The returned conn is the underlying net.Conn which should satisfy TCPConn
	if tcpConn, ok := conn.(gonnect.TCPConn); ok {
		return tcpConn, nil
	}
	// If it doesn't implement TCPConn, wrap it
	return &tcpConnWrapper{conn}, nil
}

func (l *clientListener4) SetDeadline(t time.Time) error {
	return l.conn.SetDeadline(t)
}

// tcpConnWrapper wraps a net.Conn to implement gonnect.TCPConn
type tcpConnWrapper struct {
	net.Conn
}

func (w *tcpConnWrapper) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(w, r)
}

func (w *tcpConnWrapper) WriteTo(writer io.Writer) (int64, error) {
	return io.Copy(writer, w)
}

func (w *tcpConnWrapper) SetKeepAlive(keepalive bool) error {
	if tc, ok := w.Conn.(gonnect.TCPConn); ok {
		return tc.SetKeepAlive(keepalive)
	}
	return nil
}

func (w *tcpConnWrapper) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	if tc, ok := w.Conn.(gonnect.TCPConn); ok {
		return tc.SetKeepAliveConfig(config)
	}
	return nil
}

func (w *tcpConnWrapper) SetKeepAlivePeriod(d time.Duration) error {
	if tc, ok := w.Conn.(gonnect.TCPConn); ok {
		return tc.SetKeepAlivePeriod(d)
	}
	return nil
}

func (w *tcpConnWrapper) SetLinger(sec int) error {
	if tc, ok := w.Conn.(gonnect.TCPConn); ok {
		return tc.SetLinger(sec)
	}
	return nil
}

func (w *tcpConnWrapper) SetNoDelay(noDelay bool) error {
	if tc, ok := w.Conn.(gonnect.TCPConn); ok {
		return tc.SetNoDelay(noDelay)
	}
	return nil
}

func (w *tcpConnWrapper) CloseRead() error {
	if tc, ok := w.Conn.(interface{ CloseRead() error }); ok {
		return tc.CloseRead()
	}
	return w.Close()
}

func (w *tcpConnWrapper) CloseWrite() error {
	if tc, ok := w.Conn.(interface{ CloseWrite() error }); ok {
		return tc.CloseWrite()
	}
	return w.Close()
}
