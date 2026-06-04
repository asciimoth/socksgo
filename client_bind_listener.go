package socksgo

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type oneShotBindAccept struct {
	conn net.Conn
	addr net.Addr

	mu        sync.Mutex
	accepting bool
	ready     chan struct{}
	waitClose chan struct{}
	finalErr  error
}

func newOneShotBindAccept(conn net.Conn, addr net.Addr) *oneShotBindAccept {
	return &oneShotBindAccept{
		conn: conn,
		addr: addr,
	}
}

func (a *oneShotBindAccept) Accept(
	readReply func() error,
) (net.Conn, error) {
	for {
		a.mu.Lock()
		if a.finalErr != nil {
			err := a.finalErr
			a.mu.Unlock()
			return nil, err
		}
		if a.waitClose != nil {
			wait := a.waitClose
			a.mu.Unlock()
			<-wait
			continue
		}
		if a.accepting {
			ready := a.ready
			a.mu.Unlock()
			<-ready
			continue
		}
		a.accepting = true
		a.ready = make(chan struct{})
		a.mu.Unlock()
		break
	}

	if err := readReply(); err != nil {
		_ = a.conn.Close()
		a.finish(err)
		return nil, err
	}

	a.mu.Lock()
	if a.finalErr != nil {
		err := a.finalErr
		a.accepting = false
		ready := a.ready
		a.ready = nil
		a.mu.Unlock()
		if ready != nil {
			close(ready)
		}
		return nil, err
	}
	a.accepting = false
	a.waitClose = make(chan struct{})
	ready := a.ready
	a.ready = nil
	a.mu.Unlock()
	if ready != nil {
		close(ready)
	}

	return &bindAcceptedConn{
		Conn:    a.conn,
		onClose: func() { a.finish(bindListenerClosedError(a.addr)) },
	}, nil
}

func (a *oneShotBindAccept) Close() error {
	err := a.conn.Close()
	a.finish(bindListenerClosedError(a.addr))
	return err
}

func (a *oneShotBindAccept) finish(err error) {
	a.mu.Lock()
	if a.finalErr == nil {
		a.finalErr = err
	}
	a.accepting = false
	ready := a.ready
	a.ready = nil
	waitClose := a.waitClose
	a.waitClose = nil
	a.mu.Unlock()

	if ready != nil {
		close(ready)
	}
	if waitClose != nil {
		close(waitClose)
	}
}

type bindAcceptedConn struct {
	net.Conn

	closeOnce sync.Once
	onClose   func()
}

func (c *bindAcceptedConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(c.onClose)
	return err
}

func (c *bindAcceptedConn) ReadFrom(r io.Reader) (int64, error) {
	if tc, ok := c.Conn.(interface {
		ReadFrom(io.Reader) (int64, error) //nolint:inamedparam
	}); ok {
		return tc.ReadFrom(r)
	}
	return io.Copy(c.Conn, r)
}

func (c *bindAcceptedConn) WriteTo(writer io.Writer) (int64, error) {
	return (&tcpConnWrapper{Conn: c.Conn}).WriteTo(writer)
}

func (c *bindAcceptedConn) SetKeepAlive(keepalive bool) error {
	if tc, ok := c.Conn.(interface{ SetKeepAlive(bool) error }); ok { //nolint:inamedparam
		return tc.SetKeepAlive(keepalive)
	}
	return nil
}

func (c *bindAcceptedConn) SetKeepAliveConfig(
	config net.KeepAliveConfig,
) error {
	if tc, ok := c.Conn.(interface {
		SetKeepAliveConfig(net.KeepAliveConfig) error //nolint:inamedparam
	}); ok {
		return tc.SetKeepAliveConfig(config)
	}
	return nil
}

func (c *bindAcceptedConn) SetKeepAlivePeriod(d time.Duration) error {
	if tc, ok := c.Conn.(interface{ SetKeepAlivePeriod(time.Duration) error }); ok { //nolint:inamedparam
		return tc.SetKeepAlivePeriod(d)
	}
	return nil
}

func (c *bindAcceptedConn) SetLinger(sec int) error {
	if tc, ok := c.Conn.(interface{ SetLinger(int) error }); ok { //nolint:inamedparam
		return tc.SetLinger(sec)
	}
	return nil
}

func (c *bindAcceptedConn) SetNoDelay(noDelay bool) error {
	if tc, ok := c.Conn.(interface{ SetNoDelay(bool) error }); ok { //nolint:inamedparam
		return tc.SetNoDelay(noDelay)
	}
	return nil
}

func (c *bindAcceptedConn) CloseRead() error {
	if tc, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return tc.CloseRead()
	}
	return c.Close()
}

func (c *bindAcceptedConn) CloseWrite() error {
	if tc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return tc.CloseWrite()
	}
	return c.Close()
}

func bindListenerClosedError(addr net.Addr) error {
	return &net.OpError{
		Op:   "accept",
		Net:  "tcp",
		Addr: addr,
		Err:  errors.New("use of closed network connection"),
	}
}
