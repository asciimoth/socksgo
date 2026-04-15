package socksgo

import (
	"io"
	"net"

	"github.com/asciimoth/gonnect/helpers"
)

func wrapEOF(err error) error {
	if err == nil {
		return nil
	}
	if helpers.ClosedNetworkErrToNil(err) == nil {
		return io.EOF
	}
	return err
}

type wsCoderConn struct {
	net.Conn
	Laddr net.Addr
	Raddr net.Addr
}

func (c *wsCoderConn) LocalAddr() net.Addr {
	if c.Laddr != nil {
		return c.Laddr
	}
	return c.Conn.LocalAddr()
}

func (c *wsCoderConn) RemoteAddr() net.Addr {
	if c.Raddr != nil {
		return c.Raddr
	}
	return c.Conn.RemoteAddr()
}

func (c *wsCoderConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	err = wrapEOF(err)
	return
}

func (c *wsCoderConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	err = wrapEOF(err)
	return
}

func (c *wsCoderConn) Close() error {
	return wrapEOF(c.Conn.Close())
}

var (
	_ net.Conn = &wsCoderConn{}
)
