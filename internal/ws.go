package internal

import (
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

var _ net.Conn = &WSConn{}

type WSConn struct {
	*websocket.Conn
	buf []byte
}

func (c *WSConn) Read(b []byte) (n int, err error) {
	if len(c.buf) == 0 {
		var typ int
		for {
			typ, c.buf, err = c.ReadMessage()
			if err != nil {
				err = io.EOF
				_ = c.Close()
				return
			}
			if typ == websocket.BinaryMessage {
				break
			}
		}
	}
	n = copy(b, c.buf)
	c.buf = c.buf[n:]
	return
}

func (c *WSConn) Write(b []byte) (n int, err error) {
	err = c.WriteMessage(websocket.BinaryMessage, b)
	n = len(b)
	return
}

func (c *WSConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *WSConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *WSConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
