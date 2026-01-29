package socksgo

import (
	"io"
	"net"
	"time"

	"github.com/gorilla/websocket"
)

var _ net.Conn = &wsConn{}

type wsConn struct {
	*websocket.Conn
	buf []byte
}

func (c *wsConn) Read(b []byte) (n int, err error) {
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

func (c *wsConn) Write(b []byte) (n int, err error) {
	err = c.WriteMessage(websocket.BinaryMessage, b)
	n = len(b)
	return
}

func (c *wsConn) SetDeadline(t time.Time) error {
	return c.Conn.NetConn().SetDeadline(t)
}
