package socksgo

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/gorilla/websocket"
)

var (
	_ net.Conn        = &wsConn{}
	_ gonnect.TCPConn = &wsConn{}
)

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

// TCPConn interface implementations

func (c *wsConn) ReadFrom(r io.Reader) (int64, error) {
	// Manually copy to avoid infinite recursion with io.Copy
	// (io.Copy prefers ReadFrom if available, causing recursion)
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			wn, werr := c.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

func (c *wsConn) WriteTo(w io.Writer) (int64, error) {
	// Manually copy to avoid infinite recursion with io.Copy
	// (io.Copy prefers WriteTo if available, causing recursion)
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := c.Read(buf)
		if n > 0 {
			wn, werr := w.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
	}
}

func (c *wsConn) SetKeepAlive(keepalive bool) error {
	// WebSocket doesn't support keepalive at this level
	return nil
}

func (c *wsConn) SetKeepAliveConfig(config net.KeepAliveConfig) error {
	// WebSocket doesn't support keepalive at this level
	return nil
}

func (c *wsConn) SetKeepAlivePeriod(d time.Duration) error {
	// WebSocket doesn't support keepalive at this level
	return nil
}

func (c *wsConn) SetLinger(sec int) error {
	// WebSocket doesn't support linger
	return nil
}

func (c *wsConn) SetNoDelay(noDelay bool) error {
	// WebSocket doesn't support no delay
	return nil
}

func (c *wsConn) CloseRead() error {
	return c.Close()
}

func (c *wsConn) CloseWrite() error {
	return c.Close()
}
