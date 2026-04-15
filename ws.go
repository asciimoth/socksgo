package socksgo

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/helpers"
	"github.com/gorilla/websocket"
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

// type wsCoderConnWithAddr struct {
// 	net.Conn
// 	addr net.Addr
// }
//
// func (c *wsCoderConnWithAddr) LocalAddr() net.Addr {
// 	return c.addr
// }
//
// func (c *wsCoderConnWithAddr) RemoteAddr() net.Addr {
// 	return c.Conn.RemoteAddr()
// }
//
// func (c *wsCoderConnWithAddr) Read(b []byte) (n int, err error) {
// 	n, err = c.Conn.Read(b)
// 	err = wrapEOF(err)
// 	return
// }
//
// func (c *wsCoderConnWithAddr) Write(b []byte) (n int, err error) {
// 	n, err = c.Conn.Write(b)
// 	err = wrapEOF(err)
// 	return
// }
//
// func (c *wsCoderConnWithAddr) Close() error {
// 	return wrapEOF(c.Conn.Close())
// }
//
// func (c *wsCoderConnWithAddr) SetDeadline(t time.Time) error {
// 	return c.Conn.SetDeadline(t)
// }
//
// func (c *wsCoderConnWithAddr) SetReadDeadline(t time.Time) error {
// 	return c.Conn.SetReadDeadline(t)
// }
//
// func (c *wsCoderConnWithAddr) SetWriteDeadline(t time.Time) error {
// 	return c.Conn.SetWriteDeadline(t)
// }
//
// func (c *wsCoderConnWithAddr) SetKeepAlive(keepalive bool) error {
// 	return nil
// }
//
// func (c *wsCoderConnWithAddr) SetKeepAliveConfig(config net.KeepAliveConfig) error {
// 	return nil
// }
//
// func (c *wsCoderConnWithAddr) SetKeepAlivePeriod(d time.Duration) error {
// 	return nil
// }
//
// func (c *wsCoderConnWithAddr) SetLinger(sec int) error {
// 	return nil
// }
//
// func (c *wsCoderConnWithAddr) SetNoDelay(noDelay bool) error {
// 	return nil
// }
//
// func (c *wsCoderConnWithAddr) CloseRead() error {
// 	return c.Close()
// }
//
// func (c *wsCoderConnWithAddr) CloseWrite() error {
// 	return c.Close()
// }
//
// func (c *wsCoderConnWithAddr) ReadFrom(r io.Reader) (int64, error) {
// 	buf := make([]byte, 32*1024)
// 	var total int64
// 	for {
// 		n, err := r.Read(buf)
// 		if n > 0 {
// 			wn, werr := c.Write(buf[:n])
// 			total += int64(wn)
// 			if werr != nil {
// 				return total, werr
// 			}
// 		}
// 		if err != nil {
// 			if errors.Is(err, io.EOF) {
// 				return total, nil
// 			}
// 			return total, err
// 		}
// 	}
// }
//
// func (c *wsCoderConnWithAddr) WriteTo(w io.Writer) (int64, error) {
// 	buf := make([]byte, 32*1024)
// 	var total int64
// 	for {
// 		n, err := c.Read(buf)
// 		if n > 0 {
// 			wn, werr := w.Write(buf[:n])
// 			total += int64(wn)
// 			if werr != nil {
// 				return total, werr
// 			}
// 		}
// 		if err != nil {
// 			if errors.Is(err, io.EOF) {
// 				return total, nil
// 			}
// 			return total, err
// 		}
// 	}
// }

var (
	_ net.Conn        = &wsConn{}
	_ gonnect.TCPConn = &wsConn{}
	_ net.Conn        = &wsCoderConn{}
	// _ gonnect.TCPConn = &wsCoderConn{}
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
