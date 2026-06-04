package socksgo_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

func TestMindHandlerLaddrBlocked(t *testing.T) {
	server := socksgo.Server{
		LaddrFilter: func(*protocol.Addr) bool {
			return false
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultGostMBindHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdGostMuxBind,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != "address example.com:8080 is disallowed by server laddr filter" {
		t.Fatal(err)
	}
}

func TestMbindHandlerListenFail(t *testing.T) {
	errstr := "mock dialer error"
	server := socksgo.Server{
		Listener: func(context.Context, string, string) (net.Listener, error) {
			return nil, errors.New(errstr)
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultGostMBindHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdGostMuxBind,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != errstr {
		t.Fatal(err)
	}
}

func TestMbindHandlerReplyFail(t *testing.T) {
	server := socksgo.Server{
		Listener: func(context.Context, string, string) (net.Listener, error) {
			return listenerWithAddr{
				Listener: listenerWithAccept{
					Listener: &net.TCPListener{},
					Acc: func() (net.Conn, error) {
						return connWithAaddr{
							Conn: &net.TCPConn{},
							Raddr: protocol.AddrFromFQDN(
								"example.com",
								8080,
								"",
							),
						}, nil
					},
				},
				Laddr: protocol.AddrFromFQDN("example.com", 8080, ""),
			}, nil
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultGostMBindHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdGostMuxBind,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err == nil {
		t.Fatal("error expected got nil")
	}
}

func TestMbindHandlerSmuxFail(t *testing.T) {
	conn, conn2 := net.Pipe()
	defer func() {
		_ = conn.Close()
		_ = conn2.Close()
	}()
	server := socksgo.Server{
		Listener: func(context.Context, string, string) (net.Listener, error) {
			return listenerWithAddr{
				Listener: listenerWithAccept{
					Listener: &net.TCPListener{},
					Acc: func() (net.Conn, error) {
						return connWithAaddr{
							Conn: &net.TCPConn{},
							Raddr: protocol.AddrFromFQDN(
								"example.com",
								8080,
								"",
							),
						}, nil
					},
				},
				Laddr: protocol.AddrFromFQDN("example.com", 8080, ""),
			}, nil
		},
		// Invalid config
		Smux: &smux.Config{
			Version: 42,
		},
	}
	go func() {
		for {
			_, err := conn2.Read([]byte{0})
			if err != nil {
				return
			}
		}
	}()
	err := socksgo.DefaultGostMBindHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdGostMuxBind,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != "unsupported protocol version" {
		t.Fatal(err)
	}
}

func TestMbindHandlerSmuxAccept(t *testing.T) {
	conn, conn2 := net.Pipe()
	defer func() {
		_ = conn.Close()
		_ = conn2.Close()
	}()
	server := socksgo.Server{
		Listener: func(context.Context, string, string) (net.Listener, error) {
			return listenerWithAddr{
				Listener: listenerWithAccept{
					Listener: &net.TCPListener{},
					Acc: func() (net.Conn, error) {
						return connWithAaddr{
							Conn: &net.TCPConn{},
							Raddr: protocol.AddrFromFQDN(
								"example.com",
								8080,
								"",
							),
						}, nil
					},
				},
				Laddr: protocol.AddrFromFQDN("example.com", 8080, ""),
			}, nil
		},
	}
	go func() {
		_, addr, _ := protocol.ReadSocks5TCPReply(conn2, nil)
		go func() {
			c, err := net.Dial("tcp", addr.String()) //nolint
			if err == nil {
				_ = c.Close()
			}
		}()
		session, err := smux.Server(conn2, nil)
		if err != nil {
			panic(err)
		}
		if rw, err := session.Open(); err == nil {
			_ = rw.Close()
		}
		_ = session.Close()
		_ = conn.Close()
		_ = conn2.Close()
	}()
	err := socksgo.DefaultGostMBindHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdGostMuxBind,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMbindHandlerContextCancelClosesIdleListener(t *testing.T) {
	conn, conn2 := net.Pipe()
	defer func() {
		_ = conn.Close()
		_ = conn2.Close()
	}()

	listener := &blockingCloseListener{
		addr: &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1080,
		},
		closed:        make(chan struct{}),
		acceptStarted: make(chan struct{}),
	}
	server := socksgo.Server{
		Listener: func(context.Context, string, string) (net.Listener, error) {
			return listener, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- socksgo.DefaultGostMBindHandler.Handler(
			ctx,
			&server,
			conn,
			"5",
			protocol.AuthInfo{},
			protocol.CmdGostMuxBind,
			protocol.AddrFromFQDN("example.com", 8080, ""),
		)
	}()

	_, _, err := protocol.ReadSocks5TCPReply(conn2, nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := smux.Server(conn2, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = session.Close()
	}()

	select {
	case <-listener.acceptStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for listener accept")
	}

	cancel()

	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for listener close")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handler return")
	}
}

type blockingCloseListener struct {
	addr          net.Addr
	closed        chan struct{}
	acceptStarted chan struct{}
	acceptOnce    sync.Once
	closeOnce     sync.Once
}

func (l *blockingCloseListener) Accept() (net.Conn, error) {
	l.acceptOnce.Do(func() {
		close(l.acceptStarted)
	})
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingCloseListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *blockingCloseListener) Addr() net.Addr {
	return l.addr
}
