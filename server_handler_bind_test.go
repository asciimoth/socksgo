// nolint
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
)

type closeTrackingListener struct {
	conn     net.Conn
	addr     net.Addr
	accepted chan struct{}
	closed   chan struct{}
	once     sync.Once
}

func (l *closeTrackingListener) Accept() (net.Conn, error) {
	close(l.accepted)
	return l.conn, nil
}

func (l *closeTrackingListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *closeTrackingListener) Addr() net.Addr {
	return l.addr
}

func TestBindHandlerLaddrBlocked(t *testing.T) {
	server := socksgo.Server{
		LaddrFilter: func(*protocol.Addr) bool {
			return false
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultBindHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdBind,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != "address example.com:8080 is disallowed by server laddr filter" {
		t.Fatal(err)
	}
}

func TestBindHandlerListenFail(t *testing.T) {
	errstr := "mock dialer error"
	server := socksgo.Server{
		Listener: func(context.Context, string, string) (net.Listener, error) {
			return nil, errors.New(errstr)
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultBindHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdBind,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != errstr {
		t.Fatal(err)
	}
}

func TestBindHandlerReplyFail(t *testing.T) {
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
	err := socksgo.DefaultBindHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdBind,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err == nil {
		t.Fatal("error expected got nil")
	}
}

func TestBindHandlerSecondReplyFail(t *testing.T) {
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
						_ = conn.Close()
						_ = conn2.Close()
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
		for {
			_, err := conn2.Read([]byte{0})
			if err != nil {
				return
			}
		}
	}()
	err := socksgo.DefaultBindHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdBind,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != "io: read/write on closed pipe" {
		t.Fatal(err)
	}
}

func TestBindHandlerClosesListenerAfterFirstAccept(t *testing.T) {
	ctrlServer, ctrlClient := net.Pipe()
	proxyServer, proxyClient := net.Pipe()
	defer func() {
		_ = ctrlServer.Close()
		_ = ctrlClient.Close()
		_ = proxyServer.Close()
		_ = proxyClient.Close()
	}()

	listener := &closeTrackingListener{
		conn: connWithAaddr{
			Conn:  proxyServer,
			Laddr: protocol.AddrFromFQDN("example.com", 8080, ""),
			Raddr: protocol.AddrFromFQDN("peer.example.com", 9090, ""),
		},
		addr:     protocol.AddrFromFQDN("example.com", 8080, ""),
		accepted: make(chan struct{}),
		closed:   make(chan struct{}),
	}
	server := socksgo.Server{
		Listener: func(context.Context, string, string) (net.Listener, error) {
			return listener, nil
		},
	}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 64)
		for {
			if _, err := ctrlClient.Read(buf); err != nil {
				return
			}
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- socksgo.DefaultBindHandler.Handler(
			context.Background(),
			&server,
			ctrlServer,
			"5",
			protocol.AuthInfo{},
			protocol.CmdBind,
			protocol.AddrFromFQDN("example.com", 8080, ""),
		)
	}()

	select {
	case <-listener.accepted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bind listener Accept")
	}

	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("bind listener was not closed after first Accept")
	}

	_ = ctrlClient.Close()
	_ = proxyClient.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for bind handler to return")
	}
	<-readDone
}

func TestBindHandlerAcceptFail(t *testing.T) {
	errstr := "mock dialer error"
	server := socksgo.Server{
		Listener: func(context.Context, string, string) (net.Listener, error) {
			return listenerWithAddr{
				Listener: listenerWithAccept{
					Listener: &net.TCPListener{},
					Acc: func() (net.Conn, error) {
						return nil, errors.New(errstr)
					},
				},
				Laddr: protocol.AddrFromFQDN("example.com", 8080, ""),
			}, nil
		},
	}
	conn, conn2 := net.Pipe()
	defer func() {
		_ = conn.Close()
		_ = conn2.Close()
	}()
	go func() {
		for {
			_, err := conn2.Read([]byte{0})
			if err != nil {
				return
			}
		}
	}()
	err := socksgo.DefaultBindHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdBind,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != errstr {
		t.Fatal(err)
	}
}

func TestBindHandlerContextCancelClosesIdleListener(t *testing.T) {
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
		done <- socksgo.DefaultBindHandler.Handler(
			ctx,
			&server,
			conn,
			"5",
			protocol.AuthInfo{},
			protocol.CmdBind,
			protocol.AddrFromFQDN("example.com", 8080, ""),
		)
	}()

	_, _, err := protocol.ReadSocks5TCPReply(conn2, nil)
	if err != nil {
		t.Fatal(err)
	}

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
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handler return")
	}
}

func TestBindHandlerControlCloseClosesIdleListener(t *testing.T) {
	ctrlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ctrlListener.Close() }()

	conn2, err := net.Dial("tcp", ctrlListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := ctrlListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
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
	done := make(chan error, 1)
	go func() {
		done <- socksgo.DefaultBindHandler.Handler(
			context.Background(),
			&server,
			conn,
			"5",
			protocol.AuthInfo{},
			protocol.CmdBind,
			protocol.AddrFromFQDN("example.com", 8080, ""),
		)
	}()

	_, _, err = protocol.ReadSocks5TCPReply(conn2, nil)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-listener.acceptStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for listener accept")
	}

	_ = conn2.Close()

	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for listener close")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handler return")
	}
}

func TestBindHandlerWrappedControlCloseClosesIdleListener(t *testing.T) {
	ctrlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ctrlListener.Close() }()

	conn2, err := net.Dial("tcp", ctrlListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := ctrlListener.Accept()
	if err != nil {
		t.Fatal(err)
	}
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
	done := make(chan error, 1)
	go func() {
		done <- socksgo.DefaultBindHandler.Handler(
			context.Background(),
			&server,
			noSyscallConn{Conn: conn},
			"5",
			protocol.AuthInfo{},
			protocol.CmdBind,
			protocol.AddrFromFQDN("example.com", 8080, ""),
		)
	}()

	_, _, err = protocol.ReadSocks5TCPReply(conn2, nil)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-listener.acceptStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for listener accept")
	}

	_ = conn2.Close()

	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for listener close")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handler return")
	}
}

type noSyscallConn struct {
	net.Conn
}
