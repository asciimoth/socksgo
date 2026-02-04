package socksgo_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

func TestBindHandlerRaddrBlocked(t *testing.T) {
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
