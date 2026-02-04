package socksgo_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

func TestConnectHandlerRaddrBlocked(t *testing.T) {
	server := socksgo.Server{
		RaddrFilter: func(*protocol.Addr) bool {
			return false
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultConnectHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdConnect,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != "address example.com:8080 is disallowed by server raddr filter" {
		t.Fatal(err)
	}
}

func TestConnectHandlerDialFail(t *testing.T) {
	errstr := "mock dialer error"
	server := socksgo.Server{
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New(errstr)
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultConnectHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdConnect,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != errstr {
		t.Fatal(err)
	}
}

func TestConnectHandlerReplyFail(t *testing.T) {
	server := socksgo.Server{
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return connWithAaddr{
				Conn:  &net.TCPConn{},
				Raddr: protocol.AddrFromFQDN("example.com", 8080, ""),
			}, nil
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultConnectHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdConnect,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err == nil {
		t.Fatal("error expected got nil")
	}
}
