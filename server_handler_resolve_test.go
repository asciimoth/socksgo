package socksgo_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

func TestResolveHandlerRaddrBlocked(t *testing.T) {
	server := socksgo.Server{
		RaddrFilter: func(*protocol.Addr) bool {
			return false
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultResolveHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdTorResolve,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != "address example.com:8080 is disallowed by server raddr filter" {
		t.Fatal(err)
	}
}

func TestResolveHandlerLookupFail(t *testing.T) {
	errstr := "mock resolver error"
	server := socksgo.Server{
		Resolver: &mockResolver{
			FnLookupIP: func(ctx context.Context, network, address string) ([]net.IP, error) {
				return nil, errors.New(errstr)
			},
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultResolveHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdTorResolve,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != errstr {
		t.Fatal(err)
	}
}

func TestResolveHandlerLookupNoIP(t *testing.T) {
	server := socksgo.Server{
		Resolver: &mockResolver{
			FnLookupIP: func(ctx context.Context, network, address string) ([]net.IP, error) {
				return nil, nil
			},
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultResolveHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdTorResolve,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if !strings.Contains(err.Error(), "zero IPs found") {
		t.Fatal(err)
	}
}
