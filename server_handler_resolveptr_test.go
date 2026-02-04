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

func TestResolvePtrHandlerRaddrBlocked(t *testing.T) {
	server := socksgo.Server{
		RaddrFilter: func(*protocol.Addr) bool {
			return false
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultResolvePtrHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdTorResolvePtr,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != "address example.com:8080 is disallowed by server raddr filter" {
		t.Fatal(err)
	}
}

func TestResolvePtrHandlerLookupFail(t *testing.T) {
	errstr := "mock resolver error"
	server := socksgo.Server{
		Resolver: &mockResolver{
			FnLookupAddr: func(ctx context.Context, address string) ([]string, error) {
				return nil, errors.New(errstr)
			},
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultResolvePtrHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdTorResolvePtr,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != errstr {
		t.Fatal(err)
	}
}

func TestResolvePtrHandlerLookupNoAddrs(t *testing.T) {
	server := socksgo.Server{
		Resolver: &mockResolver{
			FnLookupAddr: func(ctx context.Context, address string) ([]string, error) {
				return nil, nil
			},
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultResolvePtrHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdTorResolvePtr,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if !strings.Contains(err.Error(), "zero addrs found") {
		t.Fatal(err)
	}
}
