package socksgo_test

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

func TestTunHandlerAddrBlocked(t *testing.T) {
	server := socksgo.Server{
		LaddrFilter: func(*protocol.Addr) bool {
			return false
		},
		RaddrFilter: func(*protocol.Addr) bool {
			return false
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultGostUDPTUNHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdGostUDPTun,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != "address example.com:8080 is disallowed by server raddr filter" {
		t.Fatal(err)
	}
}

func TestTunHandlerChecksDefaultListenHostLaddr(t *testing.T) {
	var checked string
	server := socksgo.Server{
		DefaultListenHost: "127.0.0.1",
		LaddrFilter: func(addr *protocol.Addr) bool {
			checked = addr.ToHostPort()
			return false
		},
	}

	conn := &net.TCPConn{}
	err := socksgo.DefaultGostUDPTUNHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdGostUDPTun,
		protocol.AddrFromIP(net.IPv4zero, 0, ""),
	)
	if err == nil {
		t.Fatal("error expected")
	}
	if checked != "127.0.0.1:0" {
		t.Fatalf("checked laddr = %q, want 127.0.0.1:0", checked)
	}
}

func TestTunHandlerReplyFail(t *testing.T) {
	server := socksgo.Server{}
	conn := &net.TCPConn{}
	err := socksgo.DefaultGostUDPTUNHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdGostUDPTun,
		protocol.AddrFromIP(net.IPv4(8, 8, 8, 8), 53, "udp"),
	)
	if err == nil {
		t.Fatal("error expected")
	}
}

func TestTunHandlerPreservesWildcardAddressFamily(t *testing.T) {
	t.Parallel()

	listenErr := errors.New("stop after recording listen call")
	type listenCall struct {
		network string
		address string
	}
	var calls []listenCall
	server := socksgo.Server{}
	server.PacketListener = func(
		_ context.Context,
		network string,
		address string,
	) (gonnect.PacketConn, error) {
		calls = append(calls, listenCall{network, address})
		return nil, listenErr
	}

	for _, address := range []string{"0.0.0.0:25120", "[::]:25120"} {
		err := socksgo.DefaultGostUDPTUNHandler.Handler(
			context.Background(),
			&server,
			&net.TCPConn{},
			"5",
			protocol.AuthInfo{},
			protocol.CmdGostUDPTun,
			protocol.AddrFromHostPort(address, "udp"),
		)
		if !errors.Is(err, listenErr) {
			t.Fatalf("handler error = %v, want %v", err, listenErr)
		}
	}

	want := []listenCall{
		{network: "udp4", address: "0.0.0.0:25120"},
		{network: "udp6", address: "[::]:25120"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("packet listener calls = %#v, want %#v", calls, want)
	}
}
