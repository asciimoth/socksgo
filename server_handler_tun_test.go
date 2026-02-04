package socksgo_test

import (
	"context"
	"net"
	"testing"

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
