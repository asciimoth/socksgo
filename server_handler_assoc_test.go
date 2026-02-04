package socksgo_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

func TestAssocHandlerAddrBlocked(t *testing.T) {
	server := socksgo.Server{
		LaddrFilter: func(*protocol.Addr) bool {
			return false
		},
		RaddrFilter: func(*protocol.Addr) bool {
			return false
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultUDPAssocHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdUDPAssoc,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)
	if err.Error() != "address example.com:8080 is disallowed by server raddr filter" {
		t.Fatal(err)
	}
}

func TestAssocHandlerListenFail(t *testing.T) {
	errstr := "mock dialer error"
	server := socksgo.Server{
		AssocListener: func(ctx context.Context, ctrl net.Conn) (assoc socksgo.PacketConn, err error) {
			return nil, errors.New(errstr)
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultUDPAssocHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdUDPAssoc,
		protocol.AddrFromIP(net.IPv4(8, 8, 8, 8), 53, "udp"),
	)
	if err.Error() != errstr {
		t.Fatal(err)
	}
}

func TestAssocHandlerReplyFail(t *testing.T) {
	server := socksgo.Server{
		AssocListener: func(ctx context.Context, ctrl net.Conn) (assoc socksgo.PacketConn, err error) {
			return packetConnWithAaddr{
				PacketConn: &net.UDPConn{},
				Laddr:      protocol.AddrFromFQDN("example.com", 8080, ""),
				Raddr:      protocol.AddrFromFQDN("example.com", 8080, ""),
			}, nil
		},
	}
	conn := &net.TCPConn{}
	err := socksgo.DefaultUDPAssocHandler.Handler(
		context.Background(),
		&server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdUDPAssoc,
		protocol.AddrFromIP(net.IPv4(8, 8, 8, 8), 53, "udp"),
	)
	if err == nil {
		t.Fatal("error expected")
	}
}
