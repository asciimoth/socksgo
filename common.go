package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

var supportedNetworks = map[string]any{
	"tcp":  nil,
	"tcp4": nil,
	"tcp6": nil,

	"udp":  nil,
	"udp4": nil,
	"udp6": nil,
}

type PacketConn interface {
	net.PacketConn
	net.Conn
	// TODO: Add all methods implemented by clientPacketConn5
}

type Dialer = func(ctx context.Context, network, address string) (net.Conn, error)
type PacketDialer = func(ctx context.Context, network, address string) (PacketConn, error)
type Listener = func(ctx context.Context, network, address string) (net.Listener, error)
type PacketListener = func(ctx context.Context, network, address string) (PacketConn, error)
type Resolver interface {
	LookupIP(ctx context.Context, network, address string) ([]net.IP, error)
	LookupAddr(ctx context.Context, address string) ([]string, error)
}

// Client side connection filter.
// Return true if direct Dial/Listen function should be called instead of
// passing it to proxy.
// Return false if proxy should be used.
// network may be "" if it is unknown.
type Filter = func(network, address string) bool

// Always returns false
func PassAllFilter(_, _ string) bool {
	return false
}

// Return true for "localhost" and loopback ip addrs
func LoopbackFilter(_, address string) bool {
	if address == "localhost" {
		return true
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	if net.ParseIP(host).IsLoopback() {
		return true
	}
	return false
}

func resolveTcp4Addr(
	ctx context.Context,
	addr protocol.Addr,
	resolver Resolver,
) *protocol.Addr {
	if addr.Type == protocol.IP4Addr {
		return &addr
	}
	if addr.Type == protocol.FQDNAddr {
		ips, err := resolver.LookupIP(ctx, "ip4", addr.ToFQDN())
		if err != nil || len(ips) < 1 {
			return nil
		}
		addr = protocol.AddrFromIP(ips[0], addr.Port, "tcp4")
		return &addr
	}
	return nil
}
