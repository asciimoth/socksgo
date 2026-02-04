package socksgo_test

import (
	"context"
	"net"
	"testing"

	"github.com/asciimoth/socksgo"
)

func TestBuildFilter_HostsAndWildcards(t *testing.T) {
	f := socksgo.BuildFilter("example.com, *.example.org, Example.NET.")

	cases := []struct {
		address string
		want    bool
	}{
		{"example.com", true},
		{"example.com:80", true},       // host without port matches any port
		{"foo.example.org", true},      // wildcard match
		{"bar.example.org:1234", true}, // wildcard match with port
		{"example.net", true},          // case + trailing dot handled
		{
			"example.org",
			false,
		}, // "*.example.org" does NOT match bare example.org
		{"notexample.com", false},
	}

	for _, tt := range cases {
		got := f("tcp", tt.address)
		if got != tt.want {
			t.Fatalf("filter(%q) = %v; want %v", tt.address, got, tt.want)
		}
	}
}

func TestBuildFilter_HostsWithPortsAndIPPorts(t *testing.T) {
	f := socksgo.BuildFilter("example.com:443,1.2.3.4:8080,[::1]:22")

	cases := []struct {
		address string
		want    bool
	}{
		{"example.com:443", true},
		{"example.com:80", false}, // port mismatch
		{"1.2.3.4:8080", true},
		{"1.2.3.4", false}, // ip entry had port so must match port
		{"[::1]:22", true},
		{
			"::1",
			false,
		}, // ipv6 literal without port shouldn't match bracketed-with-port entry
	}

	for _, tt := range cases {
		got := f("tcp", tt.address)
		if got != tt.want {
			t.Fatalf("filter(%q) = %v; want %v", tt.address, got, tt.want)
		}
	}
}

func TestBuildFilter_CIDRAndIPMatches(t *testing.T) {
	f := socksgo.BuildFilter("10.0.0.0/8,192.168.1.1,2001:db8::/32")

	cases := []struct {
		address string
		want    bool
	}{
		{"10.1.2.3", true},       // in 10.0.0.0/8
		{"10.1.2.3:53", true},    // cidr matches regardless of port
		{"192.168.1.1", true},    // exact IPv4 match
		{"192.168.1.1:80", true}, // exact IPv4 match with port
		{"192.168.1.2", false},
		{"2001:db8::5", true},       // ipv6 cidr match
		{"[2001:db8::5]:123", true}, // ipv6 cidr match with port
	}

	for _, tt := range cases {
		got := f("tcp", tt.address)
		if got != tt.want {
			t.Fatalf("filter(%q) = %v; want %v", tt.address, got, tt.want)
		}
	}
}

func TestBuildFilter_HostnameVsIP_NoDNS(t *testing.T) {
	f := socksgo.BuildFilter("localhost")

	cases := []struct {
		address string
		want    bool
	}{
		{"localhost", true},
		{
			"127.0.0.1",
			false,
		}, // should not match just because localhost resolves to 127.0.0.1
	}

	for _, tt := range cases {
		got := f("tcp", tt.address)
		if got != tt.want {
			t.Fatalf("filter(%q) = %v; want %v", tt.address, got, tt.want)
		}
	}
}

func TestConstantFilters(t *testing.T) {
	nets := []string{"tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "", "fsasdf"}
	addrs := []string{"example.com", "127.0.0.1"}

	for _, net := range nets {
		for _, addr := range addrs {
			p := socksgo.PassAllFilter(net, addr)
			m := socksgo.MatchAllFilter(net, addr)
			if p || !m {
				t.Error(net, addr, p, m)
			}
		}
	}
}

func TestLoopbackFilter(t *testing.T) {
	table := []struct {
		addr string
		exp  bool
	}{
		{"localhost", true},
		{"localhost:42", true},
		{"127.0.0.1", true},
		{"127.0.0.1:42", true},
		{"::1", true},
		{"[::1]:42", true},
		{"192.168.0.0.1", false},
		{"8.8.8.8", false},
		{"example.com", false},
		{"", false},
	}
	for _, tt := range table {
		got := socksgo.LoopbackFilter("", tt.addr)
		if got != tt.exp {
			t.Error(tt.addr, tt.exp, got)
		}
	}
}

type connWithAaddr struct {
	net.Conn
	Laddr, Raddr net.Addr
}

func (c connWithAaddr) RemoteAddr() net.Addr {
	return c.Raddr
}

func (c connWithAaddr) LocalAddr() net.Addr {
	return c.Laddr
}

type packetConnWithAaddr struct {
	socksgo.PacketConn
	Laddr, Raddr net.Addr
}

func (c packetConnWithAaddr) RemoteAddr() net.Addr {
	return c.Raddr
}

func (c packetConnWithAaddr) LocalAddr() net.Addr {
	return c.Laddr
}

type listenerWithAddr struct {
	net.Listener
	Laddr net.Addr
}

func (c listenerWithAddr) Addr() net.Addr {
	return c.Laddr
}

type listenerWithAccept struct {
	net.Listener
	Acc func() (net.Conn, error)
}

func (c listenerWithAccept) Accept() (net.Conn, error) {
	return c.Acc()
}

type mockResolver struct {
	FnLookupIP   func(ctx context.Context, network, address string) ([]net.IP, error)
	FnLookupAddr func(ctx context.Context, address string) ([]string, error)
}

func (m *mockResolver) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	return m.FnLookupIP(ctx, network, address)
}

func (m *mockResolver) LookupAddr(
	ctx context.Context,
	address string,
) ([]string, error) {
	return m.FnLookupAddr(ctx, address)
}
