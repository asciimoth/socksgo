package protocol_test

import (
	"net"
	"testing"

	"github.com/asciimoth/socks/protocol"
)

func TestAddr(t *testing.T) {
	tests := []struct {
		Name    string
		NetAddr net.Addr

		Type protocol.AddrType

		IsUnspecified bool
		ToIP          net.IP
		ToFQDN        string
		Network       string
		String        string
	}{
		{
			Name: "NormalIP4Port",
			NetAddr: NetAddr{
				Addr: "127.0.0.1:80",
				Net:  "udp",
			},
			Type:          protocol.IP4Addr,
			IsUnspecified: false,
			ToIP:          net.IPv4(127, 0, 0, 1),
			ToFQDN:        "127.0.0.1",
			Network:       "udp4",
			String:        "127.0.0.1:80",
		},
		{
			Name: "NormalIP6Port",
			NetAddr: NetAddr{
				Addr: "[::1]:80",
				Net:  "udp",
			},
			Type:          protocol.IP6Addr,
			IsUnspecified: false,
			ToIP:          net.IPv6loopback,
			ToFQDN:        "::1",
			Network:       "udp6",
			String:        "[::1]:80",
		},
		{
			Name: "NormalFQDNPort",
			NetAddr: NetAddr{
				Addr: "localhost:80",
				Net:  "udp",
			},
			Type:          protocol.FQDNAddr,
			IsUnspecified: false,
			ToIP:          nil,
			ToFQDN:        "localhost",
			Network:       "udp",
			String:        "localhost:80",
		},
		{
			Name: "IP4NoPort",
			NetAddr: NetAddr{
				Addr: "127.0.0.1",
				Net:  "udp",
			},
			Type:          protocol.IP4Addr,
			IsUnspecified: false,
			ToIP:          net.IPv4(127, 0, 0, 1),
			ToFQDN:        "127.0.0.1",
			Network:       "udp4",
			String:        "127.0.0.1",
		},
		{
			Name: "FQDNNoPort",
			NetAddr: NetAddr{
				Addr: "localhost",
				Net:  "udp",
			},
			Type:          protocol.FQDNAddr,
			IsUnspecified: false,
			ToIP:          nil,
			ToFQDN:        "localhost",
			Network:       "udp",
			String:        "localhost",
		},
		{
			Name: "IP4NoNet",
			NetAddr: NetAddr{
				Addr: "127.0.0.1:80",
				Net:  "",
			},
			Type:          protocol.IP4Addr,
			IsUnspecified: false,
			ToIP:          net.IPv4(127, 0, 0, 1),
			ToFQDN:        "127.0.0.1",
			Network:       "tcp4",
			String:        "127.0.0.1:80",
		},
		{
			Name: "FQDNPort",
			NetAddr: NetAddr{
				Addr: "localhost:80",
				Net:  "",
			},
			Type:          protocol.FQDNAddr,
			IsUnspecified: false,
			ToIP:          nil,
			ToFQDN:        "localhost",
			Network:       "tcp",
			String:        "localhost:80",
		},

		{
			Name: "UnspecIP4Port",
			NetAddr: NetAddr{
				Addr: "0.0.0.0:80",
				Net:  "udp",
			},
			Type:          protocol.IP4Addr,
			IsUnspecified: true,
			ToIP:          net.IPv4(0, 0, 0, 0),
			ToFQDN:        "0.0.0.0",
			Network:       "udp4",
			String:        "0.0.0.0:80",
		},
		{
			Name: "UnspecIP6Port",
			NetAddr: NetAddr{
				Addr: "[::]:80",
				Net:  "udp",
			},
			Type:          protocol.IP6Addr,
			IsUnspecified: true,
			ToIP:          net.IPv6unspecified,
			ToFQDN:        "::",
			Network:       "udp6",
			String:        "[::]:80",
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			addr := protocol.AddrFromNetAddr(tc.NetAddr)

			if addr.Type != tc.Type {
				t.Fatalf(
					"Type is %v while expected %v",
					addr.Type,
					tc.Type,
				)
			}

			if addr.IsUnspecified() != tc.IsUnspecified {
				t.Fatalf(
					"IsUnspecified returned %v while expected %v",
					addr.IsUnspecified(),
					tc.IsUnspecified,
				)
			}

			if !addr.ToIP().Equal(tc.ToIP) {
				t.Fatalf(
					"ToIP returned %v while expected %v",
					addr.ToIP(),
					tc.ToIP,
				)
			}

			if addr.ToFQDN() != tc.ToFQDN {
				t.Fatalf(
					"ToFQDN returned %v while expected %v",
					addr.ToFQDN(),
					tc.ToFQDN,
				)
			}

			if addr.Network() != tc.Network {
				t.Fatalf(
					"Network returned %v while expected %v",
					addr.Network(),
					tc.Network,
				)
			}

			if addr.String() != tc.String {
				t.Fatalf(
					"String returned %v while expected %v",
					addr.String(),
					tc.String,
				)
			}
		})
	}
}
