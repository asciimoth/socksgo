// nolint
package protocol_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"testing"

	"github.com/asciimoth/socksgo/protocol"
)

type fakeAddr string

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return string(f) }

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

func TestAddrTypeString(t *testing.T) {
	if s := protocol.IP4Addr.String(); s == "" {
		t.Fatalf("IP4Addr.String() returned empty string")
	}
	if s := protocol.IP6Addr.String(); s == "" {
		t.Fatalf("IP6Addr.String() returned empty string")
	}
	if s := protocol.FQDNAddr.String(); s == "" {
		t.Fatalf("FQDNAddr.String() returned empty string")
	}
	// unknown value
	var v protocol.AddrType = 0x99
	if got := v.String(); got == "" {
		t.Fatalf("unknown AddrType.String() returned empty string")
	}
}

func TestAddrFromIPAndString(t *testing.T) {
	ip4 := net.ParseIP("1.2.3.4")
	a := protocol.AddrFromIP(ip4, 8080, "tcp")
	if a.Type != protocol.IP4Addr {
		t.Fatalf("expected IP4Addr, got %v", a.Type)
	}
	if a.Port != 8080 {
		t.Fatalf("port mismatch: %d", a.Port)
	}
	if got := a.ToFQDN(); got != "1.2.3.4" {
		t.Fatalf("ToFQDN() = %q, want %q", got, "1.2.3.4")
	}

	ip6 := net.ParseIP("::1")
	b := protocol.AddrFromIP(ip6, 0, "udp6")
	if b.Type != protocol.IP6Addr {
		t.Fatalf("expected IP6Addr, got %v", b.Type)
	}
	if b.Port != 0 {
		t.Fatalf("port mismatch: %d", b.Port)
	}
	if got := b.ToFQDN(); got != "::1" {
		t.Fatalf("ToFQDN() = %q, want %q", got, "::1")
	}

	// FromString should parse IP and FQDN
	c := protocol.AddrFromString("example.com", 53, "tcp")
	if c.Type != protocol.FQDNAddr {
		t.Fatalf("expected FQDNAddr, got %v", c.Type)
	}
	if c.ToFQDN() != "example.com" {
		t.Fatalf("ToFQDN() wrong: %q", c.ToFQDN())
	}
}

func TestAddrFromFQDNPortOverrideAndNoDot(t *testing.T) {
	d := protocol.AddrFromFQDN("example.com:1234", 53, "tcp")
	if d.Port != 1234 {
		t.Fatalf("expected port 1234, got %d", d.Port)
	}

	e := protocol.AddrFromFQDNNoDot("example.com.", 53, "tcp")
	if e.ToFQDN() != "example.com" {
		t.Fatalf("expected trimmed fqdn, got %q", e.ToFQDN())
	}
}

func TestAddrFromNetAddrVariants(t *testing.T) {
	tcp := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 80}
	a := protocol.AddrFromNetAddr(tcp)
	if a.Type != protocol.IP4Addr || a.Port != 80 || a.NetTyp != "tcp" {
		t.Fatalf("unexpected Addr from TCPAddr: %#v", a)
	}

	udp := &net.UDPAddr{IP: net.ParseIP("::1"), Port: -1}
	b := protocol.AddrFromNetAddr(udp)
	// negative port should be clamped to 0
	if b.Port != 0 {
		t.Fatalf("expected clamped port 0, got %d", b.Port)
	}

	// custom net.Addr fallback path
	f := fakeAddr("example.org:4242")
	c := protocol.AddrFromNetAddr(f)
	if c.Type != protocol.FQDNAddr || c.Port != 4242 {
		t.Fatalf("fallback AddrFromNetAddr failed: %#v", c)
	}
}

func TestAddrFromUDPAddr(t *testing.T) {
	na := protocol.AddrFromUDPAddr(nil)
	if !na.IsUnspecified() {
		t.Fatalf("got: %s while expected void addr struct", na)
	}
	wpa := protocol.AddrFromUDPAddr(&net.UDPAddr{Port: 99999})
	if wpa.Port != 0 {
		t.Fatalf("got: %d while expected 0", wpa.Port)
	}
	oka := protocol.AddrFromUDPAddr(&net.UDPAddr{Port: 42})
	if oka.Port != 42 {
		t.Fatalf("got: %d while expected 42", oka.Port)
	}
}

func TestAddrFromTCPAddr(t *testing.T) {
	na := protocol.AddrFromTCPAddr(nil)
	if !na.IsUnspecified() {
		t.Fatalf("got: %s while expected void addr struct", na)
	}
	wpa := protocol.AddrFromTCPAddr(&net.TCPAddr{Port: 99999})
	if wpa.Port != 0 {
		t.Fatalf("got: %d while expected 0", wpa.Port)
	}
}

func TestAddrFromHostPort(t *testing.T) {
	a6 := protocol.AddrFromHostPort("", "tcp6")
	if a6.ToHostPort() != "[::]:0" {
		t.Fatalf("got: %s while expected [::]:0", a6.ToHostPort())
	}
	a4 := protocol.AddrFromHostPort("", "udp")
	if a4.ToHostPort() != "0.0.0.0:0" {
		t.Fatalf("got: %s while expected 0.0.0.0:0", a6.ToHostPort())
	}
}

func TestIsUnspecifiedAndWithDefaultHostCopy(t *testing.T) {
	zero := protocol.Addr{}
	if !zero.IsUnspecified() {
		t.Fatalf("empty Addr should be unspecified")
	}

	ip0 := protocol.AddrFromString("0.0.0.0", 0, "tcp")
	if !ip0.IsUnspecified() {
		t.Fatalf("0.0.0.0 should be unspecified")
	}
	ip1 := protocol.AddrFromString("8.8.8.8", 53, "udp")
	if ip1.IsUnspecified() {
		t.Fatalf("8.8.8.8 should be specified")
	}

	// WithDefaultHost should replace unspecified host
	filled := zero.WithDefaultHost("1.2.3.4")
	if got := filled.ToFQDN(); got != "1.2.3.4" {
		t.Fatalf("WithDefaultHost failed: %q", got)
	}

	// Copy should deep copy Host
	x := protocol.AddrFromString("example.com", 11, "tcp")
	y := x.Copy()
	if &x == &y {
		t.Fatalf("Copy returned same address by pointer")
	}
	if !bytes.Equal(x.Host, y.Host) {
		t.Fatalf("copied host mismatch")
	}
	// mutate original host slice and ensure copy is unaffected
	x.Host[0] = 'X'
	if bytes.Equal(x.Host, y.Host) {
		t.Fatalf("Copy did not deep copy Host slice")
	}

	// Void host
	vha := protocol.Addr{
		Type: protocol.IP4Addr,
		Host: net.IPv4(0, 0, 0, 0).To4(),
		Port: 42,
	}.WithDefaultHost("")
	if vha.ToHostPort() != "0.0.0.0:42" {
		t.Fatalf("got %s while wxpected 0.0.0.0:42", vha.ToHostPort())
	}

	// Specified
	spa := protocol.Addr{
		Type: protocol.IP4Addr,
		Host: net.IPv4(127, 0, 0, 1).To4(),
		Port: 42,
	}.WithDefaultHost("")
	if spa.ToHostPort() != "127.0.0.1:42" {
		t.Fatalf("got %s while wxpected 127.0.0.1:42", spa.ToHostPort())
	}
}

func TestLenWithNetTypWithDefaultHostToIP(t *testing.T) {
	a := protocol.AddrFromString("1.2.3.4", 0, "tcp4")
	if a.Len() != 4 {
		t.Fatalf("Len for IPv4 should be 4, got %d", a.Len())
	}
	b := protocol.AddrFromString("::1", 0, "tcp6")
	if b.Len() != 16 {
		t.Fatalf("Len for IPv6 should be 16, got %d", b.Len())
	}
	c := protocol.AddrFromString("host.example", 0, "tcp")
	if c.Len() != len(c.Host) {
		t.Fatalf("Len for FQDN should equal host length")
	}

	// WithNetTyp normalization
	d := a.WithNetTyp("tcp4")
	if d.NetTyp != "tcp" {
		t.Fatalf("WithNetTyp did not normalize tcp4 -> tcp, got %q", d.NetTyp)
	}
	e := a.WithNetTyp("udp6")
	if e.NetTyp != "udp" {
		t.Fatalf("WithNetTyp did not normalize udp6 -> udp, got %q", e.NetTyp)
	}

	// With wrong typ
	wta := protocol.Addr{
		Host: make([]byte, 10),
		Type: 42,
	}
	if wta.Len() != 10 {
		t.Fatalf("got %d while 10 expected", wta.Len())
	}
}

func TestToUDPToTCPToUnspecifiedToHostPortNetworkIpNetworkString(t *testing.T) {
	a := protocol.AddrFromString("1.2.3.4", 8080, "tcp")
	udp := a.ToUDP()
	if udp == nil || udp.Port != 8080 {
		t.Fatalf("ToUDP invalid: %#v", udp)
	}
	tcp := a.ToTCP()
	if tcp == nil || tcp.Port != 8080 {
		t.Fatalf("ToTCP invalid: %#v", tcp)
	}

	fqdn := protocol.AddrFromString("example.org", 0, "")
	if fqdn.ToUDP() != nil || fqdn.ToTCP() != nil {
		t.Fatalf("FQDN ToUDP/ToTCP should be nil")
	}

	unspec := a.ToUnspecified()
	if unspec.IsUnspecified() == false {
		t.Fatalf("ToUnspecified should be unspecified")
	}

	// ToHostPort with IPv6
	ipv6 := protocol.AddrFromString("::1", 53, "tcp6")
	hp := ipv6.ToHostPort()
	if hp == "::1:53" || hp == "[::1]:53" == false {
		// ensure it's parsable by net.SplitHostPort
		_, _, err := net.SplitHostPort(hp)
		if err != nil {
			t.Fatalf("ToHostPort produced unparsable value: %q", hp)
		}
	}

	// Network and IpNetwork
	if a.Network() != "tcp4" {
		t.Fatalf("Network() expected tcp4, got %q", a.Network())
	}
	if ipv6.Network() != "tcp6" {
		t.Fatalf("Network() expected tcp6, got %q", ipv6.Network())
	}
	if fqdn.Network() != "tcp" {
		t.Fatalf("FQDN Network() expected tcp, got %q", fqdn.Network())
	}

	// IpNetwork mapping
	cases := []struct{ in, want string }{
		{"", "ip"},
		{"tcp", "ip"},
		{"udp", "ip"},
		{"tcp4", "ip4"},
		{"udp6", "ip6"},
		{"custom", "custom"},
	}
	for _, c := range cases {
		x := protocol.Addr{NetTyp: c.in}
		if got := x.IpNetwork(); got != c.want {
			t.Fatalf("IpNetwork(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// String behaviour
	if s := a.String(); s != a.ToHostPort() {
		t.Fatalf("String() with port expected %q, got %q", a.ToHostPort(), s)
	}
	if s := fqdn.String(); s != fqdn.ToFQDN() {
		t.Fatalf("String() without port expected %q, got %q", fqdn.ToFQDN(), s)
	}
}

func TestPortStr(t *testing.T) {
	a := protocol.AddrFromString("1.2.3.4", 65535, "tcp")
	if a.PortStr() != strconv.Itoa(65535) {
		t.Fatalf("PortStr mismatch: %q", a.PortStr())
	}
}

func TestAddrToIP(t *testing.T) {
	ip := protocol.Addr{
		Type: 42,
	}.ToIP()
	if ip != nil {
		t.Fatal("nil expected")
	}
}

func TestAddrToUnspec(t *testing.T) {
	u6 := protocol.Addr{
		Type: protocol.IP6Addr,
		Host: net.IPv6loopback.To16(),
	}.ToUnspecified()
	if u6.ToIP().String() != net.IPv6unspecified.String() {
		t.Fatal("must be usnpecified")
	}

	ud := protocol.Addr{
		Type: protocol.FQDNAddr,
		Host: []byte("localhost"),
	}.ToUnspecified()
	if ud.String() != "" {
		t.Fatal("must be usnpecified")
	}
}

func TestAddrToUnknownNet(t *testing.T) {
	addr := protocol.Addr{
		NetTyp: "unknown",
	}
	if addr.Network() != "unknown" {
		t.Fatalf("got %s while expected unknown", addr.Network())
	}
}

func TestWithDefaultAddr(t *testing.T) {
	orig := protocol.AddrFromHostPort("0.0.0.0:0", "")
	a := orig.WithDefaultAddr(nil)
	b := orig.WithDefaultAddr(&protocol.Addr{
		Type: protocol.IP4Addr,
		Host: net.IPv4(127, 0, 0, 1).To4(),
		Port: 42,
	})
	if !a.IsUnspecified() {
		t.Error(a.String())
	}
	if b.IsUnspecified() {
		t.Error(b.String())
	}
}

func TestResolveToIP4(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := []struct {
		name    string
		input   protocol.Addr
		lookup  func(context.Context, string, string) ([]net.IP, error)
		wantNil bool
		// optional expectations when wantNil == false
		wantType protocol.AddrType
		wantNet  string
		wantIP   net.IP
	}{
		{
			name:  "already IPv4 - returns itself and lookup not called",
			input: protocol.AddrFromString("1.2.3.4", 80, "tcp"),
			lookup: func(context.Context, string, string) ([]net.IP, error) {
				t.Fatalf("lookup must not be called for IPv4 addresses")
				return nil, nil
			},
			wantNil:  false,
			wantType: protocol.IP4Addr,
			wantNet:  "tcp", // original net typ preserved by returned copy
			wantIP:   net.ParseIP("1.2.3.4").To4(),
		},
		{
			name:  "FQDN resolves to IPv4 - returns ip with tcp4",
			input: protocol.AddrFromFQDN("example.com", 8080, "tcp"),
			lookup: func(_ context.Context, network, host string) ([]net.IP, error) {
				if network != "ip4" {
					t.Fatalf("expected lookup network 'ip4', got %q", network)
				}
				if host != "example.com" {
					t.Fatalf("expected lookup host 'example.com', got %q", host)
				}
				return []net.IP{
					net.ParseIP("5.6.7.8"),
					net.ParseIP("::1"),
				}, nil
			},
			wantNil:  false,
			wantType: protocol.IP4Addr,
			wantNet:  "tcp4", // ResolveToIP4 sets net to "tcp4"
			wantIP:   net.ParseIP("5.6.7.8").To4(),
		},
		{
			name:  "FQDN lookup returns empty slice -> nil",
			input: protocol.AddrFromFQDN("noips.example", 53, "tcp"),
			lookup: func(context.Context, string, string) ([]net.IP, error) {
				return []net.IP{}, nil
			},
			wantNil: true,
		},
		{
			name:  "FQDN lookup returns error -> nil",
			input: protocol.AddrFromFQDN("err.example", 53, "tcp"),
			lookup: func(context.Context, string, string) ([]net.IP, error) {
				return nil, errors.New("lookup failed")
			},
			wantNil: true,
		},
		{
			name:  "IPv6 address -> nil",
			input: protocol.AddrFromString("::1", 1234, "tcp6"),
			lookup: func(context.Context, string, string) ([]net.IP, error) {
				t.Fatalf("lookup must not be called for IPv6 addresses")
				return nil, nil
			},
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.input.ResolveToIP4(ctx, tc.lookup)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil result, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected non-nil result, got nil")
			}

			// Type check
			if got.Type != tc.wantType {
				t.Fatalf("wrong type: want %v got %v", tc.wantType, got.Type)
			}
			// Port preserved
			if got.Port != tc.input.Port {
				t.Fatalf(
					"port changed: want %d got %d",
					tc.input.Port,
					got.Port,
				)
			}
			// NetTyp expectation
			if got.NetTyp != tc.wantNet {
				t.Fatalf("NetTyp: want %q got %q", tc.wantNet, got.NetTyp)
			}
			// Host bytes represent expected IP
			if !reflect.DeepEqual(net.IP(got.Host).To4(), tc.wantIP) {
				t.Fatalf(
					"host IP mismatch: want %v got %v",
					tc.wantIP,
					net.IP(got.Host),
				)
			}

			// Also ensure returned Addr is independent (copy) of original value:
			// mutating original should not affect returned value's Host slice.
			origCopy := tc.input.Copy()
			if len(origCopy.Host) > 0 {
				origCopy.Host[0] ^= 0xFF
				if reflect.DeepEqual(net.IP(got.Host), net.IP(origCopy.Host)) {
					t.Fatalf("returned Addr shares Host storage with original")
				}
			}
		})
	}
}

func TestAddrFromNetIPAddrPort(t *testing.T) {
	t.Parallel()

	t.Run("valid IPv4 AddrPort with default network", func(t *testing.T) {
		t.Parallel()
		addrPort := netip.MustParseAddrPort("192.168.1.1:8080")
		addr := protocol.AddrFromNetIPAddrPort(addrPort)

		if addr.Type != protocol.IP4Addr {
			t.Fatalf("expected IP4Addr, got %v", addr.Type)
		}
		if addr.Port != 8080 {
			t.Fatalf("expected port 8080, got %d", addr.Port)
		}
		if addr.NetTyp != "udp" {
			t.Fatalf("expected default NetTyp 'udp', got %q", addr.NetTyp)
		}
		expectedIP := net.ParseIP("192.168.1.1").To4()
		if !net.IP(addr.Host).Equal(expectedIP) {
			t.Fatalf(
				"IP mismatch: got %v, want %v",
				net.IP(addr.Host),
				expectedIP,
			)
		}
	})

	t.Run("valid IPv6 AddrPort with custom network", func(t *testing.T) {
		t.Parallel()
		addrPort := netip.MustParseAddrPort("[::1]:443")
		addr := protocol.AddrFromNetIPAddrPort(addrPort, "tcp")

		if addr.Type != protocol.IP6Addr {
			t.Fatalf("expected IP6Addr, got %v", addr.Type)
		}
		if addr.Port != 443 {
			t.Fatalf("expected port 443, got %d", addr.Port)
		}
		if addr.NetTyp != "tcp" {
			t.Fatalf("expected NetTyp 'tcp', got %q", addr.NetTyp)
		}
	})

	t.Run("invalid zero AddrPort returns zero Addr", func(t *testing.T) {
		t.Parallel()
		var zeroAddrPort netip.AddrPort
		addr := protocol.AddrFromNetIPAddrPort(zeroAddrPort)

		if addr.Type != 0 {
			t.Fatalf("expected zero AddrType, got %v", addr.Type)
		}
		if addr.Host != nil {
			t.Fatalf("expected nil Host, got %v", addr.Host)
		}
		if addr.Port != 0 {
			t.Fatalf("expected zero Port, got %d", addr.Port)
		}
		if addr.NetTyp != "" {
			t.Fatalf("expected empty NetTyp, got %q", addr.NetTyp)
		}
	})

	t.Run(
		"valid AddrPort with empty network string uses udp default",
		func(t *testing.T) {
			t.Parallel()
			addrPort := netip.MustParseAddrPort("10.0.0.1:53")
			addr := protocol.AddrFromNetIPAddrPort(addrPort, "")

			if addr.NetTyp != "udp" {
				t.Fatalf(
					"expected NetTyp 'udp' for empty string, got %q",
					addr.NetTyp,
				)
			}
		},
	)

	t.Run("valid AddrPort with tcp4 network", func(t *testing.T) {
		t.Parallel()
		addrPort := netip.MustParseAddrPort("172.16.0.1:80")
		addr := protocol.AddrFromNetIPAddrPort(addrPort, "tcp4")

		if addr.NetTyp != "tcp4" {
			t.Fatalf("expected NetTyp 'tcp4', got %q", addr.NetTyp)
		}
		if addr.Type != protocol.IP4Addr {
			t.Fatalf("expected IP4Addr, got %v", addr.Type)
		}
	})
}

func TestAddrFromFQDNNoDotEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("FQDN with multiple trailing dots", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromFQDNNoDot("example.com...", 443, "tcp")
		if addr.ToFQDN() != "example.com" {
			t.Fatalf("expected 'example.com', got %q", addr.ToFQDN())
		}
	})

	t.Run("FQDN with port and trailing dot", func(t *testing.T) {
		t.Parallel()
		// Note: AddrFromFQDNNoDot trims the dot from "8080." -> "8080" which is not a valid port
		// So SplitHostPort will treat "example.com:8080." as host="example.com:8080." with no port
		// After trimming: "example.com:8080" which then becomes the host string
		addr := protocol.AddrFromFQDNNoDot("example.com.", 8080, "tcp")
		if addr.Port != 8080 {
			t.Fatalf("expected port 8080, got %d", addr.Port)
		}
		if addr.ToFQDN() != "example.com" {
			t.Fatalf("expected 'example.com', got %q", addr.ToFQDN())
		}
	})

	t.Run("single dot FQDN", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromFQDNNoDot(".", 80, "tcp")
		if addr.ToFQDN() != "." {
			t.Fatalf("expected '.', got %q", addr.ToFQDN())
		}
	})

	t.Run("empty FQDN", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromFQDNNoDot("", 80, "tcp")
		if addr.ToFQDN() != "" {
			t.Fatalf("expected empty string, got %q", addr.ToFQDN())
		}
	})
}

func TestAddrCopyEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("copy with nil Host", func(t *testing.T) {
		t.Parallel()
		original := protocol.Addr{
			Type:   protocol.IP4Addr,
			Host:   nil,
			Port:   80,
			NetTyp: "tcp",
		}
		copied := original.Copy()

		if copied.Host != nil {
			t.Fatalf("expected nil Host in copy, got %v", copied.Host)
		}
		if copied.Port != original.Port {
			t.Fatalf(
				"port mismatch: got %d, want %d",
				copied.Port,
				original.Port,
			)
		}
	})

	t.Run("copy preserves all fields", func(t *testing.T) {
		t.Parallel()
		original := protocol.AddrFromFQDN("example.com", 443, "tcp")
		copied := original.Copy()

		if copied.Type != original.Type {
			t.Fatalf(
				"Type mismatch: got %v, want %v",
				copied.Type,
				original.Type,
			)
		}
		if copied.Port != original.Port {
			t.Fatalf(
				"Port mismatch: got %d, want %d",
				copied.Port,
				original.Port,
			)
		}
		if copied.NetTyp != original.NetTyp {
			t.Fatalf(
				"NetTyp mismatch: got %q, want %q",
				copied.NetTyp,
				original.NetTyp,
			)
		}
		if !bytes.Equal(copied.Host, original.Host) {
			t.Fatalf("Host mismatch")
		}
	})
}

func TestAddrLenEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("unknown AddrType returns len of Host", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{
			Type: protocol.AddrType(0x99),
			Host: []byte("test"),
		}
		if addr.Len() != 4 {
			t.Fatalf("expected len 4, got %d", addr.Len())
		}
	})

	t.Run("FQDN with empty Host", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{
			Type: protocol.FQDNAddr,
			Host: []byte{},
		}
		if addr.Len() != 0 {
			t.Fatalf("expected len 0, got %d", addr.Len())
		}
	})
}

func TestAddrWithDefaultHostEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("specified address ignores default host", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromString("192.168.1.1", 80, "tcp")
		result := addr.WithDefaultHost("10.0.0.1")

		if result.ToFQDN() != "192.168.1.1" {
			t.Fatalf("expected '192.168.1.1', got %q", result.ToFQDN())
		}
		if result.Port != 80 {
			t.Fatalf("expected port 80, got %d", result.Port)
		}
	})

	t.Run("unspecified with empty default uses 0.0.0.0", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{}
		result := addr.WithDefaultHost("")

		if result.ToFQDN() != "0.0.0.0" {
			t.Fatalf("expected '0.0.0.0', got %q", result.ToFQDN())
		}
	})
}

func TestAddrWithDefaultAddrEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run(
		"specified address returns itself even with non-nil default",
		func(t *testing.T) {
			t.Parallel()
			addr := protocol.AddrFromString("192.168.1.1", 80, "tcp")
			def := protocol.AddrFromString("10.0.0.1", 0, "tcp")
			result := addr.WithDefaultAddr(&def)

			if result.ToFQDN() != "192.168.1.1" {
				t.Fatalf("expected '192.168.1.1', got %q", result.ToFQDN())
			}
		},
	)

	t.Run("unspecified with nil default returns itself", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{}
		result := addr.WithDefaultAddr(nil)

		if !result.IsUnspecified() {
			t.Fatalf("expected unspecified address")
		}
	})

	t.Run(
		"unspecified with non-nil default returns deep copy",
		func(t *testing.T) {
			t.Parallel()
			addr := protocol.Addr{}
			def := protocol.AddrFromString("127.0.0.1", 8080, "tcp")
			result := addr.WithDefaultAddr(&def)

			if result.ToFQDN() != "127.0.0.1" {
				t.Fatalf("expected '127.0.0.1', got %q", result.ToFQDN())
			}
			if result.Port != 8080 {
				t.Fatalf("expected port 8080, got %d", result.Port)
			}
			// Ensure it's a deep copy
			result.Port = 9999
			if def.Port != 8080 {
				t.Fatalf("modification affected original default address")
			}
		},
	)
}

func TestAddrToIPEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("FQDN returns nil", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromFQDN("example.com", 80, "tcp")
		if addr.ToIP() != nil {
			t.Fatalf("expected nil for FQDN, got %v", addr.ToIP())
		}
	})
}

func TestAddrToUDPEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("FQDN returns nil", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromFQDN("example.com", 53, "udp")
		if addr.ToUDP() != nil {
			t.Fatalf("expected nil for FQDN, got %v", addr.ToUDP())
		}
	})
}

func TestAddrToTCPEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("FQDN returns nil", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromFQDN("example.com", 80, "tcp")
		if addr.ToTCP() != nil {
			t.Fatalf("expected nil for FQDN, got %v", addr.ToTCP())
		}
	})
}

func TestAddrToUnspecifiedEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("IPv4 to unspecified", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromString("192.168.1.1", 80, "tcp")
		result := addr.ToUnspecified()

		if !result.IsUnspecified() {
			t.Fatalf("expected unspecified address")
		}
		if result.Type != protocol.IP4Addr {
			t.Fatalf("expected IP4Addr type, got %v", result.Type)
		}
		if result.Port != 0 {
			t.Fatalf("expected zero port, got %d", result.Port)
		}
	})

	t.Run("FQDN to unspecified", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromFQDN("example.com", 443, "tcp")
		result := addr.ToUnspecified()

		if result.Type != protocol.FQDNAddr {
			t.Fatalf("expected FQDNAddr type, got %v", result.Type)
		}
		if len(result.Host) != 0 {
			t.Fatalf(
				"expected empty Host for FQDN unspecified, got %v",
				result.Host,
			)
		}
	})
}

func TestAddrNetworkEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty NetTyp defaults to tcp", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{
			Type:   protocol.FQDNAddr,
			Host:   []byte("example.com"),
			NetTyp: "",
		}
		if addr.Network() != "tcp" {
			t.Fatalf("expected 'tcp', got %q", addr.Network())
		}
	})

	t.Run("IPv4 with empty NetTyp", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{
			Type:   protocol.IP4Addr,
			Host:   net.ParseIP("192.168.1.1").To4(),
			NetTyp: "",
		}
		if addr.Network() != "tcp4" {
			t.Fatalf("expected 'tcp4', got %q", addr.Network())
		}
	})

	t.Run("IPv6 with empty NetTyp", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{
			Type:   protocol.IP6Addr,
			Host:   net.ParseIP("::1").To16(),
			NetTyp: "",
		}
		if addr.Network() != "tcp6" {
			t.Fatalf("expected 'tcp6', got %q", addr.Network())
		}
	})
}

func TestAddrIpNetworkEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("ip NetTyp returns ip", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{NetTyp: "ip"}
		if addr.IpNetwork() != "ip" {
			t.Fatalf("expected 'ip', got %q", addr.IpNetwork())
		}
	})

	t.Run("ip4 NetTyp returns ip4", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{NetTyp: "ip4"}
		if addr.IpNetwork() != "ip4" {
			t.Fatalf("expected 'ip4', got %q", addr.IpNetwork())
		}
	})

	t.Run("ip6 NetTyp returns ip6", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{NetTyp: "ip6"}
		if addr.IpNetwork() != "ip6" {
			t.Fatalf("expected 'ip6', got %q", addr.IpNetwork())
		}
	})

	t.Run("unknown NetTyp returns itself", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{NetTyp: "weird"}
		if addr.IpNetwork() != "weird" {
			t.Fatalf("expected 'weird', got %q", addr.IpNetwork())
		}
	})
}

func TestAddrStringEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("zero port returns ToFQDN", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromString("192.168.1.1", 0, "tcp")
		if addr.String() != "192.168.1.1" {
			t.Fatalf("expected '192.168.1.1', got %q", addr.String())
		}
	})

	t.Run("non-zero port returns ToHostPort", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromString("192.168.1.1", 80, "tcp")
		expected := "192.168.1.1:80"
		if addr.String() != expected {
			t.Fatalf("expected %q, got %q", expected, addr.String())
		}
	})
}

func TestAddrFromTCPAndUDPAddrEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("TCPAddr with negative port clamps to zero", func(t *testing.T) {
		t.Parallel()
		tcpAddr := &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.1"),
			Port: -1,
		}
		addr := protocol.AddrFromTCPAddr(tcpAddr)
		if addr.Port != 0 {
			t.Fatalf("expected port 0, got %d", addr.Port)
		}
	})

	t.Run("UDPAddr with negative port clamps to zero", func(t *testing.T) {
		t.Parallel()
		udpAddr := &net.UDPAddr{
			IP:   net.ParseIP("8.8.8.8"),
			Port: -100,
		}
		addr := protocol.AddrFromUDPAddr(udpAddr)
		if addr.Port != 0 {
			t.Fatalf("expected port 0, got %d", addr.Port)
		}
	})

	t.Run("TCPAddr with valid port", func(t *testing.T) {
		t.Parallel()
		tcpAddr := &net.TCPAddr{
			IP:   net.ParseIP("10.0.0.1"),
			Port: 65535,
		}
		addr := protocol.AddrFromTCPAddr(tcpAddr)
		if addr.Port != 65535 {
			t.Fatalf("expected port 65535, got %d", addr.Port)
		}
	})

	t.Run("UDPAddr with valid port", func(t *testing.T) {
		t.Parallel()
		udpAddr := &net.UDPAddr{
			IP:   net.ParseIP("8.8.4.4"),
			Port: 53,
		}
		addr := protocol.AddrFromUDPAddr(udpAddr)
		if addr.Port != 53 {
			t.Fatalf("expected port 53, got %d", addr.Port)
		}
	})
}

func TestAddrFromHostPortEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("empty hostport with tcp6", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromHostPort("", "tcp6")
		if addr.ToHostPort() != "[::]:0" {
			t.Fatalf("expected '[::]:0', got %q", addr.ToHostPort())
		}
	})

	t.Run("empty hostport with udp6", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromHostPort("", "udp6")
		if addr.ToHostPort() != "[::]:0" {
			t.Fatalf("expected '[::]:0', got %q", addr.ToHostPort())
		}
	})

	t.Run("empty hostport with tcp4", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromHostPort("", "tcp4")
		if addr.ToHostPort() != "0.0.0.0:0" {
			t.Fatalf("expected '0.0.0.0:0', got %q", addr.ToHostPort())
		}
	})

	t.Run("empty hostport with udp4", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromHostPort("", "udp4")
		if addr.ToHostPort() != "0.0.0.0:0" {
			t.Fatalf("expected '0.0.0.0:0', got %q", addr.ToHostPort())
		}
	})
}

func TestAddrFromStringEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("IPv4 address", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromString("10.0.0.1", 80, "tcp")
		if addr.Type != protocol.IP4Addr {
			t.Fatalf("expected IP4Addr, got %v", addr.Type)
		}
	})

	t.Run("IPv6 address", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromString("2001:db8::1", 443, "tcp")
		if addr.Type != protocol.IP6Addr {
			t.Fatalf("expected IP6Addr, got %v", addr.Type)
		}
	})

	t.Run("domain name", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromString("example.com", 80, "tcp")
		if addr.Type != protocol.FQDNAddr {
			t.Fatalf("expected FQDNAddr, got %v", addr.Type)
		}
	})
}

func TestAddrTypeStringUnknown(t *testing.T) {
	t.Parallel()

	unknownType := protocol.AddrType(0x99)
	result := unknownType.String()
	expected := "addr type no153"
	if result != expected {
		t.Fatalf("expected %q, got %q", expected, result)
	}
}

func TestAddrFromFQDNEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("FQDN without port uses provided port", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromFQDN("example.com", 443, "tcp")
		if addr.Port != 443 {
			t.Fatalf("expected port 443, got %d", addr.Port)
		}
	})

	t.Run("FQDN with embedded port overrides", func(t *testing.T) {
		t.Parallel()
		addr := protocol.AddrFromFQDN("example.com:9999", 443, "tcp")
		if addr.Port != 9999 {
			t.Fatalf("expected port 9999, got %d", addr.Port)
		}
	})
}

func TestAddrFromNetAddrCustomFallback(t *testing.T) {
	t.Parallel()

	t.Run("custom net.Addr with tcp6 network", func(t *testing.T) {
		t.Parallel()
		customAddr := fakeAddr("[::1]:8080")
		addr := protocol.AddrFromNetAddr(customAddr)

		if addr.Type != protocol.IP6Addr {
			t.Fatalf("expected IP6Addr, got %v", addr.Type)
		}
		if addr.Port != 8080 {
			t.Fatalf("expected port 8080, got %d", addr.Port)
		}
	})
}

func TestAddrWithNetTypEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("normalizes tcp4 to tcp", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{NetTyp: "tcp4"}
		result := addr.WithNetTyp("tcp4")
		if result.NetTyp != "tcp" {
			t.Fatalf("expected 'tcp', got %q", result.NetTyp)
		}
	})

	t.Run("normalizes tcp6 to tcp", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{NetTyp: "tcp6"}
		result := addr.WithNetTyp("tcp6")
		if result.NetTyp != "tcp" {
			t.Fatalf("expected 'tcp', got %q", result.NetTyp)
		}
	})

	t.Run("normalizes udp4 to udp", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{NetTyp: "udp4"}
		result := addr.WithNetTyp("udp4")
		if result.NetTyp != "udp" {
			t.Fatalf("expected 'udp', got %q", result.NetTyp)
		}
	})

	t.Run("normalizes udp6 to udp", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{NetTyp: "udp6"}
		result := addr.WithNetTyp("udp6")
		if result.NetTyp != "udp" {
			t.Fatalf("expected 'udp', got %q", result.NetTyp)
		}
	})

	t.Run("preserves unknown network", func(t *testing.T) {
		t.Parallel()
		addr := protocol.Addr{NetTyp: "custom"}
		result := addr.WithNetTyp("custom")
		if result.NetTyp != "custom" {
			t.Fatalf("expected 'custom', got %q", result.NetTyp)
		}
	})
}

func TestResolveToIP4EdgeCases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run(
		"IPv6 address returns nil without calling lookup",
		func(t *testing.T) {
			t.Parallel()
			addr := protocol.AddrFromString("::1", 80, "tcp6")
			lookupCalled := false
			lookup := func(context.Context, string, string) ([]net.IP, error) {
				lookupCalled = true
				return nil, nil
			}

			result := addr.ResolveToIP4(ctx, lookup)
			if result != nil {
				t.Fatalf("expected nil for IPv6, got %+v", result)
			}
			if lookupCalled {
				t.Fatalf("lookup should not be called for IPv6")
			}
		},
	)
}
