package protocol_test

import (
	"bytes"
	"net"
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
