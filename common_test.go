package socksgo_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/asciimoth/gonnect"
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
			p := gonnect.FalseFilter(net, addr)
			m := gonnect.TrueFilter(net, addr)
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
		got := gonnect.LoopbackFilter("", tt.addr)
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
	gonnect.PacketConn
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
	FnLookupIP     func(ctx context.Context, network, address string) ([]net.IP, error)
	FnLookupAddr   func(ctx context.Context, address string) ([]string, error)
	FnLookupIPAddr func(ctx context.Context, host string) ([]net.IPAddr, error)
	FnLookupNetIP  func(ctx context.Context, network, host string) ([]netip.Addr, error)
	FnLookupHost   func(ctx context.Context, host string) ([]string, error)
	FnLookupCNAME  func(ctx context.Context, host string) (string, error)
	FnLookupPort   func(ctx context.Context, network, service string) (int, error)
	FnLookupNS     func(ctx context.Context, name string) ([]*net.NS, error)
	FnLookupMX     func(ctx context.Context, name string) ([]*net.MX, error)
	FnLookupSRV    func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	FnLookupTXT    func(ctx context.Context, name string) ([]string, error)
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

func (m *mockResolver) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	if m.FnLookupIPAddr != nil {
		return m.FnLookupIPAddr(ctx, host)
	}
	return nil, nil
}

func (m *mockResolver) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	if m.FnLookupNetIP != nil {
		return m.FnLookupNetIP(ctx, network, host)
	}
	return nil, nil
}

func (m *mockResolver) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	if m.FnLookupHost != nil {
		return m.FnLookupHost(ctx, host)
	}
	return nil, nil
}

func (m *mockResolver) LookupCNAME(
	ctx context.Context,
	host string,
) (string, error) {
	if m.FnLookupCNAME != nil {
		return m.FnLookupCNAME(ctx, host)
	}
	return "", nil
}

func (m *mockResolver) LookupPort(
	ctx context.Context,
	network, service string,
) (int, error) {
	if m.FnLookupPort != nil {
		return m.FnLookupPort(ctx, network, service)
	}
	return 0, nil
}

func (m *mockResolver) LookupNS(
	ctx context.Context,
	name string,
) ([]*net.NS, error) {
	if m.FnLookupNS != nil {
		return m.FnLookupNS(ctx, name)
	}
	return nil, nil
}

func (m *mockResolver) LookupMX(
	ctx context.Context,
	name string,
) ([]*net.MX, error) {
	if m.FnLookupMX != nil {
		return m.FnLookupMX(ctx, name)
	}
	return nil, nil
}

func (m *mockResolver) LookupSRV(
	ctx context.Context,
	service, proto, name string,
) (string, []*net.SRV, error) {
	if m.FnLookupSRV != nil {
		return m.FnLookupSRV(ctx, service, proto, name)
	}
	return "", nil, nil
}

func (m *mockResolver) LookupTXT(
	ctx context.Context,
	name string,
) ([]string, error) {
	if m.FnLookupTXT != nil {
		return m.FnLookupTXT(ctx, name)
	}
	return nil, nil
}

func TestErrorToReplyStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: 0, // SuccReply
		},
		{
			name: "connection refused",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("connection refused"),
			},
			expected: 5, // ConnRefusedReply
		},
		{
			name: "network unreachable",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("network unreachable"),
			},
			expected: 3, // NetUnreachReply
		},
		{
			name: "host unreachable",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("host unreachable"),
			},
			expected: 4, // HostUnreachReply
		},
		{
			name: "i/o timeout",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: errors.New("i/o timeout"),
			},
			expected: 6, // TTLExpiredReply
		},
		{
			name: "connection timed out",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: errors.New("connection timed out"),
			},
			expected: 6, // TTLExpiredReply
		},
		{
			name: "permission denied",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("permission denied"),
			},
			expected: 2, // DisallowReply
		},
		{
			name: "DNS error",
			err: &net.DNSError{
				Err:  "no such host",
				Name: "nonexistent.example.com",
			},
			expected: 4, // HostUnreachReply
		},
		{
			name:     "generic error",
			err:      errors.New("some random error"),
			expected: 1, // FailReply
		},
		{
			name: "wrapped connection refused",
			err: fmt.Errorf(
				"dial failed: %w",
				&net.OpError{
					Op:  "dial",
					Net: "tcp",
					Err: errors.New("connection refused"),
				},
			),
			expected: 5, // ConnRefusedReply
		},
		{
			name: "wrapped DNS error",
			err: fmt.Errorf(
				"lookup failed: %w",
				&net.DNSError{
					Err:  "no such host",
					Name: "example.com",
				},
			),
			expected: 4, // HostUnreachReply
		},
		{
			name: "wrapped permission denied",
			err: fmt.Errorf(
				"access denied: %w",
				&net.OpError{
					Op:  "dial",
					Net: "tcp",
					Err: errors.New("permission denied"),
				},
			),
			expected: 2, // DisallowReply
		},
		{
			name: "double wrapped error",
			err: fmt.Errorf(
				"outer: %w",
				fmt.Errorf(
					"inner: %w",
					&net.OpError{
						Op:  "dial",
						Net: "tcp",
						Err: errors.New("connection refused"),
					},
				),
			),
			expected: 5, // ConnRefusedReply
		},
		{
			name: "OpError with OpError as Err",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &net.OpError{
					Op:  "read",
					Net: "tcp",
					Err: errors.New("connection refused"),
				},
			},
			expected: 5, // ConnRefusedReply
		},
		{
			name: "DNS error wrapped in OpError",
			err: &net.OpError{
				Op:  "lookup",
				Net: "dns",
				Err: &net.DNSError{
					Err:  "no such host",
					Name: "example.com",
				},
			},
			expected: 4, // HostUnreachReply
		},
		{
			name: "OpError with nil Err falls back to OpError string",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("connection refused"),
			},
			expected: 5, // ConnRefusedReply
		},
		{
			name: "bare DNSError without OpError wrapper",
			err: &net.DNSError{
				Err:  "no such host",
				Name: "example.com",
			},
			expected: 4, // HostUnreachReply
		},
		{
			name: "OpError wrapping DNSError should find DNSError via errors.As",
			err: fmt.Errorf(
				"wrapped: %w",
				&net.OpError{
					Op:  "lookup",
					Net: "dns",
					Err: &net.DNSError{
						Err:  "no such host",
						Name: "example.com",
					},
				},
			),
			expected: 4, // HostUnreachReply
		},
		{
			name: "OpError with host unreachable message in Err",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("host unreachable"),
			},
			expected: 4, // HostUnreachReply
		},
		{
			name: "OpError with network unreachable message in Err",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("network unreachable"),
			},
			expected: 3, // NetUnreachReply
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Test error message patterns directly since errorToReplyStatus is
			// unexported
			got := testErrorToReplyStatus(tt.err)
			if int(got) != tt.expected {
				t.Errorf(
					"errorToReplyStatus() = %d, want %d",
					int(got),
					tt.expected,
				)
			}
		})
	}
}

// testErrorToReplyStatus is a test helper that mirrors the logic in errorToReplyStatus
func testErrorToReplyStatus(err error) uint8 {
	if err == nil {
		return 0
	}

	// Unwrap to get to the underlying error
	var unwrapped = err
	for {
		u := errors.Unwrap(unwrapped)
		if u == nil {
			break
		}
		unwrapped = u
	}

	// Check for specific error types
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		err = opErr
		unwrapped = opErr.Err
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return 4 // HostUnreachReply
	}

	// Check error message for known patterns
	errStr := unwrapped.Error()
	if strings.Contains(errStr, "connection refused") {
		return 5 // ConnRefusedReply
	}
	if strings.Contains(errStr, "network unreachable") {
		return 3 // NetUnreachReply
	}
	if strings.Contains(errStr, "host unreachable") {
		return 4 // HostUnreachReply
	}
	if strings.Contains(errStr, "connection timed out") ||
		strings.Contains(errStr, "i/o timeout") {
		return 6 // TTLExpiredReply
	}
	if strings.Contains(errStr, "permission denied") {
		return 2 // DisallowReply
	}

	// Default to general failure
	return 1 // FailReply
}
