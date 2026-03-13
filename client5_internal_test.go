//go:build compattest

package socksgo

import (
	"net"
	"testing"
	"time"

	"github.com/asciimoth/socksgo/protocol"
)

// mockConnForResolveUnspecified is a mock net.Conn for testing resolveUnspecifiedAddr.
type mockConnForResolveUnspecified struct {
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (m *mockConnForResolveUnspecified) Read(p []byte) (n int, err error) {
	return 0, nil
}

func (m *mockConnForResolveUnspecified) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (m *mockConnForResolveUnspecified) Close() error {
	return nil
}

func (m *mockConnForResolveUnspecified) LocalAddr() net.Addr {
	if m.localAddr != nil {
		return m.localAddr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (m *mockConnForResolveUnspecified) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *mockConnForResolveUnspecified) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConnForResolveUnspecified) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConnForResolveUnspecified) SetWriteDeadline(t time.Time) error {
	return nil
}

// mockAddrForResolve is a mock net.Addr for testing.
type mockAddrForResolve struct {
	str string
}

func (m *mockAddrForResolve) String() string  { return m.str }
func (m *mockAddrForResolve) Network() string { return "tcp" }

// Test resolveUnspecifiedAddr when naddr is not unspecified (should return naddr unchanged).
func TestResolveUnspecifiedAddr_NotUnspecified(t *testing.T) {
	t.Parallel()

	proxy := &mockConnForResolveUnspecified{
		remoteAddr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999},
	}
	// Specified address (not 0.0.0.0)
	naddr := protocol.AddrFromHostPort("192.168.1.1:8080", "tcp")

	result := resolveUnspecifiedAddr(proxy, naddr)

	if result.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", result.Port)
	}
	if !result.ToIP().Equal(net.IPv4(192, 168, 1, 1)) {
		t.Fatalf("expected IP 192.168.1.1, got %v", result.ToIP())
	}
}

// Test resolveUnspecifiedAddr when proxy.RemoteAddr() is nil (should return naddr unchanged).
func TestResolveUnspecifiedAddr_RemoteAddrNil(t *testing.T) {
	t.Parallel()

	proxy := &mockConnForResolveUnspecified{
		remoteAddr: nil,
	}
	// Unspecified address
	naddr := protocol.AddrFromHostPort("0.0.0.0:8080", "tcp")

	result := resolveUnspecifiedAddr(proxy, naddr)

	if result.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", result.Port)
	}
	if !result.ToIP().Equal(net.IPv4(0, 0, 0, 0)) {
		t.Fatalf("expected IP 0.0.0.0, got %v", result.ToIP())
	}
}

// Test resolveUnspecifiedAddr when SplitHostPort fails (malformed remote addr).
func TestResolveUnspecifiedAddr_SplitHostPortFails(t *testing.T) {
	t.Parallel()

	proxy := &mockConnForResolveUnspecified{
		remoteAddr: &mockAddrForResolve{str: "malformed-no-port"},
	}
	// Unspecified address
	naddr := protocol.AddrFromHostPort("0.0.0.0:8080", "tcp")

	result := resolveUnspecifiedAddr(proxy, naddr)

	// Should return naddr unchanged (graceful degradation)
	if result.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", result.Port)
	}
	if !result.ToIP().Equal(net.IPv4(0, 0, 0, 0)) {
		t.Fatalf("expected IP 0.0.0.0, got %v", result.ToIP())
	}
}

// Test resolveUnspecifiedAddr success path (unspecified addr with valid remote addr).
func TestResolveUnspecifiedAddr_Success(t *testing.T) {
	t.Parallel()

	proxy := &mockConnForResolveUnspecified{
		remoteAddr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999},
	}
	// Unspecified address
	naddr := protocol.AddrFromHostPort("0.0.0.0:8080", "tcp")

	result := resolveUnspecifiedAddr(proxy, naddr)

	// Should use host from proxy remote addr, port from naddr
	if result.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", result.Port)
	}
	if !result.ToIP().Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("expected IP 10.0.0.1, got %v", result.ToIP())
	}
	// Network type should be tcp4 (derived from IPv4 address)
	if result.Network() != "tcp4" {
		t.Fatalf("expected network tcp4, got %s", result.Network())
	}
}

// Test resolveUnspecifiedAddr with IPv6 remote addr.
func TestResolveUnspecifiedAddr_IPv6Remote(t *testing.T) {
	t.Parallel()

	ipv6Addr := &net.TCPAddr{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 9999,
	}
	proxy := &mockConnForResolveUnspecified{
		remoteAddr: ipv6Addr,
	}
	// Unspecified address
	naddr := protocol.AddrFromHostPort("0.0.0.0:8080", "tcp")

	result := resolveUnspecifiedAddr(proxy, naddr)

	// Should use host from proxy remote addr, port from naddr
	if result.Port != 8080 {
		t.Fatalf("expected port 8080, got %d", result.Port)
	}
	if !result.ToIP().Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("expected IP 2001:db8::1, got %v", result.ToIP())
	}
	// Network type should be tcp6 (derived from IPv6 address)
	if result.Network() != "tcp6" {
		t.Fatalf("expected network tcp6, got %s", result.Network())
	}
}

// Test resolveUnspecifiedAddr preserves network type from proxy.
func TestResolveUnspecifiedAddr_PreservesNetworkType(t *testing.T) {
	t.Parallel()

	proxy := &mockConnForResolveUnspecified{
		remoteAddr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999},
	}
	// Unspecified address with tcp4 network type
	naddr := protocol.AddrFromHostPort("0.0.0.0:8080", "tcp4")

	result := resolveUnspecifiedAddr(proxy, naddr)

	if result.Network() != "tcp4" {
		t.Fatalf("expected network tcp4, got %s", result.Network())
	}
}
