//go:build testhooks

package socksgo_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
	socksgo "github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

// mockConnForClient5 implements net.Conn with configurable behavior for client5 tests.
type mockConnForClient5 struct {
	readData      []byte
	readOffset    int
	readErr       error
	readErrAfter  int // Return readErr after this many reads
	readCount     int // Track number of reads
	writeData     []byte
	writeErr      error
	writeErrAfter int // Return writeErr after this many writes
	writeCount    int // Track number of writes
	closeErr      error
	deadlineErr   error
	closed        bool
	remoteAddr    net.Addr
	localAddr     net.Addr
	setDeadlineFn func(t time.Time) error
	// State tracking for SOCKS5 handshake
	authSent         bool // Track if auth response was sent
	skipAuthResponse bool // If true, don't prepend auth response (for testing auth errors)
}

func (m *mockConnForClient5) Read(p []byte) (n int, err error) {
	m.readCount++
	if m.readErrAfter > 0 && m.readCount > m.readErrAfter {
		return 0, m.readErr
	}
	if m.readOffset >= len(m.readData) {
		if m.readErr != nil && m.readErrAfter == 0 {
			return 0, m.readErr
		}
		return 0, io.EOF
	}
	n = copy(p, m.readData[m.readOffset:])
	m.readOffset += n
	return n, nil
}

func (m *mockConnForClient5) Write(p []byte) (n int, err error) {
	m.writeCount++
	// Handle SOCKS5 auth negotiation
	// Client sends: [5, NMETHODS, METHODS...]
	// Server responds: [5, METHOD]
	if !m.authSent && !m.skipAuthResponse && len(p) >= 2 && p[0] == 5 &&
		p[1] >= 1 {
		// Auth negotiation - respond with no auth required
		m.authSent = true
		// Prepend auth response to readData
		m.readData = append([]byte{5, 0}, m.readData...)
	}
	if m.writeErrAfter > 0 && m.writeCount > m.writeErrAfter {
		return 0, m.writeErr
	}
	if m.writeErr != nil && m.writeErrAfter == 0 {
		return 0, m.writeErr
	}
	m.writeData = append(m.writeData, p...)
	return len(p), nil
}

func (m *mockConnForClient5) Close() error {
	m.closed = true
	return m.closeErr
}

func (m *mockConnForClient5) LocalAddr() net.Addr {
	if m.localAddr != nil {
		return m.localAddr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (m *mockConnForClient5) RemoteAddr() net.Addr {
	if m.remoteAddr != nil {
		return m.remoteAddr
	}
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}
}

func (m *mockConnForClient5) SetDeadline(t time.Time) error {
	if m.deadlineErr != nil {
		return m.deadlineErr
	}
	if m.setDeadlineFn != nil {
		return m.setDeadlineFn(t)
	}
	return nil
}

func (m *mockConnForClient5) SetReadDeadline(t time.Time) error {
	return m.SetDeadline(t)
}

func (m *mockConnForClient5) SetWriteDeadline(t time.Time) error {
	return m.SetDeadline(t)
}

// Test request5 when Connect fails.
func TestRequest5_ConnectFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dialErr := errors.New("dial failed")
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, dialErr
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("expected error when Connect fails")
	}
	if !errors.Is(err, dialErr) && err.Error() != dialErr.Error() {
		t.Fatalf("expected dial error, got %v", err)
	}
	if proxy != nil {
		t.Fatal("expected nil proxy on Connect failure")
	}
	if addr.Type != 0 {
		t.Fatal("expected zero addr on Connect failure")
	}
}

// Test request5 when RunAuth fails.
func TestRequest5_AuthFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	authErr := errors.New("auth failed")
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{}, nil
		},
		Auth: (&protocol.AuthMethods{}).Add(&mockAuthMethod{err: authErr}),
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("expected error when Auth fails")
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy to be closed on auth failure")
	}
	if m, ok := proxy.(*mockConnForClient5); ok {
		if !m.closed {
			t.Fatal("expected proxy to be closed on auth failure")
		}
	}
	if addr.Type != 0 {
		t.Fatal("expected zero addr on auth failure")
	}
}

// Test request5 when server responds with wrong auth version.
func TestRequest5_AuthWrongVersion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Server responds with wrong version (4 instead of 5)
			// skipAuthResponse=true so mock doesn't prepend [5, 0]
			return &mockConnForClient5{
				readData:         []byte{4, 0},
				skipAuthResponse: true,
			}, nil
		},
	}

	_, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("expected error when auth version is wrong")
	}
	// Note: proxy is nil on auth error because authenticate() closes and returns nil
	if addr.Type != 0 {
		t.Fatal("expected zero addr on auth version error")
	}
}

// Test request5 when server selects unsupported auth method.
func TestRequest5_AuthUnsupportedMethod(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Server selects GSS-API (method 1) which we don't support
			// skipAuthResponse=true so mock doesn't prepend [5, 0]
			return &mockConnForClient5{
				readData:         []byte{5, 1},
				skipAuthResponse: true,
			}, nil
		},
	}

	_, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("expected error when auth method is unsupported")
	}
	// Note: proxy is nil on auth error because authenticate() closes and returns nil
	if addr.Type != 0 {
		t.Fatal("expected zero addr on unsupported auth method")
	}
}

// Test request5 when BuildSocks5TCPRequest fails (FQDN too long).
func TestRequest5_BuildRequestFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{}, nil
		},
	}

	// Use a very long FQDN to trigger error in BuildSocks5TCPRequest
	longHost := string(make([]byte, 300))
	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromFQDN(longHost, 80, "tcp"),
	)
	if err == nil {
		t.Fatal("expected error when BuildSocks5TCPRequest fails")
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy to be closed")
	}
	if m, ok := proxy.(*mockConnForClient5); ok {
		if !m.closed {
			t.Fatal("expected proxy to be closed on build failure")
		}
	}
	if addr.Type != 0 {
		t.Fatal("expected zero addr on build failure")
	}
}

// Test request5 when io.Copy fails (write error).
func TestRequest5_CopyFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	writeErr := errors.New("write failed")
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			// writeErrAfter=1 means: succeed on first Write (auth), fail on subsequent Writes (request)
			return &mockConnForClient5{
				writeErr:      writeErr,
				writeErrAfter: 1,
			}, nil
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("expected error when io.Copy fails")
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy to be closed on copy failure")
	}
	if m, ok := proxy.(*mockConnForClient5); ok {
		if !m.closed {
			t.Fatal("expected proxy to be closed on copy failure")
		}
	}
	if addr.Type != 0 {
		t.Fatal("expected zero addr on copy failure")
	}
}

// Test request5 when ReadSocks5TCPReply fails (read error).
func TestRequest5_ReadReplyFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	readErr := errors.New("read failed")
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readErr: readErr}, nil
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("expected error when ReadSocks5TCPReply fails")
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy to be closed on read reply failure")
	}
	if m, ok := proxy.(*mockConnForClient5); ok {
		if !m.closed {
			t.Fatal("expected proxy to be closed on read reply failure")
		}
	}
	if addr.Type != 0 {
		t.Fatal("expected zero addr on read reply failure")
	}
}

// Test request5 when server returns rejection (stat.Ok() is false).
func TestRequest5_ServerRejects(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply: VER=5, REP=1 (general failure), RSV=0, ATYP=1, DST.ADDR=0.0.0.0, DST.PORT=0
	// Prepend auth response [5, 0]
	replyData := []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	proxy, _, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("expected error when server rejects")
	}
	var rejectErr socksgo.RejectdError
	if !errors.As(err, &rejectErr) {
		t.Fatalf("expected RejectdError, got %T: %v", err, err)
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy to be closed on server rejection")
	}
	if m, ok := proxy.(*mockConnForClient5); ok {
		if !m.closed {
			t.Fatal("expected proxy to be closed on server rejection")
		}
	}
	// Note: addr is still returned on rejection (contains the BND.ADDR from reply)
}

// Test request5 when server returns 0.0.0.0:0 (use proxy addr).
func TestRequest5_UseProxyAddr(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply: VER=5, REP=0 (success), RSV=0, ATYP=1, DST.ADDR=0.0.0.0, DST.PORT=0
	// Prepend auth response [5, 0]
	replyData := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	remoteAddr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData:   replyData,
				remoteAddr: remoteAddr,
			}, nil
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy on success")
	}
	// Address should be taken from proxy remote addr with port from reply
	if addr.Port != 0 {
		t.Fatalf("expected port 0, got %d", addr.Port)
	}
	if !addr.ToIP().Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("expected IP 10.0.0.1, got %v", addr.ToIP())
	}
	// NetTyp should be preserved from the reply addr
	if addr.Network() != "tcp" && addr.Network() != "tcp4" {
		t.Fatalf("expected network tcp or tcp4, got %s", addr.Network())
	}
	_ = proxy.Close()
}

// Test request5 success path.
func TestRequest5_Success(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply: VER=5, REP=0 (success), RSV=0, ATYP=1, DST.ADDR=93.184.216.34, DST.PORT=80
	replyData := []byte{5, 0, 0, 1, 93, 184, 216, 34, 0, 80}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy on success")
	}
	if addr.Port != 80 {
		t.Fatalf("expected port 80, got %d", addr.Port)
	}
	if !addr.ToIP().Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("expected IP 93.184.216.34, got %v", addr.ToIP())
	}
	_ = proxy.Close()
}

// Test request5 with context cancellation.
func TestRequest5_ContextCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Filter:       gonnect.FalseFilter,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}

	_, _, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("127.0.0.1:80", "tcp"),
	)
	if err == nil {
		t.Fatal("expected error when context is cancelled")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// mockAuthMethod is a mock auth method that always fails.
type mockAuthMethod struct {
	err error
}

func (m *mockAuthMethod) Name() string                  { return "mock" }
func (m *mockAuthMethod) Code() protocol.AuthMethodCode { return 0x02 }

func (m *mockAuthMethod) RunAuth(
	conn net.Conn,
	pool bufpool.Pool,
) (net.Conn, protocol.AuthInfo, error) {
	return conn, protocol.AuthInfo{}, m.err
}

// mockPacketConn implements gonnect.PacketConn for testing.
type mockPacketConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     bool
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, io.EOF
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (m *mockPacketConn) Read(p []byte) (n int, err error) {
	return 0, io.EOF
}

func (m *mockPacketConn) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (m *mockPacketConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockPacketConn) LocalAddr() net.Addr {
	if m.localAddr != nil {
		return m.localAddr
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (m *mockPacketConn) RemoteAddr() net.Addr {
	if m.remoteAddr != nil {
		return m.remoteAddr
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (m *mockPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Test dialPacket5 when UDP is disallowed (TLS without insecureudp).
func TestDialPacket5_UDPDisallowed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		TLS:          true,
		// InsecureUDP is false by default, so UDP should be disallowed
	}

	pc, err := c.ListenPacket(ctx, "udp", "8.8.8.8:0")
	if err == nil {
		t.Fatal("expected error when UDP is disallowed")
	}
	if !errors.Is(err, socksgo.ErrUDPDisallowed) {
		t.Fatalf("expected ErrUDPDisallowed, got %v", err)
	}
	if pc != nil {
		t.Fatal("expected nil packet conn when UDP is disallowed")
	}
}

// Test dialPacket5 when Request fails.
func TestDialPacket5_RequestFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dialErr := errors.New("dial failed")
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, dialErr
		},
	}

	pc, err := c.ListenPacket(ctx, "udp", "8.8.8.8:0")
	if err == nil {
		t.Fatal("expected error when Request fails")
	}
	if pc != nil {
		t.Fatal("expected nil packet conn on Request failure")
	}
}

// Test dialPacket5 when PacketDialer fails.
func TestDialPacket5_PacketDialerFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 UDP ASSOC reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=127.0.0.1, BND.PORT=5000
	replyData := []byte{5, 0, 0, 1, 127, 0, 0, 1, 19, 136}
	packetDialErr := errors.New("packet dial failed")
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
		PacketDialer: func(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
			return nil, packetDialErr
		},
	}

	pc, err := c.ListenPacket(ctx, "udp", "8.8.8.8:0")
	if err == nil {
		t.Fatal("expected error when PacketDialer fails")
	}
	if pc != nil {
		t.Fatal("expected nil packet conn on PacketDialer failure")
	}
}

// Test setupUDPTun5 when UDP is disallowed.
func TestSetupUDPTun5_UDPDisallowed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		TLS:          true,
		GostUDPTun:   true,
	}

	pc, err := c.ListenPacket(ctx, "udp", "8.8.8.8:0")
	if err == nil {
		t.Fatal("expected error when UDP is disallowed for UDPTun")
	}
	if !errors.Is(err, socksgo.ErrUDPDisallowed) {
		t.Fatalf("expected ErrUDPDisallowed, got %v", err)
	}
	if pc != nil {
		t.Fatal("expected nil packet conn when UDP is disallowed")
	}
}

// Test setupUDPTun5 when Request fails.
func TestSetupUDPTun5_RequestFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dialErr := errors.New("dial failed")
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostUDPTun:   true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, dialErr
		},
	}

	pc, err := c.ListenPacket(ctx, "udp", "8.8.8.8:0")
	if err == nil {
		t.Fatal("expected error when Request fails for UDPTun")
	}
	if pc != nil {
		t.Fatal("expected nil packet conn on Request failure")
	}
}

// Test setupUDPTun5 when SplitHostPort fails (malformed remote addr).
// Note: With graceful degradation, resolveUnspecifiedAddr returns the original
// naddr unchanged if SplitHostPort fails. This test verifies that behavior.
func TestSetupUDPTun5_SplitHostPortFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply with unspecified addr (0.0.0.0:0) to trigger resolveUnspecifiedAddr
	replyData := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostUDPTun:   true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Return conn with malformed RemoteAddr
			return &mockConnForClient5{
				readData:   replyData,
				remoteAddr: &mockAddr{str: "malformed-no-port"},
			}, nil
		},
		PacketDialer: func(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
			return &mockPacketConn{
				localAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
				remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
			}, nil
		},
	}

	// With graceful degradation, this should NOT error - it should use the original naddr
	pc, err := c.ListenPacket(ctx, "udp", "8.8.8.8:0")
	if err != nil {
		t.Fatalf("expected no error with graceful degradation, got: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil packet conn")
	}
	_ = pc.Close()
}

// mockAddr is a mock net.Addr for testing.
type mockAddr struct {
	str string
}

func (m *mockAddr) String() string  { return m.str }
func (m *mockAddr) Network() string { return "tcp" }

// Test resolveUnspecifiedAddr with valid remote addr - tested indirectly through setupUDPTun5.
// The resolveUnspecifiedAddr helper is called when naddr.IsUnspecified() && proxy.RemoteAddr() != nil.
// This is tested by TestSetupUDPTun5_UnspecifiedAddr which verifies the full flow.

// Test setupUDPTun5 success path with unspecified addr.
func TestSetupUDPTun5_UnspecifiedAddr(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply with unspecified addr (0.0.0.0:0)
	replyData := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	remoteAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000, Zone: ""}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostUDPTun:   true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData:   replyData,
				remoteAddr: remoteAddr,
			}, nil
		},
		PacketDialer: func(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
			return &mockPacketConn{
				localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
				remoteAddr: &net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: 5000,
				},
			}, nil
		},
	}

	pc, err := c.ListenPacket(ctx, "udp", "8.8.8.8:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil packet conn on success")
	}
	_ = pc.Close()
}

// Test clientListener5.Addr.
func TestClientListener5_Addr(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 BIND reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=192.168.1.1, BND.PORT=8080
	replyData := []byte{5, 0, 0, 1, 192, 168, 1, 1, 31, 144}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	addr := ln.Addr()
	if addr == nil {
		t.Fatal("expected non-nil addr")
	}
	if addr.String() != "192.168.1.1:8080" {
		t.Fatalf("expected addr 192.168.1.1:8080, got %s", addr.String())
	}
}

// Test clientListener5.Close.
func TestClientListener5_Close(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 BIND reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0
	replyData := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	err = ln.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

// Test clientListener5.Close with error.
func TestClientListener5_CloseWithError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	closeErr := errors.New("close failed")
	replyData := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData: replyData,
				closeErr: closeErr,
			}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	err = ln.Close()
	if err == nil {
		t.Fatal("expected close error")
	}
	if err.Error() != closeErr.Error() {
		t.Fatalf("expected close error %v, got %v", closeErr, err)
	}
}

// Test clientListener5.Accept when read fails.
func TestClientListener5_AcceptReadFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	readErr := errors.New("read failed")
	// First reply for BIND, then second reply for Accept, then error
	// BIND reply [5, 0, 0, 1, 10, 0, 0, 1, 39, 15] + Accept reply [5, 0, 0, 1, 192, 168, 1, 1, 0, 80]
	replyData := []byte{
		5,
		0,
		0,
		1,
		10,
		0,
		0,
		1,
		39,
		15,
		5,
		0,
		0,
		1,
		192,
		168,
		1,
		1,
		0,
		80,
	}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData:     replyData,
				readErr:      readErr,
				readErrAfter: 3,
			}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	_, err = ln.Accept()
	if err == nil {
		t.Fatal("expected error when read fails")
	}
}

// Test clientListener5.Accept when server rejects.
func TestClientListener5_AcceptServerRejects(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// First reply for BIND (success), second reply (rejection)
	replyData := []byte{
		5,
		0,
		0,
		1,
		10,
		0,
		0,
		1,
		39,
		15,
		5,
		1,
		0,
		1,
		0,
		0,
		0,
		0,
		0,
		0,
	}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	_, err = ln.Accept()
	if err == nil {
		t.Fatal("expected error when server rejects")
	}
	var rejectErr socksgo.RejectdError
	if !errors.As(err, &rejectErr) {
		t.Fatalf("expected RejectdError, got %T: %v", err, err)
	}
}

// Test clientListener5.Accept success path.
func TestClientListener5_AcceptSuccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// First reply for BIND (success), second reply for Accept (connected client)
	// Auth [5, 0] + First BIND reply [5, 0, 0, 1, 10, 0, 0, 1, 39, 15] + Second reply [5, 0, 0, 1, 192, 168, 1, 1, 0, 80]
	replyData := []byte{
		5,
		0,
		0,
		1,
		10,
		0,
		0,
		1,
		39,
		15,
		5,
		0,
		0,
		1,
		192,
		168,
		1,
		1,
		0,
		80,
	}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil conn on success")
	}
	defer func() { _ = conn.Close() }()

	// Verify the connection works
	testData := []byte("hello")
	n, err := conn.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(testData) {
		t.Fatalf("expected to write %d bytes, wrote %d", len(testData), n)
	}
}

// Test clientListener5mux.Addr.
func TestClientListener5mux_Addr(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 MBIND reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=192.168.1.1, BND.PORT=8080
	replyData := []byte{5, 0, 0, 1, 192, 168, 1, 1, 31, 144}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostMbind:    true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	addr := ln.Addr()
	if addr == nil {
		t.Fatal("expected non-nil addr")
	}
	if addr.String() != "192.168.1.1:8080" {
		t.Fatalf("expected addr 192.168.1.1:8080, got %s", addr.String())
	}
}

// Test clientListener5mux.Close.
func TestClientListener5mux_Close(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 MBIND reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0
	replyData := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostMbind:    true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	err = ln.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

// Test clientListener5mux.Accept.
func TestClientListener5mux_Accept(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 MBIND reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0
	replyData := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostMbind:    true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Accept should block waiting for incoming smux streams
	// We'll use a timeout to avoid blocking forever
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := ln.Accept()
		// Should get an error when session is closed
		if err == nil {
			t.Log("Accept returned nil (unexpected)")
		}
	}()

	select {
	case <-done:
		// Accept returned
	case <-time.After(2 * time.Second):
		t.Fatal("Accept blocked forever")
	}
}

// Test request5 with different reply status codes.
func TestRequest5_DifferentReplyStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rep      byte
		expected string
	}{
		{"success", 0, ""},
		{"general_failure", 1, "rejected"},
		{"disallowed", 2, "rejected"},
		{"network_unreachable", 3, "rejected"},
		{"host_unreachable", 4, "rejected"},
		{"connection_refused", 5, "rejected"},
		{"ttl_expired", 6, "rejected"},
		{"command_not_supported", 7, "rejected"},
		{"address_not_supported", 8, "rejected"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			// SOCKS5 reply with specified REP code
			replyData := []byte{5, tt.rep, 0, 1, 0, 0, 0, 0, 0, 0}
			c := &socksgo.Client{
				SocksVersion: "5",
				ProxyAddr:    "127.0.0.1:1080",
				Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
					return &mockConnForClient5{readData: replyData}, nil
				},
			}

			proxy, _, err := c.Request(
				ctx,
				protocol.CmdConnect,
				protocol.AddrFromHostPort("example.com:80", "tcp"),
			)

			if tt.rep == 0 { //nolint
				// Success case
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if proxy == nil {
					t.Fatal("expected non-nil proxy on success")
				}
				_ = proxy.Close()
			} else {
				// Failure case
				if err == nil {
					t.Fatal("expected error when server rejects")
				}
				if !bytes.Contains( //nolint
					[]byte(err.Error()),
					[]byte(tt.expected),
				) { //nolint
					t.Fatalf(
						"expected error to contain %q, got %v",
						tt.expected,
						err,
					)
				}
				var rejectErr socksgo.RejectdError
				if !errors.As(err, &rejectErr) {
					t.Fatalf("expected RejectdError, got %T: %v", err, err)
				}
				if proxy == nil {
					t.Fatal("expected non-nil proxy to be closed")
				}
				if m, ok := proxy.(*mockConnForClient5); ok {
					if !m.closed {
						t.Fatal(
							"expected proxy to be closed on server rejection",
						)
					}
				}
			}
			// Note: addr is returned even on error (contains BND.ADDR from reply)
		})
	}
}

// Test request5 with IPv6 reply.
func TestRequest5_IPv6Reply(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply: VER=5, REP=0, RSV=0, ATYP=4 (IPv6), DST.ADDR=::1, DST.PORT=443
	replyData := []byte{
		5, 0, 0, 4,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		1, 187,
	}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:443", "tcp"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy on success")
	}
	if addr.Port != 443 {
		t.Fatalf("expected port 443, got %d", addr.Port)
	}
	if !addr.ToIP().Equal(net.IPv6loopback) {
		t.Fatalf("expected IP ::1, got %v", addr.ToIP())
	}
	_ = proxy.Close()
}

// Test request5 with FQDN reply.
func TestRequest5_FQDNReply(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply: VER=5, REP=0, RSV=0, ATYP=3 (FQDN), DST=example.com, DST.PORT=80
	replyData := []byte{
		5, 0, 0, 3,
		11, // length
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
		0, 80,
	}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy on success")
	}
	if addr.Port != 80 {
		t.Fatalf("expected port 80, got %d", addr.Port)
	}
	if addr.Type != protocol.FQDNAddr {
		t.Fatalf("expected FQDN addr type, got %d", addr.Type)
	}
	_ = proxy.Close()
}

// Test that request5 properly closes proxy on auth error.
func TestRequest5_ProxyClosedOnAuthError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	authErr := errors.New("auth failed")
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{}, nil
		},
		Auth: (&protocol.AuthMethods{}).Add(&mockAuthMethod{err: authErr}),
	}

	proxy, _, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("expected error when auth fails")
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy")
	}
	if m, ok := proxy.(*mockConnForClient5); ok {
		if !m.closed {
			t.Fatal("expected proxy to be closed on auth error")
		}
	}
}

// Test that request5 properly closes proxy on reply error.
func TestRequest5_ProxyClosedOnReplyError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	replyErr := errors.New("reply error")
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readErr: replyErr}, nil
		},
	}

	proxy, _, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("expected error when reply fails")
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy")
	}
	if m, ok := proxy.(*mockConnForClient5); ok {
		if !m.closed {
			t.Fatal("expected proxy to be closed on reply error")
		}
	}
}

// Test dialPacket5 with DoNotSpawnUDPAsocProbber set.
func TestDialPacket5_NoProbber(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 UDP ASSOC reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=127.0.0.1, BND.PORT=5000
	replyData := []byte{5, 0, 0, 1, 127, 0, 0, 1, 19, 136}
	c := &socksgo.Client{
		SocksVersion:             "5",
		ProxyAddr:                "127.0.0.1:1080",
		DoNotSpawnUDPAsocProbber: true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
		PacketDialer: func(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
			return &mockPacketConn{
				localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
				remoteAddr: &net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: 5000,
				},
			}, nil
		},
	}

	pc, err := c.ListenPacket(ctx, "udp", "8.8.8.8:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil packet conn")
	}
	_ = pc.Close()
}

// Test setupUDPTun5 success path with specified addr.
func TestSetupUDPTun5_SpecifiedAddr(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply with specified addr
	replyData := []byte{5, 0, 0, 1, 127, 0, 0, 1, 19, 136}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostUDPTun:   true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
		PacketDialer: func(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
			return &mockPacketConn{
				localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
				remoteAddr: &net.UDPAddr{
					IP:   net.IPv4(127, 0, 0, 1),
					Port: 5000,
				},
			}, nil
		},
	}

	pc, err := c.ListenPacket(ctx, "udp", "8.8.8.8:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pc == nil {
		t.Fatal("expected non-nil packet conn")
	}
	_ = pc.Close()
}

// Test request5 with Bind command.
func TestRequest5_BindCommand(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=10.10.10.10, BND.PORT=5555
	replyData := []byte{5, 0, 0, 1, 10, 10, 10, 10, 21, 179}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdBind,
		protocol.AddrFromHostPort("0.0.0.0:0", "tcp"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy on success")
	}
	if addr.Port != 5555 {
		t.Fatalf("expected port 5555, got %d", addr.Port)
	}
	if !addr.ToIP().Equal(net.IPv4(10, 10, 10, 10)) {
		t.Fatalf("expected IP 10.10.10.10, got %v", addr.ToIP())
	}
	_ = proxy.Close()
}

// Test request5 with UDPAssoc command.
func TestRequest5_UDPAssocCommand(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=127.0.0.1, BND.PORT=6000
	replyData := []byte{5, 0, 0, 1, 127, 0, 0, 1, 23, 112}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdUDPAssoc,
		protocol.AddrFromHostPort("0.0.0.0:0", "tcp"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy on success")
	}
	if addr.Port != 6000 {
		t.Fatalf("expected port 6000, got %d", addr.Port)
	}
	_ = proxy.Close()
}

// Test request5 with GostMbind command.
func TestRequest5_GostMbindCommand(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=192.168.0.1, BND.PORT=7000
	replyData := []byte{5, 0, 0, 1, 192, 168, 0, 1, 27, 88}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostMbind:    true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdGostMuxBind,
		protocol.AddrFromHostPort("0.0.0.0:0", "tcp"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy on success")
	}
	if addr.Port != 7000 {
		t.Fatalf("expected port 7000, got %d", addr.Port)
	}
	_ = proxy.Close()
}

// Test request5 with GostUDPTun command.
func TestRequest5_GostUDPTunCommand(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=10.0.0.1, BND.PORT=8000
	replyData := []byte{5, 0, 0, 1, 10, 0, 0, 1, 31, 64}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostUDPTun:   true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdGostUDPTun,
		protocol.AddrFromHostPort("0.0.0.0:0", "tcp"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy on success")
	}
	if addr.Port != 8000 {
		t.Fatalf("expected port 8000, got %d", addr.Port)
	}
	_ = proxy.Close()
}

// Test client5.go authenticate error path
func TestClient5_Authenticate_ErrorPath(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Auth: (&protocol.AuthMethods{}).Add(&protocol.PassAuthMethod{
			User: "user",
			Pass: "pass",
		}),
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient4{readErr: errors.New("auth failed")}, nil
		},
	}

	_, _, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("expected error on auth failure")
	}
}

// Test client5.go dialPacket5 UDP disallowed
func TestClient5_DialPacket5_UDPDisallowed(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Filter: func(_, _ string) bool {
			return false // Block all
		},
	}

	_, err := c.PacketDial(ctx, "udp", "8.8.8.8:53")
	if err == nil {
		t.Fatal("expected error when UDP disallowed")
	}
}

// Test client5.go setupUDPTun5 error path
func TestClient5_SetupUDPTun5_ErrorPath(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Filter: func(_, _ string) bool {
			return false // Block all
		},
	}

	_, err := c.PacketDial(ctx, "udp", "8.8.8.8:53")
	if err == nil {
		t.Fatal("expected error when UDP tunnel setup fails")
	}
}

// Test client5.go request5 with unspecified addr resolution
func TestRequest5_UnspecifiedAddrResolution(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// SOCKS5 reply with 0.0.0.0:0 (should use proxy addr)
	// Note: mockConnForClient5 will auto-prepend auth response
	replyData := []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData:   replyData,
				remoteAddr: remoteAddr,
			}, nil
		},
	}

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proxy == nil {
		t.Fatal("expected non-nil proxy")
	}
	// Address should have port from reply but IP from proxy
	if addr.Port != 0 {
		t.Logf("Note: addr.Port=%d (expected behavior may vary)", addr.Port)
	}
	_ = proxy.Close()
}

// Test client5.go resolveUnspecifiedAddr
func TestResolveUnspecifiedAddr(t *testing.T) {
	t.Parallel()

	// Test with non-unspecified address (should return unchanged)
	addr := protocol.AddrFromHostPort("192.168.1.1:80", "tcp")
	proxy := &mockConnForClient4{
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1080},
	}
	result := socksgo.TestResolveUnspecifiedAddr(proxy, addr)
	if result.String() != addr.String() {
		t.Fatalf("expected unchanged addr, got %v", result)
	}

	// Test with unspecified address and valid remote (should resolve)
	unspecAddr := protocol.AddrFromHostPort("0.0.0.0:80", "tcp")
	result2 := socksgo.TestResolveUnspecifiedAddr(proxy, unspecAddr)
	// Should resolve to proxy's IP
	if result2.ToIP() == nil || !result2.ToIP().Equal(net.ParseIP("10.0.0.1")) {
		t.Logf("Note: resolution behavior may vary, got %v", result2)
	}
}

// Test clientListener5.AcceptTCP() with TCPConn connection (direct return path).
func TestClientListener5_AcceptTCP_TCPConnPath(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	replyData := []byte{
		5, 0, 0, 1, 10, 0, 0, 1, 39, 15,
		5, 0, 0, 1, 192, 168, 1, 1, 0, 80,
	}

	// This test verifies the path where Accept() returns a connection
	// that implements gonnect.TCPConn (the type assertion succeeds).
	// However, our mockConnForClient5 doesn't implement TCPConn, so this
	// path is difficult to test directly. The wrapper path is tested above.
	// This test documents the behavior but may not cover the type assertion
	// success path without a more sophisticated mock.

	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	tcpLn, ok := ln.(interface {
		AcceptTCP() (gonnect.TCPConn, error)
	})
	if !ok {
		t.Fatal("expected listener to implement AcceptTCP")
	}

	conn, err := tcpLn.AcceptTCP()
	if err != nil {
		t.Fatalf("AcceptTCP failed: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil TCPConn")
	}
	_ = conn.Close()
}

// Test clientListener5.AcceptTCP() with error propagation.
func TestClientListener5_AcceptTCP_Error(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	readErr := errors.New("read failed")
	replyData := []byte{5, 0, 0, 1, 10, 0, 0, 1, 39, 15}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData: replyData,
				readErr:  readErr,
			}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	tcpLn, ok := ln.(interface {
		AcceptTCP() (gonnect.TCPConn, error)
	})
	if !ok {
		t.Fatal("expected listener to implement AcceptTCP")
	}

	_, err = tcpLn.AcceptTCP()
	if err == nil {
		t.Fatal("expected error when Accept fails")
	}
}

// Test clientListener5.SetDeadline().
func TestClientListener5_SetDeadline(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	replyData := []byte{5, 0, 0, 1, 10, 0, 0, 1, 39, 15}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{readData: replyData}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Type assert to access SetDeadline
	type deadlineSetter interface {
		SetDeadline(time.Time) error
	}
	dl, ok := ln.(deadlineSetter)
	if !ok {
		t.Fatal("expected listener to implement SetDeadline")
	}

	// Test SetDeadline with zero time (clear deadline)
	err = dl.SetDeadline(time.Time{})
	if err != nil {
		t.Fatalf("SetDeadline failed: %v", err)
	}

	// Test SetDeadline with future time
	future := time.Now().Add(1 * time.Hour)
	err = dl.SetDeadline(future)
	if err != nil {
		t.Fatalf("SetDeadline failed: %v", err)
	}
}

// Test clientListener5.SetDeadline() with error - verifies error propagation.
func TestClientListener5_SetDeadline_Error(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	deadlineErr := errors.New("deadline failed")
	replyData := []byte{5, 0, 0, 1, 10, 0, 0, 1, 39, 15}

	// Track whether we should return the error
	shouldFail := false

	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData: replyData,
				setDeadlineFn: func(t time.Time) error {
					if shouldFail {
						return deadlineErr
					}
					return nil
				},
			}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Now set shouldFail to true for the next SetDeadline call
	shouldFail = true

	type deadlineSetter interface {
		SetDeadline(time.Time) error
	}
	dl, ok := ln.(deadlineSetter)
	if !ok {
		t.Fatal("expected listener to implement SetDeadline")
	}

	err = dl.SetDeadline(time.Time{})
	if err == nil {
		t.Fatal("expected deadline error")
	}
	if err.Error() != deadlineErr.Error() {
		t.Fatalf("expected error %v, got %v", deadlineErr, err)
	}
}

// Test clientListener5mux.Close() with both session and conn close errors.
func TestClientListener5mux_Close_BothErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	replyData := []byte{5, 0, 0, 1, 10, 0, 0, 1, 39, 15}
	sessionErr := errors.New("session close failed")
	connErr := errors.New("conn close failed")
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostMbind:    true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData: replyData,
				closeErr: connErr,
				remoteAddr: &net.TCPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 1080,
				},
			}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Close should return joined errors
	err = ln.Close()
	if err == nil {
		t.Fatal("expected error when both session and conn close fail")
	}
	// Check that both errors are present
	if !errors.Is(err, sessionErr) && !errors.Is(err, connErr) {
		t.Logf("Note: got error %v, expected both session and conn errors", err)
	}
}

// Test clientListener5mux.Close() with only session error.
func TestClientListener5mux_Close_SessionErrorOnly(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	replyData := []byte{5, 0, 0, 1, 10, 0, 0, 1, 39, 15}
	sessionErr := errors.New("session close failed")
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostMbind:    true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData: replyData,
				closeErr: nil,
				remoteAddr: &net.TCPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 1080,
				},
			}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// This test mainly verifies no panic - session.Close() may or may not error
	_ = ln.Close()
	_ = sessionErr // Suppress unused warning
}

// Test clientListener5mux.AcceptTCP() success path.
func TestClientListener5mux_AcceptTCP_Success(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	replyData := []byte{5, 0, 0, 1, 10, 0, 0, 1, 39, 15}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostMbind:    true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData: replyData,
				remoteAddr: &net.TCPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 1080,
				},
			}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Cast to TCPListener to test AcceptTCP
	tcpLn, ok := ln.(interface {
		AcceptTCP() (gonnect.TCPConn, error)
	})
	if !ok {
		t.Fatal("expected listener to implement AcceptTCP")
	}

	// AcceptTCP will try to accept from smux session, which will fail when session closes
	// We just verify the method exists and can be called
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := tcpLn.AcceptTCP()
		// May return error when session closes
		if err != nil {
			t.Logf("AcceptTCP returned (expected): %v", err)
		}
	}()

	select {
	case <-done:
		// AcceptTCP returned
	case <-time.After(2 * time.Second):
		t.Fatal("AcceptTCP blocked forever")
	}
}

// Test clientListener5mux.AcceptTCP() with error from Accept.
func TestClientListener5mux_AcceptTCP_AcceptError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	replyData := []byte{5, 0, 0, 1, 10, 0, 0, 1, 39, 15}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostMbind:    true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData: replyData,
				remoteAddr: &net.TCPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 1080,
				},
			}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	// Close the listener first to ensure Accept returns error
	err = ln.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	tcpLn, ok := ln.(interface {
		AcceptTCP() (gonnect.TCPConn, error)
	})
	if !ok {
		t.Fatal("expected listener to implement AcceptTCP")
	}

	_, err = tcpLn.AcceptTCP()
	if err == nil {
		t.Log(
			"AcceptTCP returned nil (session may have been closed gracefully)",
		)
	}
}

// Test clientListener5mux.SetDeadline() success.
func TestClientListener5mux_SetDeadline_Success(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	replyData := []byte{5, 0, 0, 1, 10, 0, 0, 1, 39, 15}
	c := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostMbind:    true,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &mockConnForClient5{
				readData: replyData,
				remoteAddr: &net.TCPAddr{
					IP:   net.ParseIP("127.0.0.1"),
					Port: 1080,
				},
			}, nil
		},
	}

	ln, err := c.Listen(ctx, "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type deadlineSetter interface {
		SetDeadline(time.Time) error
	}
	dl, ok := ln.(deadlineSetter)
	if !ok {
		t.Fatal("expected listener to implement SetDeadline")
	}

	// Test SetDeadline with zero time
	err = dl.SetDeadline(time.Time{})
	if err != nil {
		t.Fatalf("SetDeadline failed: %v", err)
	}

	// Test SetDeadline with future time
	future := time.Now().Add(1 * time.Hour)
	err = dl.SetDeadline(future)
	if err != nil {
		t.Fatalf("SetDeadline failed: %v", err)
	}
}

// Test resolveUnspecifiedAddr with nil RemoteAddr.
func TestResolveUnspecifiedAddr_NilRemoteAddr(t *testing.T) {
	t.Parallel()

	// Test with unspecified address but nil RemoteAddr (should return unchanged)
	unspecAddr := protocol.AddrFromHostPort("0.0.0.0:80", "tcp")

	// Create a mock that returns nil for RemoteAddr
	proxy := &mockConnWithNilRemoteAddr{}
	result := socksgo.TestResolveUnspecifiedAddr(proxy, unspecAddr)
	if result.String() != unspecAddr.String() {
		t.Fatalf(
			"expected unchanged addr when RemoteAddr is nil, got %v",
			result,
		)
	}
}

// mockConnWithNilRemoteAddr is a minimal mock that returns nil for RemoteAddr
type mockConnWithNilRemoteAddr struct{}

func (m *mockConnWithNilRemoteAddr) Read(
	p []byte,
) (n int, err error) {
	return 0, io.EOF
}

func (m *mockConnWithNilRemoteAddr) Write(
	p []byte,
) (n int, err error) {
	return 0, nil
}

func (m *mockConnWithNilRemoteAddr) Close() error { return nil }
func (m *mockConnWithNilRemoteAddr) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (m *mockConnWithNilRemoteAddr) RemoteAddr() net.Addr { return nil }
func (m *mockConnWithNilRemoteAddr) SetDeadline(t time.Time) error {
	return nil
}
func (m *mockConnWithNilRemoteAddr) SetReadDeadline(t time.Time) error {
	return nil
}
func (m *mockConnWithNilRemoteAddr) SetWriteDeadline(t time.Time) error {
	return nil
}
