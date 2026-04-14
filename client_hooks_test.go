//go:build testhooks

package socksgo

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo/protocol"
)

// Test lookupIPWithHook directly
func TestLookupIPWithHook_NilIP(t *testing.T) {
	// Note: Not using t.Parallel() because this test modifies global hook state

	// Set up hook to return FQDN address (which has ToIP() == nil)
	oldHook := testLookupIPHook
	testLookupIPHook = func(addr protocol.Addr) protocol.Addr {
		// Return FQDN address to trigger ip == nil path
		return protocol.AddrFromFQDN("example.com", 80, "tcp")
	}
	defer func() { testLookupIPHook = oldHook }()

	client := &Client{}

	_, err := client.lookupIPWithHook(nil, "ip", "example.com", protocol.Addr{})
	if err != ErrWrongAddrInLookupResponse {
		t.Fatalf("Expected ErrWrongAddrInLookupResponse, got %T: %v", err, err)
	}
}

// Test lookupIPWithHook with valid IP
func TestLookupIPWithHook_ValidIP(t *testing.T) {
	// Note: Not using t.Parallel() because this test modifies global hook state

	// Reset hook to default (identity)
	oldHook := testLookupIPHook
	testLookupIPHook = func(addr protocol.Addr) protocol.Addr {
		return addr
	}
	defer func() { testLookupIPHook = oldHook }()

	client := &Client{}
	ipAddr := protocol.AddrFromIP(net.ParseIP("127.0.0.1"), 80, "tcp")

	ips, err := client.lookupIPWithHook(nil, "ip", "127.0.0.1", ipAddr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("Expected 1 IP, got %d", len(ips))
	}
	if !ips[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("Expected 127.0.0.1, got %v", ips[0])
	}
}

// Test lookupAddrWithHook directly
func TestLookupAddrWithHook(t *testing.T) {
	// Note: Not using t.Parallel() because this test modifies global hook state

	// Set up hook to modify returned address
	oldHook := testLookupAddrHook
	testLookupAddrHook = func(addr protocol.Addr) protocol.Addr {
		// Return modified FQDN
		return protocol.AddrFromFQDN("modified.example.com", 0, "tcp")
	}
	defer func() { testLookupAddrHook = oldHook }()

	client := &Client{}

	addrs, err := client.lookupAddrWithHook(nil, protocol.Addr{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	if addrs[0] != "modified.example.com" {
		t.Errorf("Expected modified.example.com, got %s", addrs[0])
	}
}

// mockConnForHooks implements net.Conn for testing listenSmuxWithHook
type mockConnForHooks struct {
	closed   bool
	readData []byte
	readOff  int
}

func (m *mockConnForHooks) Read(p []byte) (n int, err error) {
	if m.readOff >= len(m.readData) {
		return 0, errors.New("EOF")
	}
	n = copy(p, m.readData[m.readOff:])
	m.readOff += n
	return n, nil
}

func (m *mockConnForHooks) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (m *mockConnForHooks) Close() error {
	m.closed = true
	return nil
}

func (m *mockConnForHooks) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (m *mockConnForHooks) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}
}

func (m *mockConnForHooks) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConnForHooks) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConnForHooks) SetWriteDeadline(t time.Time) error {
	return nil
}

// Test listenSmuxWithHook with simulated error
func TestListenSmuxWithHook_Error(t *testing.T) {
	// Note: Not using t.Parallel() because this test modifies global hook state

	closeCalled := false

	// Set up hook to simulate error before smux.Server
	oldSmuxHook := testListenSmuxHook
	oldCloseHook := testListenCloseHook

	testListenSmuxHook = func() error {
		return errors.New("simulated smux error")
	}
	testListenCloseHook = func(conn net.Conn) {
		closeCalled = true
		_ = conn.Close()
	}
	defer func() {
		testListenSmuxHook = oldSmuxHook
		testListenCloseHook = oldCloseHook
	}()

	conn := &mockConnForHooks{}
	client := &Client{}

	addr := protocol.AddrFromIP(net.ParseIP("127.0.0.1"), 0, "tcp")
	_, err := client.listenSmuxWithHook(conn, addr)
	if err == nil {
		t.Fatal("Expected error from smux hook, got nil")
	}
	if !closeCalled {
		t.Error("Expected conn.Close() to be called on smux error")
	}
	if !conn.closed {
		t.Error("Expected connection to be closed")
	}
}

// Test listenSmuxWithHook with nil smux config (will fail at smux.Server)
func TestListenSmuxWithHook_SmuxServerError(t *testing.T) {
	// Note: Not using t.Parallel() because this test modifies global hook state

	// Reset smux hook to default
	oldSmuxHook := testListenSmuxHook
	oldCloseHook := testListenCloseHook

	testListenSmuxHook = func() error {
		return nil
	}
	testListenCloseHook = func(conn net.Conn) {
		_ = conn.Close()
	}
	defer func() {
		testListenSmuxHook = oldSmuxHook
		testListenCloseHook = oldCloseHook
	}()

	// Note: Testing actual smux.Server failure requires a connection that
	// smux will reject. For now, we test that the hook mechanism works
	// and that close is called when the hook returns an error.
	// The TestListenSmuxWithHook_Error test covers the error path.
	t.Skip("smux.Server integration test skipped - requires complex mock")
}

// Test hooks reset
func TestHooksReset(t *testing.T) {
	// Note: Not using t.Parallel() because this test modifies global hook state

	// Set hooks to non-default values
	testLookupIPHook = func(addr protocol.Addr) protocol.Addr {
		return protocol.AddrFromFQDN("test.com", 80, "tcp")
	}
	testLookupAddrHook = func(addr protocol.Addr) protocol.Addr {
		return protocol.AddrFromFQDN("test.com", 80, "tcp")
	}
	testListenSmuxHook = func() error {
		return errors.New("test error")
	}
	testListenCloseHook = func(conn net.Conn) {
		// no-op
	}

	// Reset hooks
	resetTestHooks()

	// Verify hooks are reset to defaults
	addr := protocol.AddrFromFQDN("example.com", 80, "tcp")
	result := testLookupIPHook(addr)
	if result.ToFQDN() != "example.com" {
		t.Error("LookupIP hook should be reset to identity function")
	}

	result = testLookupAddrHook(addr)
	if result.ToFQDN() != "example.com" {
		t.Error("LookupAddr hook should be reset to identity function")
	}

	if testListenSmuxHook() != nil {
		t.Error("ListenSmux hook should be reset to return nil")
	}
}

// TestClient_Listen_UnknownVersion_WithHook tests the unknown version path
// in Listen using the testRequestHook to bypass the version check in request().
func TestClient_Listen_UnknownVersion_WithHook(t *testing.T) {
	// Note: Not using t.Parallel() because this test modifies global hook state

	// Save and restore hook
	oldHook := testRequestHook
	defer func() { testRequestHook = oldHook }()

	// Create a mock connection with BIND reply data
	// SOCKS5 BIND reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=127.0.0.1, BND.PORT=0
	mockConn := &mockConnForHooks{
		readData: []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0},
	}

	// Set up hook to return mock connection for Bind command
	testRequestHook = func(
		ctx context.Context,
		cmd protocol.Cmd,
		address protocol.Addr,
	) (net.Conn, protocol.Addr, bool) {
		if cmd == protocol.CmdBind {
			return mockConn, protocol.AddrFromHostPort(
				"127.0.0.1:0",
				"tcp",
			), true
		}
		return nil, protocol.Addr{}, false
	}

	// Create client with unknown SOCKS version
	// Use PassAllFilter to force proxy path (filter returns false = use proxy)
	client := &Client{
		SocksVersion: "99",
		ProxyAddr:    "127.0.0.1:1080",
		Filter:       gonnect.FalseFilter,
	}

	ln, err := client.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		_ = ln.Close()
		t.Fatal("Expected error for unknown SOCKS version in Listen, got nil")
	}
	if ln != nil {
		t.Fatal("Expected nil listener on unknown version error")
	}
	_, ok := err.(UnknownSocksVersionError)
	if !ok {
		t.Errorf("Expected UnknownSocksVersionError, got %T: %v", err, err)
	}
	// Verify connection was closed via hook
	if !mockConn.closed {
		t.Error("Expected connection to be closed on unknown version error")
	}
}

// Test hooks setter/getter functions
// NOTE: Not parallel - modifies global test hooks state
func TestTestHooks_SetAndGet(t *testing.T) {
	// Test SetTestLookupIPHook / GetTestLookupIPHook
	hook := func(addr protocol.Addr) protocol.Addr {
		return addr
	}

	oldHook := GetTestLookupIPHook()
	SetTestLookupIPHook(hook)
	if GetTestLookupIPHook() == nil {
		t.Fatal("GetTestLookupIPHook should return set hook")
	}

	// Restore
	SetTestLookupIPHook(oldHook)

	// Test SetTestLookupAddrHook / GetTestLookupAddrHook
	addrHook := func(addr protocol.Addr) protocol.Addr {
		return addr
	}
	oldAddrHook := GetTestLookupAddrHook()
	SetTestLookupAddrHook(addrHook)
	if GetTestLookupAddrHook() == nil {
		t.Fatal("GetTestLookupAddrHook should return set hook")
	}
	SetTestLookupAddrHook(oldAddrHook)

	// Test SetTestListenSmuxHook / GetTestListenSmuxHook
	smuxHook := func() error { return nil }
	oldSmuxHook := GetTestListenSmuxHook()
	SetTestListenSmuxHook(smuxHook)
	if GetTestListenSmuxHook() == nil {
		t.Fatal("GetTestListenSmuxHook should return set hook")
	}
	SetTestListenSmuxHook(oldSmuxHook)

	// Test SetTestListenCloseHook / GetTestListenCloseHook
	closeHook := func(conn net.Conn) { _ = conn.Close() }
	oldCloseHook := GetTestListenCloseHook()
	SetTestListenCloseHook(closeHook)
	if GetTestListenCloseHook() == nil {
		t.Fatal("GetTestListenCloseHook should return set hook")
	}
	SetTestListenCloseHook(oldCloseHook)

	// Test SetTestRequestHook / GetTestRequestHook
	reqHook := func(ctx context.Context, cmd protocol.Cmd, addr protocol.Addr) (net.Conn, protocol.Addr, bool) {
		return nil, protocol.Addr{}, false
	}
	oldReqHook := GetTestRequestHook()
	SetTestRequestHook(reqHook)
	if GetTestRequestHook() == nil {
		t.Fatal("GetTestRequestHook should return set hook")
	}
	SetTestRequestHook(oldReqHook)
}

// Test TestAddrFromFQDN and TestAddrFromIP helpers
func TestTestAddrHelpers(t *testing.T) {
	t.Parallel()

	// Test TestAddrFromFQDN
	addr := TestAddrFromFQDN("example.com", 80, "tcp")
	if addr.Type != protocol.FQDNAddr {
		t.Fatalf("expected FQDNAddr, got %d", addr.Type)
	}
	if addr.ToFQDN() != "example.com" {
		t.Fatalf("expected example.com, got %s", addr.ToFQDN())
	}
	if addr.Port != 80 {
		t.Fatalf("expected port 80, got %d", addr.Port)
	}

	// Test TestAddrFromIP
	ip := net.ParseIP("192.168.1.1")
	addr2 := TestAddrFromIP(ip, 443, "tcp")
	if addr2.Type != protocol.IP4Addr && addr2.Type != protocol.IP6Addr {
		t.Fatalf("expected IP type, got %d", addr2.Type)
	}
	if !addr2.ToIP().Equal(ip) {
		t.Fatalf("expected %v, got %v", ip, addr2.ToIP())
	}
	if addr2.Port != 443 {
		t.Fatalf("expected port 443, got %d", addr2.Port)
	}
}

// Test ResetTestHooks
// NOTE: Not parallel - modifies global test hooks state
func TestResetTestHooks(t *testing.T) {
	// Set some hooks
	SetTestLookupIPHook(func(addr protocol.Addr) protocol.Addr {
		return protocol.Addr{}
	})

	// Reset them
	ResetTestHooks()

	// Verify they're reset (should not panic or error)
	hook := GetTestLookupIPHook()
	if hook == nil {
		t.Fatal("hook should not be nil after reset")
	}

	// Test the reset hook works
	addr := TestAddrFromFQDN("test.com", 80, "tcp")
	result := hook(addr)
	if result.ToFQDN() != "test.com" {
		t.Fatalf(
			"expected default hook to return addr unchanged, got %s",
			result.ToFQDN(),
		)
	}
}
