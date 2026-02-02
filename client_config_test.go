package socksgo_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	socksgo "github.com/asciimoth/socksgo"
)

// A small helper to dial a TCP listener for tests.
func mustListenTCP(t *testing.T) (net.Listener, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0") //nolint
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	return l, l.Addr().String()
}

// mockConn implements net.Conn and can be configured to fail SetDeadline.
type mockConn struct {
	closed      bool
	deadlineErr bool
}

func (m *mockConn) Read([]byte) (int, error)  { return 0, nil }
func (m *mockConn) Write([]byte) (int, error) { return 0, nil }
func (m *mockConn) Close() error              { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr       { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr      { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error {
	if m.deadlineErr {
		return &net.OpError{}
	}
	return nil
}

func (m *mockConn) SetReadDeadline(
	t time.Time,
) error {
	return m.SetDeadline(t)
}

func (m *mockConn) SetWriteDeadline(
	t time.Time,
) error {
	return m.SetDeadline(t)
}

func TestWebSocketConfigMethodsNilAndNonNil(t *testing.T) {
	// non-nil values are returned
	jar, _ := cookiejar.New(nil)
	cfg := &socksgo.WebSocketConfig{
		ReadBufferSize:    12345,
		Subprotocols:      []string{"a", "b"},
		EnableCompression: true,
		Jar:               jar,
	}
	if got := cfg.Jar; got != jar {
		t.Fatalf("jar() expected %v got %v", jar, got)
	}
	if got := cfg.ReadBufferSize; got != 12345 {
		t.Fatalf("readBufferSize expected 12345 got %d", got)
	}
	if !equalStringSlices(cfg.Subprotocols, []string{"a", "b"}) {
		t.Fatalf("subprotocols mismatch")
	}
	if !cfg.EnableCompression {
		t.Fatalf("enableCompression expected true")
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestClient_Version_GetNet_GetAddr_IsTLS_IsUDPAllowed(t *testing.T) {
	var c *socksgo.Client

	// GetNet on nil receiver
	if got := c.GetNet(); got != "tcp" {
		t.Fatalf("GetNet on nil expected tcp got %s", got)
	}

	c = &socksgo.Client{}
	// Version default
	if v := c.Version(); v != "5" {
		t.Fatalf("default Version expected 5 got %s", v)
	}
	c.SocksVersion = "4"
	if v := c.Version(); v != "4" {
		t.Fatalf("Version expected 4 got %s", v)
	}

	// GetNet with empty and non-empty proxy net
	c = &socksgo.Client{}
	if got := c.GetNet(); got != "tcp" {
		t.Fatalf("GetNet default expected tcp got %s", got)
	}
	c.ProxyNet = "udp"
	if got := c.GetNet(); got != "udp" {
		t.Fatalf("GetNet expected udp got %s", got)
	}

	// GetAddr with missing port and explicit port
	c = &socksgo.Client{ProxyAddr: "localhost"}
	if got := c.GetAddr(); got != "localhost:1080" {
		t.Fatalf("GetAddr expected localhost:1080 got %s", got)
	}
	c.ProxyAddr = "1.2.3.4:999"
	if got := c.GetAddr(); got != "1.2.3.4:999" {
		t.Fatalf("GetAddr expected 1.2.3.4:999 got %s", got)
	}

	// IsTLS: TLS flag and WebSocketURL wss
	c = &socksgo.Client{TLS: true}
	if !c.IsTLS() {
		t.Fatalf("IsTLS expected true when TLS flag set")
	}
	c = &socksgo.Client{WebSocketURL: "wss://example"}
	if !c.IsTLS() {
		t.Fatalf("IsTLS expected true when WebSocketURL starts with wss")
	}

	// IsUDPAllowed: !IsTLS || InsecureUDP
	c = &socksgo.Client{TLS: false, InsecureUDP: false}
	if !c.IsUDPAllowed() {
		t.Fatalf("IsUDPAllowed expected true when not TLS")
	}
	c = &socksgo.Client{TLS: true, InsecureUDP: false}
	if c.IsUDPAllowed() {
		t.Fatalf("IsUDPAllowed expected false when TLS and InsecureUDP false")
	}
	c = &socksgo.Client{TLS: true, InsecureUDP: true}
	if !c.IsUDPAllowed() {
		t.Fatalf("IsUDPAllowed expected true when TLS and InsecureUDP true")
	}
}

func TestGetListenerAndDialerAndPacketListenerAndPacketDialer(t *testing.T) {
	ctx := context.Background()

	c := &socksgo.Client{}

	// GetListener default: use net.ListenConfig.Listen
	listenerFunc := c.GetListener()
	// make sure listener function can bind to free port (we only check it returns a listener)
	ln, err := listenerFunc(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenerFunc failed: %v", err)
	}
	ln.Close() //nolint

	// GetDialer default: dial the listener
	l2, addr2 := mustListenTCP(t)
	defer l2.Close() //nolint
	dialer := c.GetDialer()
	conn, err := dialer(ctx, "tcp", addr2)
	if err != nil {
		t.Fatalf("GetDialer dial failed: %v", err)
	}
	conn.Close() //nolint

	// GetPacketListener default: create UDP listener on free port
	pl := c.GetPacketListener()
	pc, err := pl(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("GetPacketListener failed: %v", err)
	}
	_ = pc.Close()

	// GetPacketDialer default: create a UDP server and dial to it
	// Ensure c.Dialer == nil so default PacketDialer is returned
	c = &socksgo.Client{Dialer: nil}
	pd := c.GetPacketDialer()
	udpSrv, err := net.ListenUDP(
		"udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
	)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer udpSrv.Close() //nolint

	raddr := udpSrv.LocalAddr().String()
	pconn, err := pd(ctx, "udp", raddr)
	if err != nil {
		t.Fatalf("PacketDialer dial failed: %v", err)
	}
	_ = pconn.Close()
}

func TestGetResolver_GetTLSConfig_GetHandshakeTimeout_GetWsDialer(
	t *testing.T,
) {
	// GetResolver default
	c := &socksgo.Client{}
	if r := c.GetResolver(); r != net.DefaultResolver {
		t.Fatalf("GetResolver expected net.DefaultResolver")
	}

	// GetTLSConfig: when not TLS -> nil
	c = &socksgo.Client{TLS: false, WebSocketURL: ""}
	if cfg := c.GetTLSConfig(); cfg != nil {
		t.Fatalf("GetTLSConfig expected nil when not TLS")
	}

	// When TLS true and ProxyAddr contains host:port, ServerName should be host
	c = &socksgo.Client{TLS: true, ProxyAddr: "example.test:1337"}
	cfg := c.GetTLSConfig()
	if cfg == nil {
		t.Fatalf("GetTLSConfig returned nil when TLS true")
	}
	if cfg.ServerName != "example.test" {
		t.Fatalf(
			"GetTLSConfig ServerName expected example.test got %q",
			cfg.ServerName,
		)
	}

	// When TLSConfig provided copy/clone and preserve ServerName
	orig := &tls.Config{ServerName: "predefined"} //nolint
	c = &socksgo.Client{TLS: true, ProxyAddr: "host:1", TLSConfig: orig}
	cfg2 := c.GetTLSConfig()
	if cfg2 == nil {
		t.Fatalf(
			"GetTLSConfig returned nil when TLS true and TLSConfig provided",
		)
	}
	if cfg2.ServerName != "predefined" {
		t.Fatalf(
			"GetTLSConfig should preserve provided ServerName, got %q",
			cfg2.ServerName,
		)
	}
	// ensure it's a clone (modifying cfg2 doesn't change orig)
	cfg2.ServerName = "changed"
	if orig.ServerName == "changed" {
		t.Fatalf("GetTLSConfig returned the same pointer instead of a clone")
	}

	// GetHandshakeTimeout: nil receiver and set value
	var nilC *socksgo.Client
	if timeout := nilC.GetHandshakeTimeout(); timeout != 0 {
		t.Fatalf("GetHandshakeTimeout on nil expected 0 got %v", timeout)
	}
	c = &socksgo.Client{HandshakeTimeout: 5 * time.Second}
	if tmo := c.GetHandshakeTimeout(); tmo != 5*time.Second {
		t.Fatalf("GetHandshakeTimeout expected 5s got %v", tmo)
	}

	// GetWsDialer: when WebSocketURL empty -> nil
	c = &socksgo.Client{}
	if d := c.GetWsDialer(); d != nil {
		t.Fatalf("GetWsDialer expected nil when WebSocketURL empty")
	}

	// When WebSocketURL set, ensure Dialer fields come from config
	jar, _ := cookiejar.New(nil)
	wsCfg := &socksgo.WebSocketConfig{
		ReadBufferSize:    999,
		Subprotocols:      []string{"p1"},
		EnableCompression: true,
		Jar:               jar,
		RequestHeader:     http.Header{"X-Test": {"v"}},
	}
	c = &socksgo.Client{
		WebSocketURL:     "ws://example",
		WebSocketConfig:  wsCfg,
		HandshakeTimeout: 2 * time.Second,
		TLS:              true,
		ProxyAddr:        "example:1080",
	}
	wsDialer := c.GetWsDialer()
	if wsDialer == nil {
		t.Fatalf("GetWsDialer returned nil unexpectedly")
	}
	if wsDialer.NetDialContext == nil {
		t.Fatalf("GetWsDialer.NetDialContext expected non-nil")
	}
	if wsDialer.TLSClientConfig == nil {
		t.Fatalf("GetWsDialer.TLSClientConfig expected non-nil")
	}
	if wsDialer.HandshakeTimeout != 2*time.Second {
		t.Fatalf(
			"GetWsDialer.HandshakeTimeout expected 2s got %v",
			wsDialer.HandshakeTimeout,
		)
	}
	if wsDialer.ReadBufferSize != 999 {
		t.Fatalf(
			"GetWsDialer.ReadBufferSize expected 999 got %d",
			wsDialer.ReadBufferSize,
		)
	}
	if !equalStringSlices(wsDialer.Subprotocols, []string{"p1"}) {
		t.Fatalf("GetWsDialer.Subprotocols mismatch")
	}
	if wsDialer.EnableCompression != true {
		t.Fatalf("GetWsDialer.EnableCompression expected true")
	}
	if wsDialer.Jar != jar {
		t.Fatalf("GetWsDialer.Jar expected provided jar")
	}
}

func TestConnect_SuccessAndDeadlineError(t *testing.T) {
	ctx := context.Background()

	// Success: use net.Pipe via Dialer
	c := &socksgo.Client{
		ProxyAddr: "host:1",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			a, _ := net.Pipe()
			return a, nil
		},
		HandshakeTimeout: 50 * time.Millisecond,
	}
	conn, err := c.Connect(ctx)
	if err != nil {
		t.Fatalf("Connect failed unexpectedly: %v", err)
	}
	_ = conn.Close()

	// Failure: SetDeadline returns error; ensure conn closed and error returned
	m := &mockConn{deadlineErr: true}
	c = &socksgo.Client{
		ProxyAddr: "host:1",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return m, nil
		},
		HandshakeTimeout: 1 * time.Second,
	}
	_, err = c.Connect(ctx)
	if err == nil {
		t.Fatalf("Connect expected to fail due to SetDeadline error")
	}
	if !m.closed {
		t.Fatalf("Connect should close connection on SetDeadline error")
	}
}

func TestCheckNetworkSupport(t *testing.T) {
	// Unknown network should return WrongNetworkError with SocksVersion default "5"
	c := &socksgo.Client{}
	err := c.CheckNetworkSupport("unknown_network_hopefully_not_present")
	if err == nil {
		t.Fatalf("CheckNetworkSupport expected error for unknown network")
	}
	if werr, ok := err.(socksgo.WrongNetworkError); ok { //nolint
		if werr.SocksVersion != "5" {
			t.Fatalf(
				"WrongNetworkError.SocksVersion expected 5 got %q",
				werr.SocksVersion,
			)
		}
	} else {
		t.Fatalf("error is not WrongNetworkError: %T", err)
	}

	// For socks4, non-tcp networks should return WrongNetworkError
	c = &socksgo.Client{SocksVersion: "4"}
	err = c.CheckNetworkSupport("udp")
	if err == nil {
		t.Fatalf("CheckNetworkSupport expected error for socks4 + udp")
	}
	if werr, ok := err.(socksgo.WrongNetworkError); ok { //nolint
		if werr.SocksVersion != "4" || werr.Network != "udp" {
			t.Fatalf("WrongNetworkError fields unexpected: %+v", werr)
		}
	} else {
		t.Fatalf("error is not WrongNetworkError: %T", err)
	}

	// A supported network (tcp) should return nil
	c = &socksgo.Client{}
	if err := c.CheckNetworkSupport("tcp"); err != nil {
		t.Fatalf("CheckNetworkSupport tcp expected nil got %v", err)
	}
}

// Test DoFilter: explicit Filter and default LoopbackFilter behavior.
func TestDoFilter_CustomAndDefault(t *testing.T) {
	// Custom Filter
	c := &socksgo.Client{
		ProxyAddr: "example.com",
		Filter: func(_, _ string) bool {
			// return false for everything so proxy would be used
			return false
		},
	}
	if got := c.DoFilter("tcp", "example:80"); got != false {
		t.Fatalf("DoFilter with custom filter expected false, got %v", got)
	}

	// Default (nil) Filter - compare against LoopbackFilter directly so test stays stable
	c = &socksgo.Client{}
	expected := socksgo.LoopbackFilter("tcp", "127.0.0.1:123")
	if got := c.DoFilter("tcp", "127.0.0.1:123"); got != expected {
		t.Fatalf("DoFilter(default) expected %v, got %v", expected, got)
	}
}

// Test GetListener when DirectListener is provided.
func TestGetListener_DirectListener(t *testing.T) {
	ctx := context.Background()
	called := false
	c := &socksgo.Client{
		DirectListener: func(ctx context.Context, network, address string) (net.Listener, error) {
			called = true
			// Let system choose port
			return net.Listen(network, address) //nolint
		},
	}

	lnFunc := c.GetListener()
	ln, err := lnFunc(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("DirectListener returned error: %v", err)
	}
	_ = ln.Close()
	if !called {
		t.Fatalf("DirectListener was not invoked")
	}
}

// Test GetPacketListener when DirectPacketListener is provided.
func TestGetPacketListener_DirectPacketListener(t *testing.T) {
	ctx := context.Background()
	called := false
	c := &socksgo.Client{
		DirectPacketListener: func(ctx context.Context, network, laddr string) (socksgo.PacketConn, error) {
			called = true
			udpAddr, err := net.ResolveUDPAddr(network, laddr)
			if err != nil {
				return nil, err
			}
			return net.ListenUDP(network, udpAddr)
		},
	}

	pl := c.GetPacketListener()
	pc, err := pl(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("DirectPacketListener returned error: %v", err)
	}
	_ = pc.Close()
	if !called {
		t.Fatalf("DirectPacketListener was not invoked")
	}
}

// Test GetPacketDialer when Dialer != nil so client returns c.PacketDialer.
func TestGetPacketDialer_WhenDialerNonNil_UsesPacketDialer(t *testing.T) {
	ctx := context.Background()

	// start a UDP server to dial to
	udpSrv, err := net.ListenUDP(
		"udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
	)
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	defer udpSrv.Close() //nolint

	called := false
	c := &socksgo.Client{
		// non-nil Dialer ensures GetPacketDialer returns PacketDialer field
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, nil //nolint
		},
		PacketDialer: func(ctx context.Context, network, raddr string) (socksgo.PacketConn, error) {
			called = true
			ra, err := net.ResolveUDPAddr(network, raddr)
			if err != nil {
				return nil, err
			}
			return net.DialUDP(network, nil, ra)
		},
	}

	pd := c.GetPacketDialer()
	pconn, err := pd(ctx, "udp", udpSrv.LocalAddr().String())
	if err != nil {
		t.Fatalf("PacketDialer returned error: %v", err)
	}
	_ = pconn.Close()
	if !called {
		t.Fatalf("PacketDialer was not invoked")
	}
}

// fakeResolver implements socksgo.Resolver for tests.
type fakeResolver struct{}

func (f fakeResolver) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
	return []net.IP{net.ParseIP("1.2.3.4")}, nil
}

func (f fakeResolver) LookupAddr(
	ctx context.Context,
	address string,
) ([]string, error) {
	return []string{"host.test"}, nil
}

// Test GetResolver when user provided a Resolver instance.
func TestGetResolver_CustomResolver(t *testing.T) {
	c := &socksgo.Client{
		Resolver: fakeResolver{},
	}
	r := c.GetResolver()
	ips, err := r.LookupIP(context.Background(), "ip", "example")
	if err != nil {
		t.Fatalf("LookupIP failed: %v", err)
	}
	if len(ips) == 0 || !ips[0].Equal(net.ParseIP("1.2.3.4")) {
		t.Fatalf("LookupIP returned unexpected IPs: %v", ips)
	}
	names, err := r.LookupAddr(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("LookupAddr failed: %v", err)
	}
	if len(names) == 0 || names[0] != "host.test" {
		t.Fatalf("LookupAddr returned unexpected names: %v", names)
	}
}

// Test Connect when Dialer fails (non-websocket path).
func TestConnect_DialerFails(t *testing.T) {
	ctx := context.Background()
	c := &socksgo.Client{
		ProxyAddr: "host:1",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("dial failed intentionally")
		},
	}
	_, err := c.Connect(ctx)
	if err == nil {
		t.Fatalf("Connect expected error when Dialer fails")
	}
}

// Test Connect when WebSocketURL set, WebSocketConfig is set, and underlying dial fails.
// This exercises connectWebSocket path with c.WebSocketConfig != nil and DialContext failing (via NetDialContext).
func TestConnect_WebSocket_DialContextFails(t *testing.T) {
	ctx := context.Background()
	c := &socksgo.Client{
		// any non-empty WebSocketURL triggers connectWebSocket in Connect
		WebSocketURL: "ws://example.invalid",
		WebSocketConfig: &socksgo.WebSocketConfig{
			RequestHeader: http.Header{"X-My-Test": {"v"}},
		},
		// Make GetDialer() (via c.Dialer) return error on dial; websocket.Dialer will call NetDialContext and fail.
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, fmt.Errorf("net dial failed intentionally")
		},
	}
	_, err := c.Connect(ctx)
	if err == nil {
		t.Fatalf("Connect expected error when websocket DialContext fails")
	}
}
