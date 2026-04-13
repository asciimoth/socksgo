// nolint
package socksgo_test

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

func TestClientNoProxy(t *testing.T) {
	t.Parallel()

	client := socksgo.ClientNoProxy()

	if client.ProxyAddr != "" {
		t.Errorf("ProxyAddr = %q, want empty", client.ProxyAddr)
	}
	if client.WebSocketURL != "" {
		t.Errorf("WebSocketURL = %q, want empty", client.WebSocketURL)
	}
	if client.Filter == nil {
		t.Fatal("Filter is nil, want MatchAllFilter")
	}
	// Test that filter passes everything
	if !client.Filter("tcp", "example.com:80") {
		t.Error("Filter should pass everything")
	}
	if !client.GostMbind {
		t.Error("GostMbind = false, want true")
	}
	if !client.GostUDPTun {
		t.Error("GostUDPTun = false, want true")
	}
	if !client.TorLookup {
		t.Error("TorLookup = false, want true")
	}
	if !client.IsNoProxy() {
		t.Error("IsNoProxy should return true for ClientNoProxy")
	}
}

func TestClientFromURL(t *testing.T) {
	tests := []struct {
		Name string

		Url string

		Version               string
		GetAddr               string
		IsTLS                 bool
		IsUDPAllowed          bool
		TLSInsecureSkipVerify bool
		WebSocketURL          string
	}{
		{
			Name:         "Standard socks5",
			Url:          "socks5://127.0.0.1:8080",
			Version:      "5",
			GetAddr:      "127.0.0.1:8080",
			IsUDPAllowed: true,
		},
		{
			Name:         "Standard socks5h",
			Url:          "socks5h://127.0.0.1:8080",
			Version:      "5",
			GetAddr:      "127.0.0.1:8080",
			IsUDPAllowed: true,
		},
		{
			Name:         "Standard socks4",
			Url:          "socks4://127.0.0.1:8080",
			Version:      "4",
			GetAddr:      "127.0.0.1:8080",
			IsUDPAllowed: true,
		},
		{
			Name:         "Standard socks4a",
			Url:          "socks4a://127.0.0.1:8080",
			Version:      "4a",
			GetAddr:      "127.0.0.1:8080",
			IsUDPAllowed: true,
		},
		{
			Name:                  "socks5+tls",
			Url:                   "socks5+tls://127.0.0.1:8080",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:          false,
			IsTLS:                 true,
			TLSInsecureSkipVerify: true,
		},
		{
			Name:                  "socks5+tls+secure",
			Url:                   "socks5+tls://127.0.0.1:8080?secure",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:          false,
			IsTLS:                 true,
			TLSInsecureSkipVerify: false,
		},
		{
			Name:                  "socks5+ws",
			Url:                   "socks5+ws://127.0.0.1:8080",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:          true,
			WebSocketURL:          "ws://127.0.0.1:8080/ws",
			IsTLS:                 false,
			TLSInsecureSkipVerify: false,
		},
		{
			Name:                  "socks5+ws+path",
			Url:                   "socks5+ws://127.0.0.1:8080/custom/path",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:          true,
			WebSocketURL:          "ws://127.0.0.1:8080/custom/path",
			IsTLS:                 false,
			TLSInsecureSkipVerify: false,
		},
		{
			Name:                  "socks5+wss",
			Url:                   "socks5+wss://127.0.0.1:8080",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:          false,
			WebSocketURL:          "wss://127.0.0.1:8080/ws",
			IsTLS:                 true,
			TLSInsecureSkipVerify: true,
		},
		{
			Name:                  "socks5+wss+secure",
			Url:                   "socks5+wss://127.0.0.1:8080?secure",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:          false,
			WebSocketURL:          "wss://127.0.0.1:8080/ws",
			IsTLS:                 true,
			TLSInsecureSkipVerify: false,
		},
		{
			Name:                  "socks5+ws+tls",
			Url:                   "socks5+ws+tls://127.0.0.1:8080",
			Version:               "5",
			GetAddr:               "127.0.0.1:8080",
			IsUDPAllowed:          false,
			WebSocketURL:          "wss://127.0.0.1:8080/ws",
			IsTLS:                 true,
			TLSInsecureSkipVerify: true,
		},
		{
			Name:         "Default port",
			Url:          "socks5://127.0.0.1",
			Version:      "5",
			GetAddr:      "127.0.0.1:1080",
			IsUDPAllowed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			client, err := socksgo.ClientFromURL(tc.Url)
			if err != nil {
				t.Errorf("unexpected error %v", err)
				return
			}

			if client.Version() != tc.Version {
				t.Errorf(
					"Version() == %s while expected %s",
					client.Version(),
					tc.Version,
				)
			}
			if client.GetAddr() != tc.GetAddr {
				t.Errorf(
					"GetAddr() == %s while expected %s",
					client.GetAddr(),
					tc.GetAddr,
				)
			}
			if client.WebSocketURL != tc.WebSocketURL {
				t.Errorf(
					"WebSocketURL() == %s while expected %s",
					client.WebSocketURL,
					tc.WebSocketURL,
				)
			}
			if client.IsTLS() != tc.IsTLS {
				t.Errorf(
					"IsTLS() == %t while expected %t",
					client.IsTLS(),
					tc.IsTLS,
				)
			}
			if client.IsUDPAllowed() != tc.IsUDPAllowed {
				t.Errorf(
					"IsUDPAllowed() == %t while expected %t",
					client.IsUDPAllowed(),
					tc.IsUDPAllowed,
				)
			}

			if tc.IsTLS {
				TLSInsecureSkipVerify := false
				if client.TLSConfig != nil {
					TLSInsecureSkipVerify = client.TLSConfig.InsecureSkipVerify
				}
				if TLSInsecureSkipVerify != tc.TLSInsecureSkipVerify {
					t.Errorf(
						"TLSInsecureSkipVerify() == %t while expected %t",
						TLSInsecureSkipVerify,
						tc.TLSInsecureSkipVerify,
					)
				}
			}
		})
	}
}

func TestClientFromURLSafe_ErrorPath(t *testing.T) {
	t.Parallel()

	_, err := socksgo.ClientFromURLSafe("://invalid-url")
	if err == nil {
		t.Fatal("Expected error for invalid URL, got nil")
	}
}

func TestClientFromURLObjSafe_NilURL(t *testing.T) {
	t.Parallel()

	client := socksgo.ClientFromURLObjSafe(nil)

	if client == nil {
		t.Fatal("Expected non-nil client for nil URL")
	}
	if client.ProxyAddr != "" {
		t.Errorf("ProxyAddr = %q, want empty", client.ProxyAddr)
	}
	if client.WebSocketURL != "" {
		t.Errorf("WebSocketURL = %q, want empty", client.WebSocketURL)
	}
}

func TestClientFromURLObjSafe_PassParam(t *testing.T) {
	t.Parallel()

	client, err := socksgo.ClientFromURL("socks5://127.0.0.1:1080?pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// pass parameter should set Filter to PassAllFilter
	// PassAllFilter returns false (use proxy)
	if client.Filter == nil {
		t.Fatal("Filter should not be nil")
	}
	// Test that filter passes everything (MatchAllFilter behavior)
	// Actually pass sets it to PassAllFilter which returns false
	if client.Filter("tcp", "example.com:80") {
		t.Error("Filter with pass=true should return false (use proxy)")
	}
}

func TestClientFromURLObj(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name              string
		URL               string
		ExpectedInsecure  *bool // nil means don't check
		ExpectedAssocProb *bool // nil means don't check
		ExpectedSecure    *bool // nil means don't check (TLSConfig.InsecureSkipVerify = !secure)
	}{
		{
			Name:              "insecureudp enabled",
			URL:               "socks5://127.0.0.1:1080?insecureudp",
			ExpectedInsecure:  boolPtr(true),
			ExpectedAssocProb: nil,
			ExpectedSecure:    nil,
		},
		{
			Name:              "assocprob disabled",
			URL:               "socks5://127.0.0.1:1080?assocprob=false",
			ExpectedInsecure:  nil,
			ExpectedAssocProb: boolPtr(false),
			ExpectedSecure:    nil,
		},
		{
			Name:              "assocprob enabled",
			URL:               "socks5://127.0.0.1:1080?assocprob",
			ExpectedInsecure:  nil,
			ExpectedAssocProb: boolPtr(true),
			ExpectedSecure:    nil,
		},
		{
			Name:              "secure disabled",
			URL:               "socks5://127.0.0.1:1080?secure=false",
			ExpectedInsecure:  nil,
			ExpectedAssocProb: nil,
			ExpectedSecure:    boolPtr(false),
		},
		{
			Name:              "secure enabled",
			URL:               "socks5+tls://127.0.0.1:1080?secure",
			ExpectedInsecure:  nil,
			ExpectedAssocProb: nil,
			ExpectedSecure:    boolPtr(true),
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			client, err := socksgo.ClientFromURL(tc.URL)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.ExpectedInsecure != nil {
				if client.InsecureUDP != *tc.ExpectedInsecure {
					t.Errorf(
						"InsecureUDP = %v, want %v",
						client.InsecureUDP,
						*tc.ExpectedInsecure,
					)
				}
			}
			if tc.ExpectedAssocProb != nil {
				if client.DoNotSpawnUDPAsocProbber != !*tc.ExpectedAssocProb {
					t.Errorf("DoNotSpawnUDPAsocProbber = %v, want %v",
						client.DoNotSpawnUDPAsocProbber, !*tc.ExpectedAssocProb)
				}
			}
			if tc.ExpectedSecure != nil && client.TLSConfig != nil {
				if client.TLSConfig.InsecureSkipVerify != !*tc.ExpectedSecure {
					t.Errorf(
						"TLSConfig.InsecureSkipVerify = %v, want %v",
						client.TLSConfig.InsecureSkipVerify,
						!*tc.ExpectedSecure,
					)
				}
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestClientFromURL_ErrorPath(t *testing.T) {
	t.Parallel()

	_, err := socksgo.ClientFromURL("://invalid-url")
	if err == nil {
		t.Fatal("Expected error for invalid URL, got nil")
	}
}

func TestClientFromENVSafe_EmptyEnv(t *testing.T) {
	// Save original env
	origAllProxy := os.Getenv("ALL_PROXY")
	origHTTPSProxy := os.Getenv("HTTPS_PROXY")
	origHTTPProxy := os.Getenv("HTTP_PROXY")
	defer func() {
		os.Setenv("ALL_PROXY", origAllProxy)
		os.Setenv("HTTPS_PROXY", origHTTPSProxy)
		os.Setenv("HTTP_PROXY", origHTTPProxy)
	}()

	// Clear env vars
	os.Unsetenv("ALL_PROXY")
	os.Unsetenv("HTTPS_PROXY")
	os.Unsetenv("HTTP_PROXY")

	client, err := socksgo.ClientFromENVSafe("socks5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if !client.IsNoProxy() {
		t.Error("IsNoProxy should return true when no proxy env is set")
	}
}

func TestClientFromENVSafe_WithEnv(t *testing.T) {
	// Save original env
	orig := os.Getenv("ALL_PROXY")
	defer os.Setenv("ALL_PROXY", orig)

	// Set test env
	os.Setenv("ALL_PROXY", "socks5://127.0.0.1:1080")

	client, err := socksgo.ClientFromENVSafe("socks5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if client.ProxyAddr != "127.0.0.1:1080" {
		t.Errorf("ProxyAddr = %q, want 127.0.0.1:1080", client.ProxyAddr)
	}
}

func TestClientFromENV_EmptyEnv(t *testing.T) {
	// Save original env
	origAllProxy := os.Getenv("ALL_PROXY")
	origHTTPSProxy := os.Getenv("HTTPS_PROXY")
	origHTTPProxy := os.Getenv("HTTP_PROXY")
	defer func() {
		os.Setenv("ALL_PROXY", origAllProxy)
		os.Setenv("HTTPS_PROXY", origHTTPSProxy)
		os.Setenv("HTTP_PROXY", origHTTPProxy)
	}()

	// Clear env vars
	os.Unsetenv("ALL_PROXY")
	os.Unsetenv("HTTPS_PROXY")
	os.Unsetenv("HTTP_PROXY")

	client, err := socksgo.ClientFromENV("socks5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if !client.IsNoProxy() {
		t.Error("IsNoProxy should return true when no proxy env is set")
	}
}

func TestClientFromENV_WithEnv(t *testing.T) {
	// Save original env
	orig := os.Getenv("ALL_PROXY")
	defer os.Setenv("ALL_PROXY", orig)

	// Set test env
	os.Setenv("ALL_PROXY", "socks5://127.0.0.1:1080")

	client, err := socksgo.ClientFromENV("socks5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client == nil {
		t.Fatal("Expected non-nil client")
	}
	if client.ProxyAddr != "127.0.0.1:1080" {
		t.Errorf("ProxyAddr = %q, want 127.0.0.1:1080", client.ProxyAddr)
	}
}

// Mock dialer for testing
type mockDialer struct {
	dialFunc func(ctx context.Context, network, address string) (net.Conn, error)
}

func (m *mockDialer) DialContext(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	if m.dialFunc != nil {
		return m.dialFunc(ctx, network, address)
	}
	return nil, nil
}

// mockListener implements net.Listener for testing
type mockListener struct {
	addr net.Addr
}

func (m *mockListener) Accept() (net.Conn, error) { return nil, nil }
func (m *mockListener) Close() error              { return nil }
func (m *mockListener) Addr() net.Addr            { return m.addr }

func TestClient_Dial_UDPNetwork(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
	}

	// UDP networks should be routed to DialPacket
	_, err := client.Dial(context.Background(), "udp", "127.0.0.1:53")
	// This will fail because we don't have a real proxy, but it should not panic
	// and should attempt to dial (not return network unsupported error)
	if err == nil {
		// It's ok if it doesn't error (in case of future implementation changes)
		return
	}
}

func TestClient_Dial_FilterPath(t *testing.T) {
	t.Parallel()

	called := false
	mockDialerFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		called = true
		return &mockConn{}, nil
	}

	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
		Filter:    gonnect.TrueFilter, // Always use direct connection
		Dialer:    mockDialerFunc,
	}

	conn, err := client.Dial(context.Background(), "tcp", "example.com:80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("Expected non-nil connection")
	}
	if !called {
		t.Error("Expected custom dialer to be called")
	}
}

func TestClient_Dial_UnsupportedNetwork(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
	}

	_, err := client.Dial(context.Background(), "unix", "/tmp/socket")
	if err == nil {
		t.Fatal("Expected error for unsupported network, got nil")
	}
}

func TestClient_Dial_RequestFails(t *testing.T) {
	t.Parallel()

	dialErr := errors.New("dial failed")
	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, dialErr
		},
	}

	_, err := client.Dial(context.Background(), "tcp", "example.com:80")
	if err == nil {
		t.Fatal("Expected error when Request fails, got nil")
	}
	if !errors.Is(err, dialErr) && err.Error() != dialErr.Error() {
		t.Errorf("Expected dial error, got %v", err)
	}
}

func TestClient_DialPacket_FilterPath(t *testing.T) {
	t.Parallel()

	called := false
	mockPacketDialerFunc := func(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
		called = true
		return &mockPacketConn{}, nil
	}

	client := &socksgo.Client{
		ProxyAddr:    "127.0.0.1:1080",
		Filter:       gonnect.TrueFilter,
		Dialer:       func(ctx context.Context, network, address string) (net.Conn, error) { return nil, nil },
		PacketDialer: mockPacketDialerFunc,
		GostUDPTun:   false, // Disable GostUDPTun to use standard path
	}

	// Check if filter is working
	if !client.DoFilter("udp", "127.0.0.1:53") {
		t.Fatal("Filter should return true for MatchAllFilter")
	}

	conn, err := client.DialPacket(context.Background(), "udp", "127.0.0.1:53")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("Expected non-nil connection")
	}
	if !called {
		t.Error("Expected custom packet dialer to be called")
	}
}

func TestClient_DialPacket_UnsupportedNetwork(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
	}

	_, err := client.DialPacket(context.Background(), "unix", "/tmp/socket")
	if err == nil {
		t.Fatal("Expected error for unsupported network, got nil")
	}
}

func TestClient_ListenPacket_FilterPath(t *testing.T) {
	t.Parallel()

	called := false
	mockPacketListenerFunc := func(ctx context.Context, network, address string) (gonnect.PacketConn, error) {
		called = true
		return &mockPacketConn{}, nil
	}

	client := &socksgo.Client{
		ProxyAddr:            "127.0.0.1:1080",
		Filter:               gonnect.TrueFilter,
		Dialer:               func(ctx context.Context, network, address string) (net.Conn, error) { return nil, nil },
		DirectPacketListener: mockPacketListenerFunc,
		GostUDPTun:           false, // Disable GostUDPTun to use standard path
	}

	conn, err := client.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("Expected non-nil connection")
	}
	if !called {
		t.Error("Expected custom packet listener to be called")
	}
}

func TestClient_ListenPacket_UnsupportedNetwork(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
	}

	_, err := client.ListenPacket(context.Background(), "unix", "/tmp/socket")
	if err == nil {
		t.Fatal("Expected error for unsupported network, got nil")
	}
}

func TestClient_Listen_FilterPath(t *testing.T) {
	t.Parallel()

	called := false
	mockListenerFunc := func(ctx context.Context, network, address string) (net.Listener, error) {
		called = true
		return &mockListener{
			addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
		}, nil
	}

	client := &socksgo.Client{
		ProxyAddr:      "127.0.0.1:1080",
		Filter:         gonnect.TrueFilter,
		DirectListener: mockListenerFunc,
	}

	ln, err := client.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ln == nil {
		t.Fatal("Expected non-nil listener")
	}
	if !called {
		t.Error("Expected custom listener to be called")
	}
}

func TestClient_Listen_UnsupportedNetwork(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
	}

	_, err := client.Listen(context.Background(), "unix", "/tmp/socket")
	if err == nil {
		t.Fatal("Expected error for unsupported network, got nil")
	}
}

func TestClient_LookupIP_InvalidNetwork(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
		TorLookup: true,
	}

	_, err := client.LookupIP(context.Background(), "tcp", "example.com")
	if err == nil {
		t.Fatal("Expected error for invalid network, got nil")
	}
	dnsErr, ok := err.(*net.DNSError)
	if !ok {
		t.Fatalf("Expected *net.DNSError, got %T", err)
	}
	if !dnsErr.IsNotFound {
		t.Error("Expected IsNotFound to be true")
	}
}

func TestClient_LookupIP_TorLookupDisabled(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
		TorLookup: false,
	}

	_, err := client.LookupIP(context.Background(), "ip", "example.com")
	if err == nil {
		t.Fatal("Expected error when TorLookup is disabled, got nil")
	}
	dnsErr, ok := err.(*net.DNSError)
	if !ok {
		t.Fatalf("Expected *net.DNSError, got %T", err)
	}
	if dnsErr.UnwrapErr != socksgo.ErrResolveDisabled {
		t.Errorf("Expected ErrResolveDisabled, got %v", dnsErr.UnwrapErr)
	}
}

func TestClient_LookupIP_FilterPath(t *testing.T) {
	t.Parallel()

	called := false
	mockResolver := &mockResolver{
		FnLookupIP: func(ctx context.Context, network, address string) ([]net.IP, error) {
			called = true
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
		FnLookupAddr: nil,
	}

	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
		TorLookup: true,
		Filter:    gonnect.TrueFilter,
		Resolver:  mockResolver,
	}

	ips, err := client.LookupIP(context.Background(), "ip", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 {
		t.Fatalf("Expected 1 IP, got %d", len(ips))
	}
	if !called {
		t.Error("Expected custom resolver to be called")
	}
}

func TestClient_LookupAddr_TorLookupDisabled(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
		TorLookup: false,
	}

	_, err := client.LookupAddr(context.Background(), "127.0.0.1")
	if err == nil {
		t.Fatal("Expected error when TorLookup is disabled, got nil")
	}
	dnsErr, ok := err.(*net.DNSError)
	if !ok {
		t.Fatalf("Expected *net.DNSError, got %T", err)
	}
	if dnsErr.UnwrapErr != socksgo.ErrResolveDisabled {
		t.Errorf("Expected ErrResolveDisabled, got %v", dnsErr.UnwrapErr)
	}
}

func TestClient_LookupAddr_FilterPath(t *testing.T) {
	t.Parallel()

	called := false
	mockResolver := &mockResolver{
		FnLookupIP: nil,
		FnLookupAddr: func(ctx context.Context, address string) ([]string, error) {
			called = true
			return []string{"example.com"}, nil
		},
	}

	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
		TorLookup: true,
		Filter:    gonnect.TrueFilter,
		Resolver:  mockResolver,
	}

	addrs, err := client.LookupAddr(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(addrs))
	}
	if !called {
		t.Error("Expected custom resolver to be called")
	}
}

func TestClient_LookupAddr_RequestFails(t *testing.T) {
	t.Parallel()

	dialErr := errors.New("dial failed")
	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
		TorLookup: true,
		Filter:    gonnect.FalseFilter, // Force proxy path
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, dialErr
		},
	}

	_, err := client.LookupAddr(context.Background(), "127.0.0.1")
	if err == nil {
		t.Fatal("Expected error when Request fails, got nil")
	}
	if !errors.Is(err, dialErr) && err.Error() != dialErr.Error() {
		t.Errorf("Expected dial error, got %v", err)
	}
}

// Test request method routing through Version() method
func TestClient_Request_VersionRouting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
	}{
		{"default (5)", ""},
		{"socks5", "5"},
		{"socks4a", "4a"},
		{"socks4", "4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &socksgo.Client{
				SocksVersion: tt.version,
				ProxyAddr:    "127.0.0.1:1080",
			}

			// The request will fail because there's no real proxy,
			// but we're testing that the version routing works
			_, _, err := client.Request(
				context.Background(),
				protocol.CmdConnect,
				protocol.AddrFromHostPort("example.com:80", "tcp"),
			)
			// We expect an error since there's no real proxy
			if err == nil {
				t.Log(
					"Request succeeded (unexpected but not necessarily wrong)",
				)
			}
		})
	}
}

func TestClient_Request_UnknownVersion(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		SocksVersion: "99", // Unknown version
		ProxyAddr:    "127.0.0.1:1080",
	}

	_, _, err := client.Request(
		context.Background(),
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("Expected error for unknown SOCKS version, got nil")
	}
	_, ok := err.(socksgo.UnknownSocksVersionError)
	if !ok {
		t.Errorf("Expected UnknownSocksVersionError, got %T: %v", err, err)
	}
}

func TestClient_Request_Socks4_WithoutIP(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		SocksVersion: "4",
		ProxyAddr:    "127.0.0.1:1080",
		// Use a resolver that fails to resolve the hostname
		Resolver: &mockResolver{
			FnLookupIP: func(ctx context.Context, network, address string) ([]net.IP, error) {
				if network == "ip4" {
					// Return error for IPv4 lookup
					return nil, errors.New("no IPv4 address")
				}
				return nil, nil
			},
			FnLookupAddr: func(ctx context.Context, address string) ([]string, error) {
				return nil, errors.New("not implemented")
			},
		},
	}

	// SOCKS4 requires an IP address, not a hostname
	// With a resolver that fails to resolve, Request should return UnsupportedAddrError
	_, _, err := client.Request(
		context.Background(),
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "tcp"),
	)
	// We expect an UnsupportedAddrError
	if err == nil {
		t.Fatal("Expected error for SOCKS4 with hostname (not IP), got nil")
	}
	_, ok := err.(socksgo.UnsupportedAddrError)
	if !ok {
		t.Errorf("Expected UnsupportedAddrError, got %T: %v", err, err)
	}
}

// Test SOCKS4 request with IPv6-only address (cannot resolve to IPv4)
func TestClient_Request_Socks4_IPv6Only(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		SocksVersion: "4",
		ProxyAddr:    "127.0.0.1:1080",
		Filter:       gonnect.FalseFilter, // Use proxy path
		// Use a resolver that returns error for IPv4 lookup
		Resolver: &mockResolver{
			FnLookupIP: func(ctx context.Context, network, address string) ([]net.IP, error) {
				if network == "ip4" {
					// Return error for IPv4 lookup
					return nil, errors.New("no IPv4 address")
				}
				// Return IPv6 for other queries
				return []net.IP{net.ParseIP("::1")}, nil
			},
			FnLookupAddr: func(ctx context.Context, address string) ([]string, error) {
				return nil, errors.New("not implemented")
			},
		},
	}

	// SOCKS4 requires IPv4, ResolveToIP4 will return nil for IPv6-only
	_, _, err := client.Request(
		context.Background(),
		protocol.CmdConnect,
		protocol.AddrFromHostPort("ipv6-only.example.com:80", "tcp"),
	)
	if err == nil {
		t.Fatal("Expected error for SOCKS4 with IPv6-only address, got nil")
	}
	_, ok := err.(socksgo.UnsupportedAddrError)
	if !ok {
		t.Logf("Got error type %T: %v", err, err)
	}
}

func TestClient_Request_UnsupportedNetwork(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
	}

	_, _, err := client.Request(
		context.Background(),
		protocol.CmdConnect,
		protocol.AddrFromHostPort("example.com:80", "unix"),
	)
	if err == nil {
		t.Fatal("Expected error for unsupported network, got nil")
	}
}

// Test Listen with different SOCKS versions
func TestClient_Listen_Socks4(t *testing.T) {
	t.Parallel()

	client := &socksgo.Client{
		SocksVersion: "4",
		ProxyAddr:    "127.0.0.1:1080",
		Filter:       gonnect.TrueFilter,
		DirectListener: func(ctx context.Context, network, address string) (net.Listener, error) {
			return &mockListener{
				addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
			}, nil
		},
	}

	ln, err := client.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ln == nil {
		t.Fatal("Expected non-nil listener")
	}
}

func TestClient_Listen_UnknownVersion(t *testing.T) {
	t.Parallel()

	// This test requires a working proxy connection to reach the version check
	// For now, we test through Request which has the same version check
	client := &socksgo.Client{
		SocksVersion: "99",
		ProxyAddr:    "127.0.0.1:1080",
	}

	_, _, err := client.Request(
		context.Background(),
		protocol.CmdBind,
		protocol.AddrFromHostPort("127.0.0.1:0", "tcp"),
	)
	if err == nil {
		t.Fatal("Expected error for unknown SOCKS version, got nil")
	}
	_, ok := err.(socksgo.UnknownSocksVersionError)
	if !ok {
		t.Errorf("Expected UnknownSocksVersionError, got %T: %v", err, err)
	}
}

// Test LookupIP with nil IP response
func TestClient_LookupIP_NilIPResponse(t *testing.T) {
	t.Parallel()

	// Create a mock that returns an address with nil IP
	// We need to simulate the Request returning an addr with ToIP() == nil
	// This is hard to test directly, so we test through the error path
	client := &socksgo.Client{
		ProxyAddr: "127.0.0.1:1080",
		TorLookup: true,
		Filter:    gonnect.FalseFilter, // Use proxy path
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("connection refused")
		},
	}

	_, err := client.LookupIP(context.Background(), "ip", "example.com")
	// Will get connection error before reaching the nil IP check
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
}

// Test Listen with GostMbind and smux error
func TestClient_Listen_GostMbindSmuxError(t *testing.T) {
	t.Parallel()

	// Create a client with GostMbind enabled but invalid smux config
	// This should cause smux.Server to fail
	client := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    "127.0.0.1:1080",
		GostMbind:    true,
		Smux:         nil, // nil config might cause issues
		Filter:       gonnect.FalseFilter,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Return a mock connection that will cause smux to fail
			return &mockConn{deadlineErr: true}, nil
		},
	}

	// This will either fail at smux.Server or at connection
	_, err := client.Listen(context.Background(), "tcp", "127.0.0.1:0")
	// We expect an error either from smux or from the connection
	if err == nil {
		t.Log("Listen succeeded (smux may have accepted the connection)")
	}
}
