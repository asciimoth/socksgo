// nolint
package socksgo_test

import (
	"context"
	"net"
	"testing"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

func TestNilHandlerRun(t *testing.T) {
	var handler *socksgo.CommandHandler
	err := handler.Run(
		context.Background(), nil, nil, "5",
		protocol.AuthInfo{}, 0, protocol.Addr{},
	)
	if err.Error() != "attempt to run nil handler for cmd 0 (cmd no0)" {
		t.Fatal(err)
	}
}

func TestNilHandlerAllowed(t *testing.T) {
	var handler *socksgo.CommandHandler
	versions := []string{"4", "4a", "5", "5h", "", "noversion"}
	for _, version := range versions {
		a := handler.Allowed(version, false)
		b := handler.Allowed(version, true)
		if a || b {
			t.Error(version, a, b)
		}
	}
}

func TestHandlerAllowedWrongVersion(t *testing.T) {
	handler := &socksgo.CommandHandler{
		Socks4: true,
		Socks5: true,
	}
	versions := []string{"", "noversion"}
	for _, version := range versions {
		a := handler.Allowed(version, false)
		b := handler.Allowed(version, true)
		if a || b {
			t.Error(version, a, b)
		}
	}
}

func TestHandlerNoTLS(t *testing.T) {
	handler := &socksgo.CommandHandler{
		Socks4:    true,
		Socks5:    true,
		TLSCompat: false,
	}
	versions := []string{"4", "4a", "5", "5h"}
	for _, version := range versions {
		a := handler.Allowed(version, false)
		b := handler.Allowed(version, true)
		if !a || b {
			t.Error(version, a, b)
		}
	}
}

// Test CommandHandler.Run and Allowed
func TestCommandHandler_Run(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Test with nil handler
	var nilHandler *socksgo.CommandHandler
	err := nilHandler.Run(
		ctx,
		nil,
		nil,
		"5",
		protocol.AuthInfo{},
		protocol.CmdConnect,
		protocol.Addr{},
	)
	if err == nil {
		t.Fatal("expected error for nil handler")
	}

	// Test with handler
	called := false
	handler := &socksgo.CommandHandler{
		Socks4:    true,
		Socks5:    true,
		TLSCompat: true,
		Handler: func(ctx context.Context, server *socksgo.Server, conn net.Conn, ver string, info protocol.AuthInfo, cmd protocol.Cmd, addr protocol.Addr) error {
			called = true
			return nil
		},
	}

	err = handler.Run(
		ctx,
		nil,
		nil,
		"5",
		protocol.AuthInfo{},
		protocol.CmdConnect,
		protocol.Addr{},
	)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !called {
		t.Fatal("handler not called")
	}
}

func TestCommandHandler_Allowed(t *testing.T) {
	t.Parallel()

	// Test nil handler
	var nilHandler *socksgo.CommandHandler
	if nilHandler.Allowed("5", false) {
		t.Fatal("nil handler should not be allowed")
	}

	// Test with handler
	handler := &socksgo.CommandHandler{
		Socks4:    true,
		Socks5:    true,
		TLSCompat: false,
		Handler: func(ctx context.Context, server *socksgo.Server, conn net.Conn, ver string, info protocol.AuthInfo, cmd protocol.Cmd, addr protocol.Addr) error {
			return nil
		},
	}

	// TLS without TLSCompat should fail
	if handler.Allowed("5", true) {
		t.Fatal("handler without TLSCompat should not be allowed with TLS")
	}

	// SOCKS5 without Socks5 flag
	handler.Socks5 = false
	if handler.Allowed("5", false) {
		t.Fatal("handler without Socks5 should not be allowed for SOCKS5")
	}

	// SOCKS4 should work
	handler.Socks4 = true
	if !handler.Allowed("4", false) {
		t.Fatal("handler with Socks4 should be allowed for SOCKS4")
	}

	// SOCKS4a should work
	if !handler.Allowed("4a", false) {
		t.Fatal("handler with Socks4 should be allowed for SOCKS4a")
	}

	// SOCKS5h should check Socks5
	handler.Socks5 = true
	if !handler.Allowed("5h", false) {
		t.Fatal("handler with Socks5 should be allowed for SOCKS5h")
	}
}
