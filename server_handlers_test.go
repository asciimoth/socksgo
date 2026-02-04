package socksgo_test

import (
	"context"
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
