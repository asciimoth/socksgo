package socksgo_test

import (
	"errors"
	"net"
	"testing"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

func TestErrorConstants(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrUDPDisallowed",
			err:      socksgo.ErrUDPDisallowed,
			expected: "plaintext UDP is disallowed for tls/wss proxies",
		},
		{
			name:     "ErrResolveDisabled",
			err:      socksgo.ErrResolveDisabled,
			expected: "tor resolve extension for socks is disabled",
		},
		{
			name:     "ErrWrongAddrInLookupResponse",
			err:      socksgo.ErrWrongAddrInLookupResponse,
			expected: "wrong addr type in lookup response",
		},
		{
			name:     "ErrClientAuthFailed",
			err:      socksgo.ErrClientAuthFailed,
			expected: "client auth failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

func TestWrongNetworkError(t *testing.T) {
	t.Run("Error method", func(t *testing.T) {
		err := socksgo.WrongNetworkError{
			SocksVersion: "5",
			Network:      "testnet",
		}

		expected := "socks5 unknown network testnet"
		if got := err.Error(); got != expected {
			t.Errorf("expected %q, got %q", expected, got)
		}
	})

	t.Run("Unwrap method", func(t *testing.T) {
		err := socksgo.WrongNetworkError{
			SocksVersion: "4",
			Network:      "ipx",
		}

		unwrapped := err.Unwrap()
		if unwrapped == nil {
			t.Fatal("expected unwrapped error to not be nil")
		}

		expected := "unknown network ipx"
		if unwrapped.Error() != expected {
			t.Errorf(
				"expected unwrapped error %q, got %q",
				expected,
				unwrapped.Error(),
			)
		}

		// Test that the unwrapped error is of the correct type
		var netErr net.UnknownNetworkError
		if !errors.As(unwrapped, &netErr) {
			t.Error("expected unwrapped error to be net.UnknownNetworkError")
		}
	})

	t.Run("Error method with socks4a", func(t *testing.T) {
		err := socksgo.WrongNetworkError{
			SocksVersion: "4a",
			Network:      "some_network",
		}

		expected := "socks4a unknown network some_network"
		if got := err.Error(); got != expected {
			t.Errorf("expected %q, got %q", expected, got)
		}
	})
}

func TestUnsupportedAddrError(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		addr           string
		expectedFormat string
	}{
		{
			name:           "socks5 with IPv6",
			version:        "5",
			addr:           "::1",
			expectedFormat: "addr ::1 is unsupported by socks5",
		},
		{
			name:           "socks4 with domain",
			version:        "4",
			addr:           "example.com",
			expectedFormat: "addr example.com is unsupported by socks4",
		},
		{
			name:           "socks4a with IPv6",
			version:        "4a",
			addr:           "2001:db8::1",
			expectedFormat: "addr 2001:db8::1 is unsupported by socks4a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := socksgo.UnsupportedAddrError{
				SocksVersion: tt.version,
				Addr:         tt.addr,
			}

			if got := err.Error(); got != tt.expectedFormat {
				t.Errorf("expected %q, got %q", tt.expectedFormat, got)
			}
		})
	}
}

func TestRejectdError(t *testing.T) {
	tests := []struct {
		name     string
		status   protocol.ReplyStatus
		expected string
	}{
		{
			name:     "general failure",
			status:   protocol.FailReply,
			expected: "socks request rejected with code 1 general SOCKS server failure",
		},
		{
			name:     "connection not allowed",
			status:   protocol.ConnRefusedReply,
			expected: "socks request rejected with code 5 connection refused",
		},
		{
			name:     "network unreachable",
			status:   protocol.NetUnreachReply,
			expected: "socks request rejected with code 3 network unreachable",
		},
		{
			name:     "host unreachable",
			status:   protocol.HostUnreachReply,
			expected: "socks request rejected with code 4 host unreachable",
		},
		{
			name:     "connection refused",
			status:   protocol.ConnRefusedReply,
			expected: "socks request rejected with code 5 connection refused",
		},
		{
			name:     "TTL expired",
			status:   protocol.TTLExpiredReply,
			expected: "socks request rejected with code 6 TTL expired",
		},
		{
			name:     "command not supported",
			status:   protocol.CmdNotSuppReply,
			expected: "socks request rejected with code 7 command not supported",
		},
		{
			name:     "address type not supported",
			status:   protocol.AddrNotSuppReply,
			expected: "socks request rejected with code 128 address type not supported",
		},
		{
			name:     "unknown status",
			status:   protocol.ReplyStatus(99),
			expected: "socks request rejected with code 99 reply code no99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := socksgo.RejectdError{
				Status: tt.status,
			}

			if got := err.Error(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestUnsupportedCommandError(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		cmd      protocol.Cmd
		expected string
	}{
		{
			name:     "socks5 bind command",
			version:  "5",
			cmd:      protocol.CmdBind,
			expected: "socks5 client requested unsupported command 2 (cmd bind)",
		},
		{
			name:     "socks4 UDP associate",
			version:  "4",
			cmd:      protocol.CmdUDPAssoc,
			expected: "socks4 client requested unsupported command 3 (cmd UDP associate)",
		},
		{
			name:     "socks4a unknown command",
			version:  "4a",
			cmd:      protocol.Cmd(99),
			expected: "socks4a client requested unsupported command 99 (cmd no99)",
		},
		{
			name:     "socks5 connect command",
			version:  "5",
			cmd:      protocol.CmdConnect,
			expected: "socks5 client requested unsupported command 1 (cmd connect)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := socksgo.UnsupportedCommandError{
				SocksVersion: tt.version,
				Cmd:          tt.cmd,
			}

			if got := err.Error(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestNilHandlerError(t *testing.T) {
	tests := []struct {
		name     string
		cmd      protocol.Cmd
		expected string
	}{
		{
			name:     "connect command",
			cmd:      protocol.CmdConnect,
			expected: "attempt to run nil handler for cmd 1 (cmd connect)",
		},
		{
			name:     "bind command",
			cmd:      protocol.CmdBind,
			expected: "attempt to run nil handler for cmd 2 (cmd bind)",
		},
		{
			name:     "UDP associate command",
			cmd:      protocol.CmdUDPAssoc,
			expected: "attempt to run nil handler for cmd 3 (cmd UDP associate)",
		},
		{
			name:     "unknown command",
			cmd:      protocol.Cmd(99),
			expected: "attempt to run nil handler for cmd 99 (cmd no99)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := socksgo.NilHandlerError{
				Cmd: tt.cmd,
			}

			if got := err.Error(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestAddrDisallowedError(t *testing.T) {
	ip4 := protocol.AddrFromString("192.168.1.1", 8080, "")
	ip6 := protocol.AddrFromString("2001:db8::1", 80, "")
	fqdn := protocol.AddrFromString("example.com", 443, "")

	tests := []struct {
		name       string
		addr       *protocol.Addr
		filterName string
		expected   string
	}{
		{
			name:       "IPv4 address",
			addr:       &ip4,
			filterName: "blacklist",
			expected:   "address 192.168.1.1:8080 is disallowed by blacklist filter",
		},
		{
			name:       "domain address",
			addr:       &fqdn,
			filterName: "domain_filter",
			expected:   "address example.com:443 is disallowed by domain_filter filter",
		},
		{
			name:       "IPv6 address",
			addr:       &ip6,
			filterName: "ipv6_filter",
			expected:   "address [2001:db8::1]:80 is disallowed by ipv6_filter filter",
		},
		{
			name:       "empty filter name",
			addr:       &ip4,
			filterName: "",
			expected:   "address 192.168.1.1:8080 is disallowed by  filter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := socksgo.AddrDisallowedError{
				Addr:       tt.addr,
				FilterName: tt.filterName,
			}

			if got := err.Error(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestErrorEdgeCases(t *testing.T) {
	t.Run("WrongNetworkError with empty network", func(t *testing.T) {
		err := socksgo.WrongNetworkError{
			SocksVersion: "5",
			Network:      "",
		}

		expected := "socks5 unknown network "
		if got := err.Error(); got != expected {
			t.Errorf("expected %q, got %q", expected, got)
		}

		// Unwrap should still work
		unwrapped := err.Unwrap()
		if unwrapped.Error() != "unknown network " {
			t.Errorf("unexpected unwrapped error: %q", unwrapped.Error())
		}
	})

	t.Run("UnsupportedAddrError with empty address", func(t *testing.T) {
		err := socksgo.UnsupportedAddrError{
			SocksVersion: "5",
			Addr:         "",
		}

		expected := "addr  is unsupported by socks5"
		if got := err.Error(); got != expected {
			t.Errorf("expected %q, got %q", expected, got)
		}
	})

	t.Run("NilHandlerError with zero value command", func(t *testing.T) {
		err := socksgo.NilHandlerError{
			Cmd: protocol.Cmd(0),
		}

		expected := "attempt to run nil handler for cmd 0 (cmd no0)"
		if got := err.Error(); got != expected {
			t.Errorf("expected %q, got %q", expected, got)
		}
	})
}

func TestUnknownSocksVersionError(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "version 6",
			version:  "6",
			expected: "unknown socks version 6",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "unknown socks version ",
		},
		{
			name:     "version with special chars",
			version:  "4.5-beta",
			expected: "unknown socks version 4.5-beta",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := socksgo.UnknownSocksVersionError{
				Version: tt.version,
			}

			if got := err.Error(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}
