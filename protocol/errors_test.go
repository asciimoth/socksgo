package protocol_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/asciimoth/socksgo/protocol"
)

func TestErrorVariables(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrNoAcceptableAuthMethods",
			err:      protocol.ErrNoAcceptableAuthMethods,
			expected: "no acceptable socks auth methods",
		},
		{
			name:     "ErrTooLongUser",
			err:      protocol.ErrTooLongUser,
			expected: "socks user name is too long",
		},
		{
			name:     "ErrTooLongHost",
			err:      protocol.ErrTooLongHost,
			expected: "socks host name is too long",
		},
		{
			name:     "ErrUDPAssocTimeout",
			err:      protocol.ErrUDPAssocTimeout,
			expected: "socks udp assoc timeout",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Error() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, tc.err.Error())
			}
			// Test error type
			if !errors.Is(tc.err, tc.err) {
				t.Errorf("error should be itself")
			}
		})
	}
}

func TestUnknownAuthVerError(t *testing.T) {
	tests := []struct {
		name     string
		version  int
		expected string
	}{
		{
			name:     "version 1",
			version:  1,
			expected: "unknown socks auth version 1",
		},
		{
			name:     "version 42",
			version:  42,
			expected: "unknown socks auth version 42",
		},
		{
			name:     "version 0",
			version:  0,
			expected: "unknown socks auth version 0",
		},
		{
			name:     "negative version",
			version:  -5,
			expected: "unknown socks auth version -5",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := protocol.UnknownAuthVerError{Version: tc.version}
			if err.Error() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, err.Error())
			}

			// Test type assertion
			var e protocol.UnknownAuthVerError
			if errors.As(err, &e) {
				if e.Version != tc.version {
					t.Errorf(
						"expected version %d, got %d",
						tc.version,
						e.Version,
					)
				}
			} else {
				t.Error("error should be of type UnknownAuthVerError")
			}
		})
	}
}

func TestUnsupportedAuthMethodError(t *testing.T) {
	tests := []struct {
		name     string
		method   protocol.AuthMethodCode
		expected string
	}{
		{
			name:     "method 0",
			method:   protocol.AuthMethodCode(0),
			expected: "socks server select unsupported auth method 0",
		},
		{
			name:     "method 255",
			method:   protocol.AuthMethodCode(255),
			expected: "socks server select unsupported auth method 255",
		},
		{
			name:     "method 42",
			method:   protocol.AuthMethodCode(42),
			expected: "socks server select unsupported auth method 42",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := protocol.UnsupportedAuthMethodError{Method: tc.method}
			if err.Error() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, err.Error())
			}

			// Test type assertion
			var e protocol.UnsupportedAuthMethodError
			if errors.As(err, &e) {
				if e.Method != tc.method {
					t.Errorf("expected method %d, got %d", tc.method, e.Method)
				}
			} else {
				t.Error("error should be of type UnsupportedAuthMethodError")
			}
		})
	}
}

func TestUnknownAddrTypeError(t *testing.T) {
	tests := []struct {
		name     string
		addrType protocol.AddrType
		expected string
	}{
		{
			name:     "AddrType 0",
			addrType: protocol.AddrType(0),
			expected: "unknown socks addr type: addr type no0", // string representation of byte 0
		},
		{
			name:     "AddrType 10",
			addrType: protocol.AddrType(10),
			expected: "unknown socks addr type: addr type no10",
		},
		{
			name:     "AddrType 255",
			addrType: protocol.AddrType(255),
			expected: "unknown socks addr type: addr type no255", // string representation of byte 255
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := protocol.UnknownAddrTypeError{Type: tc.addrType}
			if err.Error() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, err.Error())
			}

			// Test type assertion
			var e protocol.UnknownAddrTypeError
			if errors.As(err, &e) {
				if e.Type != tc.addrType {
					t.Errorf(
						"expected addr type %d, got %d",
						tc.addrType,
						e.Type,
					)
				}
			} else {
				t.Error("error should be of type UnknownAddrTypeError")
			}
		})
	}
}

func TestWrong4ReplyVerError(t *testing.T) {
	tests := []struct {
		name     string
		version  int
		expected string
	}{
		{
			name:     "version 1",
			version:  1,
			expected: "wrong socks4 reply version 1, should be 0",
		},
		{
			name:     "version 255",
			version:  255,
			expected: "wrong socks4 reply version 255, should be 0",
		},
		{
			name:     "negative version",
			version:  -1,
			expected: "wrong socks4 reply version -1, should be 0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := protocol.Wrong4ReplyVerError{Version: tc.version}
			if err.Error() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, err.Error())
			}

			// Test type assertion
			var e protocol.Wrong4ReplyVerError
			if errors.As(err, &e) {
				if e.Version != tc.version {
					t.Errorf(
						"expected version %d, got %d",
						tc.version,
						e.Version,
					)
				}
			} else {
				t.Error("error should be of type Wrong4ReplyVerError")
			}
		})
	}
}

func TestWrongProtocolVerError(t *testing.T) {
	tests := []struct {
		name     string
		version  int
		expected string
	}{
		{
			name:     "version 1",
			version:  1,
			expected: "wrong socks protocol version 1",
		},
		{
			name:     "version 42",
			version:  42,
			expected: "wrong socks protocol version 42",
		},
		{
			name:     "version 0",
			version:  0,
			expected: "wrong socks protocol version 0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := protocol.WrongProtocolVerError{Version: tc.version}
			if err.Error() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, err.Error())
			}

			// Test type assertion
			var e protocol.WrongProtocolVerError
			if errors.As(err, &e) {
				if e.Version != tc.version {
					t.Errorf(
						"expected version %d, got %d",
						tc.version,
						e.Version,
					)
				}
			} else {
				t.Error("error should be of type WrongProtocolVerError")
			}
		})
	}
}

// TestErrorStringFormatting tests edge cases for string formatting
func TestErrorStringFormatting(t *testing.T) {
	// Test that all error messages are properly formatted
	testCases := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "UnknownAuthVerError with large number",
			err:      protocol.UnknownAuthVerError{Version: 1000000},
			expected: "unknown socks auth version 1000000",
		},
		{
			name:     "WrongProtocolVerError with max int",
			err:      protocol.WrongProtocolVerError{Version: 1<<31 - 1},
			expected: fmt.Sprintf("wrong socks protocol version %d", 1<<31-1),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Error() != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, tc.err.Error())
			}
		})
	}
}

// TestErrorInterfaceCompliance tests that all error types properly implement the error interface
func TestErrorInterfaceCompliance(t *testing.T) {
	// This test ensures all error types satisfy the error interface at compile time
	// We'll use type assertions to verify at runtime

	var err error

	// Test variable errors
	err = protocol.ErrNoAcceptableAuthMethods
	_ = err.Error()

	err = protocol.ErrTooLongUser
	_ = err.Error()

	err = protocol.ErrTooLongHost
	_ = err.Error()

	err = protocol.ErrUDPAssocTimeout
	_ = err.Error()

	// Test struct errors
	err = protocol.UnknownAuthVerError{Version: 1}
	_ = err.Error()

	err = protocol.UnsupportedAuthMethodError{
		Method: protocol.AuthMethodCode(1),
	}
	_ = err.Error()

	err = protocol.UnknownAddrTypeError{Type: protocol.AddrType(1)}
	_ = err.Error()

	err = protocol.Wrong4ReplyVerError{Version: 1}
	_ = err.Error()

	err = protocol.WrongProtocolVerError{Version: 1}
	_ = err.Error()

	// If we reach here without panicking, all types satisfy the error interface
}
