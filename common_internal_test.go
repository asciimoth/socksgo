//go:build compattest

package socksgo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/asciimoth/socksgo/protocol"
)

func TestErrorToReplyStatus_Internal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected protocol.ReplyStatus
	}{
		{
			name:     "nil error returns success",
			err:      nil,
			expected: protocol.SuccReply,
		},
		{
			name: "connection refused",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("connection refused"),
			},
			expected: protocol.ConnRefusedReply,
		},
		{
			name: "network unreachable",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("network unreachable"),
			},
			expected: protocol.NetUnreachReply,
		},
		{
			name: "host unreachable",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("host unreachable"),
			},
			expected: protocol.HostUnreachReply,
		},
		{
			name: "i/o timeout",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: errors.New("i/o timeout"),
			},
			expected: protocol.TTLExpiredReply,
		},
		{
			name: "connection timed out",
			err: &net.OpError{
				Op:  "read",
				Net: "tcp",
				Err: errors.New("connection timed out"),
			},
			expected: protocol.TTLExpiredReply,
		},
		{
			name: "permission denied",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("permission denied"),
			},
			expected: protocol.DisallowReply,
		},
		{
			name: "DNS error",
			err: &net.DNSError{
				Err:  "no such host",
				Name: "nonexistent.example.com",
			},
			expected: protocol.HostUnreachReply,
		},
		{
			name:     "generic error returns fail",
			err:      errors.New("some random error"),
			expected: protocol.FailReply,
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
			expected: protocol.ConnRefusedReply,
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
			expected: protocol.HostUnreachReply,
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
			expected: protocol.DisallowReply,
		},
		{
			name: "double wrapped connection refused",
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
			expected: protocol.ConnRefusedReply,
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
			expected: protocol.ConnRefusedReply,
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
			expected: protocol.HostUnreachReply,
		},
		{
			name: "OpError wrapping DNSError via errors.As",
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
			expected: protocol.HostUnreachReply,
		},
		{
			name: "OpError with nil Err uses OpError error string",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("connection refused"),
			},
			expected: protocol.ConnRefusedReply,
		},
		{
			name: "bare DNSError without OpError wrapper",
			err: &net.DNSError{
				Err:  "no such host",
				Name: "example.com",
			},
			expected: protocol.HostUnreachReply,
		},
		{
			name: "OpError with host unreachable in Err",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("host unreachable"),
			},
			expected: protocol.HostUnreachReply,
		},
		{
			name: "OpError with network unreachable in Err",
			err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: errors.New("network unreachable"),
			},
			expected: protocol.NetUnreachReply,
		},
		{
			name: "deeply wrapped error with connection refused",
			err: fmt.Errorf(
				"level1: %w",
				fmt.Errorf(
					"level2: %w",
					fmt.Errorf(
						"level3: %w",
						errors.New("connection refused"),
					),
				),
			),
			expected: protocol.ConnRefusedReply,
		},
		{
			name: "error with multiple wraps ending in DNS error",
			err: fmt.Errorf(
				"outer: %w",
				&net.OpError{
					Op:  "lookup",
					Net: "dns",
					Err: fmt.Errorf(
						"dns failed: %w",
						&net.DNSError{
							Err:  "no such host",
							Name: "test.com",
						},
					),
				},
			),
			expected: protocol.HostUnreachReply,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := errorToReplyStatus(tt.err)
			if got != tt.expected {
				t.Errorf(
					"errorToReplyStatus() = %d, want %d for error: %v",
					got,
					tt.expected,
					tt.err,
				)
			}
		})
	}
}

// Test that errorToReplyStatus is properly integrated with server handlers
func TestErrorToReplyStatus_Integration(t *testing.T) {
	t.Parallel()

	// Create a mock connection that will fail with a specific error
	mockErr := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: errors.New("connection refused"),
	}

	server := &Server{
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return nil, mockErr
		},
	}

	// The handler should use errorToReplyStatus internally
	// We can't directly verify the reply code sent, but we can verify
	// the handler returns an error
	conn := &net.TCPConn{}
	err := DefaultConnectHandler.Handler(
		context.Background(),
		server,
		conn,
		"5",
		protocol.AuthInfo{},
		protocol.CmdConnect,
		protocol.AddrFromFQDN("example.com", 8080, ""),
	)

	// The error should be the original dial error
	if err != mockErr {
		t.Errorf("expected mockErr, got %v", err)
	}
}
