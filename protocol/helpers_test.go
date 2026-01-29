package protocol_test

import (
	"bytes"
	"net"
	"slices"
	"testing"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/protocol"
)

func TestReject(t *testing.T) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	a, b := net.Pipe()
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()

	go func() {
		protocol.Reject("5", a, protocol.FailReply, pool)
		_ = a.Close()
	}()

	msg := []byte{}
	buf := make([]byte, 1024)

	for {
		n, err := b.Read(buf)
		if err != nil {
			break
		}
		msg = append(msg, buf[:n]...)
	}

	exp := []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}

	if !slices.Equal(exp, msg) {
		t.Fatal(msg)
	}
}

func TestReply(t *testing.T) {
	tests := []struct {
		name     string
		ver      string
		stat     protocol.ReplyStatus
		addr     protocol.Addr
		expected []byte
		errMsg   string
	}{
		{
			name: "5 IPv4 SuccReply",
			ver:  "5",
			stat: protocol.SuccReply,
			addr: protocol.AddrFromIP(net.ParseIP("192.168.1.1"), 8080, ""),
			expected: []byte{
				0x05,           // SOCKS version
				0x00,           // Status
				0x00,           // Reserved
				0x01,           // IPv4 address type
				192, 168, 1, 1, // IP address
				0x1F, 0x90, // Port 8080
			},
		},
		{
			name: "5 IPv6 Fail",
			ver:  "5",
			stat: protocol.FailReply,
			addr: protocol.AddrFromIP(net.ParseIP("2001:db8::1"), 443, ""),
			expected: []byte{
				0x05,                   // SOCKS version
				0x01,                   // Stataus
				0x00,                   // Reserved
				0x04,                   // IPv6 address type
				0x20, 0x01, 0x0d, 0xb8, // IPv6 address
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,
				0x01, 0xBB, // Port 443
			},
		},
		{
			name: "5 FQDN Fail",
			ver:  "5",
			stat: protocol.FailReply,
			addr: protocol.AddrFromFQDN("example.com", 80, ""),
			expected: []byte{
				0x05, // SOCKS version
				0x01, // Status
				0x00, // Reserved
				0x03, // Domain name address type
				11,   // Domain name length
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				0x00, 0x50, // Port 80
			},
		},
		{
			name:   "5 FQDN TooLongHost",
			ver:    "5",
			stat:   protocol.FailReply,
			addr:   protocol.AddrFromFQDN(string(make([]byte, 512)), 80, ""),
			errMsg: protocol.ErrTooLongHost.Error(),
		},
		{
			name: "4 Granted",
			ver:  "4",
			stat: protocol.Granted,
			addr: protocol.AddrFromIP(net.IPv4(192, 168, 1, 100), 1080, ""),
			expected: []byte{
				0,                      // Reply version
				byte(protocol.Granted), // Command (90 = granted)
				4, 56,                  // Port 1080 (0x0438)
				192, 168, 1, 100, // IP address
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			a, b := net.Pipe()
			defer func() {
				_ = a.Close()
				_ = b.Close()
			}()

			errch := make(chan error, 1)

			go func() {
				err := protocol.Reply(tt.ver, a, tt.stat, tt.addr, pool)
				_ = a.Close()
				errch <- err
			}()

			got := []byte{}
			buf := make([]byte, 1024)

			for {
				n, err := b.Read(buf)
				if err != nil {
					break
				}
				got = append(got, buf[:n]...)
			}

			err := <-errch

			if tt.errMsg != "" {
				if err == nil {
					t.Errorf("Reply() expected error, got nil")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf(
						"Reply() error = %v, want containing %v",
						err,
						tt.errMsg,
					)
				}
				return
			}

			if err != nil {
				t.Errorf("BuildSocks5TCPReply() unexpected error: %v", err)
				return
			}

			if !bytes.Equal(got, tt.expected) {
				t.Errorf(
					"BuildSocks5TCPReply() = %v, want %v",
					got,
					tt.expected,
				)
			}
		})
	}
}
