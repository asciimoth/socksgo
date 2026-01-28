package protocol_test

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/protocol"
)

func TestBuildSocks5TCPRequest(t *testing.T) {
	tests := []struct {
		name     string
		cmd      protocol.Cmd
		addr     protocol.Addr
		wantErr  bool
		errMsg   string
		expected []byte
	}{
		{
			name: "IPv4 Connect command",
			cmd:  protocol.CmdConnect,
			addr: protocol.AddrFromIP(net.ParseIP("192.168.1.1"), 8080, ""),
			expected: []byte{
				0x05,           // SOCKS version
				0x01,           // CONNECT command
				0x00,           // Reserved
				0x01,           // IPv4 address type
				192, 168, 1, 1, // IP address
				0x1F, 0x90, // Port 8080
			},
		},
		{
			name: "IPv6 Bind command",
			cmd:  protocol.CmdBind,
			addr: protocol.AddrFromIP(net.ParseIP("2001:db8::1"), 443, ""),
			expected: []byte{
				0x05,                   // SOCKS version
				0x02,                   // BIND command
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
			name: "FQDN with reasonable length",
			cmd:  protocol.CmdUDPAssoc,
			addr: protocol.AddrFromFQDN("example.com", 80, ""),
			expected: []byte{
				0x05, // SOCKS version
				0x03, // UDP ASSOCIATE command
				0x00, // Reserved
				0x03, // Domain name address type
				11,   // Domain name length
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				0x00, 0x50, // Port 80
			},
		},
		{
			name: "FQDN with special characters",
			cmd:  protocol.CmdConnect,
			addr: protocol.AddrFromFQDN("sub-domain.example.co.uk", 443, ""),
			expected: []byte{
				0x05, // SOCKS version
				0x01, // CONNECT command
				0x00, // Reserved
				0x03, // Domain name address type
				24,   // Domain name length
				's', 'u', 'b', '-', 'd', 'o', 'm', 'a', 'i', 'n',
				'.', 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				'.', 'c', 'o', '.', 'u', 'k',
				0x01, 0xBB, // Port 443
			},
		},
		{
			name:    "FQDN too long should error",
			cmd:     protocol.CmdConnect,
			addr:    protocol.AddrFromFQDN(string(make([]byte, 256)), 80, ""),
			wantErr: true,
			errMsg:  "host name is too long",
		},
		{
			name: "Localhost IPv4",
			cmd:  protocol.CmdConnect,
			addr: protocol.AddrFromIP(net.ParseIP("127.0.0.1"), 1080, ""),
			expected: []byte{
				0x05,         // SOCKS version
				0x01,         // CONNECT command
				0x00,         // Reserved
				0x01,         // IPv4 address type
				127, 0, 0, 1, // IP address
				0x04, 0x38, // Port 1080
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			got, err := protocol.BuildSocks5TCPRequest(tt.cmd, tt.addr, pool)
			defer bufpool.PutBuffer(pool, got)

			if tt.wantErr {
				if err == nil {
					t.Errorf("BuildSocks5TCPRequest() expected error, got nil")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf(
						"BuildSocks5TCPRequest() error = %v, want containing %v",
						err,
						tt.errMsg,
					)
				}
				return
			}

			if err != nil {
				t.Errorf("BuildSocks5TCPRequest() unexpected error: %v", err)
				return
			}

			if !bytes.Equal(got, tt.expected) {
				t.Errorf(
					"BuildSocks5TCPRequest() = %v, want %v",
					got,
					tt.expected,
				)
			}
		})
	}
}

func TestReadSocks5TCPRequest(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte // Data WITHOUT the first version byte
		wantCmd  protocol.Cmd
		wantAddr string // Using Addr.String() format for comparison
		wantErr  bool
	}{
		{
			name: "IPv4 Connect request",
			data: []byte{
				0x05, // SOCKS version
				0x01, // CONNECT command
				0x00, // Reserved
				0x01, // IPv4 address type
				192, 168, 1, 1,
				0x1F, 0x90, // Port 8080
			},
			wantCmd:  protocol.CmdConnect,
			wantAddr: "192.168.1.1:8080",
		},
		{
			name: "IPv6 Bind request",
			data: []byte{
				0x05, // SOCKS version
				0x02, // BIND command
				0x00, // Reserved
				0x04, // IPv6 address type
				0x20, 0x01, 0x0d, 0xb8,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,
				0x01, 0xBB, // Port 443
			},
			wantCmd:  protocol.CmdBind,
			wantAddr: "[2001:db8::1]:443",
		},
		{
			name: "FQDN UDP Associate request",
			data: []byte{
				0x05, // SOCKS version
				0x03, // UDP ASSOCIATE command
				0x00, // Reserved
				0x03, // Domain name address type
				11,   // Domain name length
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				0x00, 0x50, // Port 80
			},
			wantCmd:  protocol.CmdUDPAssoc,
			wantAddr: "example.com:80",
		},
		{
			name: "Empty FQDN",
			data: []byte{
				0x05,       // SOCKS version
				0x01,       // CONNECT command
				0x00,       // Reserved
				0x03,       // Domain name address type
				0,          // Domain name length
				0x04, 0x38, // Port 1080
			},
			wantCmd:  protocol.CmdConnect,
			wantAddr: ":1080", // Empty host
		},
		{
			name: "Invalid address type",
			data: []byte{
				0x05, // SOCKS version
				0x01, // CONNECT command
				0x00, // Reserved
				0xFF, // Invalid address type
				192, 168, 1, 1,
				0x1F, 0x90,
			},
			wantErr: true,
		},
		{
			name: "Incomplete IPv4 data",
			data: []byte{
				0x05,        // SOCKS version
				0x01,        // CONNECT command
				0x00,        // Reserved
				0x01,        // IPv4 address type
				192, 168, 1, // Missing one byte of IP and port
			},
			wantErr: true,
		},
		{
			name: "Incomplete FQDN length byte",
			data: []byte{
				0x05, // SOCKS version
				0x01, // CONNECT command
				0x00, // Reserved
				0x03, // Domain name address type
				// Missing length byte and rest
			},
			wantErr: true,
		},
		{
			name: "Reserved byte should be ignored",
			data: []byte{
				0x05, // SOCKS version
				0x01, // CONNECT command
				0xFF, // Reserved (non-zero, should be ignored)
				0x01, // IPv4 address type
				127, 0, 0, 1,
				0x04, 0x38, // Port 1080
			},
			wantCmd:  protocol.CmdConnect,
			wantAddr: "127.0.0.1:1080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			reader := bytes.NewReader(tt.data)
			cmd, addr, err := protocol.ReadSocks5TCPRequest(reader, pool)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ReadSocks5TCPRequest() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ReadSocks5TCPRequest() unexpected error: %v", err)
				return
			}

			if cmd != tt.wantCmd {
				t.Errorf(
					"ReadSocks5TCPRequest() cmd = %v, want %v",
					cmd,
					tt.wantCmd,
				)
			}

			if addr.String() != tt.wantAddr {
				t.Errorf(
					"ReadSocks5TCPRequest() addr = %v, want %v",
					addr.String(),
					tt.wantAddr,
				)
			}
		})
	}
}

func TestBuildAndReadRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		cmd  protocol.Cmd
		addr protocol.Addr
	}{
		{
			name: "IPv4 round trip",
			cmd:  protocol.CmdConnect,
			addr: protocol.AddrFromIP(net.ParseIP("8.8.8.8"), 53, ""),
		},
		{
			name: "IPv6 round trip",
			cmd:  protocol.CmdUDPAssoc,
			addr: protocol.AddrFromIP(
				net.ParseIP("2001:4860:4860::8888"),
				53,
				"",
			),
		},
		{
			name: "FQDN round trip",
			cmd:  protocol.CmdBind,
			addr: protocol.AddrFromFQDN("google.com", 443, ""),
		},
		{
			name: "FQDN with maximum length",
			cmd:  protocol.CmdConnect,
			// Assuming MAX_HEADER_STR_LENGTH is 255
			addr: protocol.AddrFromFQDN(string(make([]byte, 255)), 8080, ""),
		},
		{
			name: "Localhost IPv4",
			cmd:  protocol.CmdConnect,
			addr: protocol.AddrFromIP(net.ParseIP("127.0.0.1"), 1080, ""),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			// Build the request
			request, err := protocol.BuildSocks5TCPRequest(
				tc.cmd,
				tc.addr,
				pool,
			)
			if err != nil {
				t.Fatalf("BuildSocks5TCPRequest failed: %v", err)
			}
			defer bufpool.PutBuffer(pool, request)

			// Read it back
			if len(request) < 1 {
				t.Fatal("Request too short")
			}
			reader := bytes.NewReader(request)
			cmd, addr, err := protocol.ReadSocks5TCPRequest(reader, nil)
			if err != nil {
				t.Fatalf("ReadSocks5TCPRequest failed: %v", err)
			}

			// Compare results
			if cmd != tc.cmd {
				t.Errorf("Command mismatch: got %v, want %v", cmd, tc.cmd)
			}

			// Compare addresses using String() method as requested
			if addr.String() != tc.addr.String() {
				t.Errorf(
					"Address mismatch: got %v, want %v",
					addr.String(),
					tc.addr.String(),
				)
			}
		})
	}
}

func TestReadWithPartialData(t *testing.T) {
	// Create a broken reader that returns EOF early
	brokenReader := &io.LimitedReader{
		R: bytes.NewReader([]byte{0x01, 0x00, 0x01}),
		N: 2,
	}

	_, _, err := protocol.ReadSocks5TCPRequest(brokenReader, nil)
	if err == nil {
		t.Error("Expected error with partial data, got nil")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

func TestBuildSocks5TCPReply(t *testing.T) {
	tests := []struct {
		name     string
		stat     protocol.ReplyStatus
		addr     protocol.Addr
		wantErr  bool
		errMsg   string
		expected []byte
	}{
		{
			name: "IPv4 SuccReply",
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
			name: "IPv6 Fail",
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
			name: "FQDN Fail",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			got, err := protocol.BuildSocks5TCPReply(tt.stat, tt.addr, pool)
			defer bufpool.PutBuffer(pool, got)

			if tt.wantErr {
				if err == nil {
					t.Errorf("BuildSocks5TCPReply() expected error, got nil")
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf(
						"BuildSocks5TCPReply() error = %v, want containing %v",
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

func TestReadSocks5TCPReply(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte // Data WITHOUT the first version byte
		wantReply protocol.ReplyStatus
		wantAddr  string // Using Addr.String() format for comparison
		wantErr   bool
	}{
		{
			name: "IPv4 Granted",
			data: []byte{
				0x05, // SOCKS version
				90,   // Granted
				0x00, // Reserved
				0x01, // IPv4 address type
				192, 168, 1, 1,
				0x1F, 0x90, // Port 8080
			},
			wantReply: protocol.SuccReply,
			wantAddr:  "192.168.1.1:8080",
		},
		{
			name: "IPv6 SuccReply",
			data: []byte{
				0x05, // SOCKS version
				0x00, // SuccReply
				0x00, // Reserved
				0x04, // IPv6 address type
				0x20, 0x01, 0x0d, 0xb8,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x01,
				0x01, 0xBB, // Port 443
			},
			wantReply: protocol.SuccReply,
			wantAddr:  "[2001:db8::1]:443",
		},
		{
			name: "FQDN Fail",
			data: []byte{
				0x05, // SOCKS version
				0x01, // Fail
				0x00, // Reserved
				0x03, // Domain name address type
				11,   // Domain name length
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				0x00, 0x50, // Port 80
			},
			wantReply: protocol.FailReply,
			wantAddr:  "example.com:80",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			reader := bytes.NewReader(tt.data)
			rply, addr, err := protocol.ReadSocks5TCPReply(reader, pool)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ReadSocks5TCPReply() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ReadSocks5TCPReply() unexpected error: %v", err)
				return
			}

			if rply != tt.wantReply {
				t.Errorf(
					"ReadSocks5TCPReply() cmd = %v, want %v",
					rply,
					tt.wantReply,
				)
			}

			if addr.String() != tt.wantAddr {
				t.Errorf(
					"ReadSocks5TCPReply() addr = %v, want %v",
					addr.String(),
					tt.wantAddr,
				)
			}
		})
	}
}

func TestReadSocks5TCPRequestErrors(t *testing.T) {
	t.Run("Wrong Ver", func(t *testing.T) {
		pool := bufpool.NewTestDebugPool(t)
		defer pool.Close()

		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			defer func() { _ = b.Close() }()
			_, _ = io.Copy(b, bytes.NewReader([]byte{42, 42, 42, 42}))
		}()
		go func() {
			for {
				_, err := b.Read([]byte{0})
				if err != nil {
					return
				}
			}
		}()
		_, _, err := protocol.ReadSocks5TCPRequest(a, pool)
		exp := protocol.WrongProtocolVerError{42}
		if err.Error() != exp.Error() {
			t.Fatal(err)
		}
	})
	t.Run("IPv6 read err", func(t *testing.T) {
		pool := bufpool.NewTestDebugPool(t)
		defer pool.Close()

		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			defer func() { _ = b.Close() }()
			_, _ = io.Copy(b, bytes.NewReader([]byte{
				0x05, // SOCKS version
				0x02, // BIND command
				0x00, // Reserved
				0x04, // Partial IPv6 address
				0x20, 0x01, 0x0d, 0xb8,
				0x00, 0x00, 0x00, 0x00,
			}))
		}()
		go func() {
			for {
				_, err := b.Read([]byte{0})
				if err != nil {
					return
				}
			}
		}()
		_, _, err := protocol.ReadSocks5TCPRequest(a, pool)
		if !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("got %s while expecting EOF", err)
		}
	})
	t.Run("FQDN read err", func(t *testing.T) {
		pool := bufpool.NewTestDebugPool(t)
		defer pool.Close()

		a, b := net.Pipe()
		defer func() {
			_ = a.Close()
			_ = b.Close()
		}()
		go func() {
			defer func() { _ = b.Close() }()
			_, _ = io.Copy(b, bytes.NewReader([]byte{
				0x05,                              // SOCKS version
				0x03,                              // UDP ASSOCIATE command
				0x00,                              // Reserved
				0x03,                              // Domain name address type
				11,                                // Domain name length
				'e', 'x', 'a', 'm', 'p', 'l', 'e', // Partial fqdn
			}))
		}()
		go func() {
			for {
				_, err := b.Read([]byte{0})
				if err != nil {
					return
				}
			}
		}()
		_, _, err := protocol.ReadSocks5TCPRequest(a, pool)
		if !strings.Contains(err.Error(), "EOF") {
			t.Fatalf("got %s while expecting EOF", err)
		}
	})
}
