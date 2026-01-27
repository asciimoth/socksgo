package protocol_test

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/protocol"
)

func TestBuildSocks4TCPRequest(t *testing.T) {
	tests := []struct {
		name        string
		cmd         protocol.Cmd
		addr        protocol.Addr
		user        string
		expected    []byte
		expectedErr string
	}{
		{
			name: "SOCKS4 IPv4 connect",
			cmd:  protocol.CmdConnect,
			addr: protocol.AddrFromIP(net.IPv4(192, 168, 1, 1), 1080, ""),
			user: "testuser",
			expected: []byte{
				4,     // SOCKS version
				1,     // CmdConnect
				4, 56, // Port 1080 (0x0438)
				192, 168, 1, 1, // IP address
				't', 'e', 's', 't', 'u', 's', 'e', 'r', // Username
				0, // Null terminator
			},
		},
		{
			name: "SOCKS4 IPv4 bind",
			cmd:  protocol.CmdBind,
			addr: protocol.AddrFromIP(net.IPv4(10, 0, 0, 1), 8080, ""),
			user: "",
			expected: []byte{
				4,       // SOCKS version
				2,       // CmdBind
				31, 144, // Port 8080 (0x1F90)
				10, 0, 0, 1, // IP address
				0, // Null terminator (empty username)
			},
		},
		{
			name: "SOCKS4a FQDN connect",
			cmd:  protocol.CmdConnect,
			addr: protocol.AddrFromFQDN("example.com", 443, ""),
			user: "alice",
			expected: []byte{
				4,      // SOCKS version
				1,      // CmdConnect
				1, 187, // Port 443 (0x01BB)
				0, 0, 0, 1, // SOCKS4a identifier (0.0.0.1)
				'a', 'l', 'i', 'c', 'e', // Username
				0,                                      // Null terminator for username
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', // Hostname
				'c', 'o', 'm',
				0, // Null terminator for hostname
			},
		},
		{
			name: "SOCKS4a FQDN bind with long username",
			cmd:  protocol.CmdBind,
			addr: protocol.AddrFromFQDN("sub.domain.co.uk", 80, ""),
			user: "verylongusername",
			expected: []byte{
				4,     // SOCKS version
				2,     // CmdBind
				0, 80, // Port 80 (0x0050)
				0, 0, 0, 1, // SOCKS4a identifier
				'v', 'e', 'r', 'y', 'l', 'o', 'n', 'g', 'u', 's', 'e', 'r', 'n', 'a', 'm', 'e',
				0, // Null terminator for username
				's', 'u', 'b', '.', 'd', 'o', 'm', 'a', 'i', 'n', '.', 'c', 'o', '.', 'u', 'k',
				0, // Null terminator for hostname
			},
		},
		{
			name: "Too long FQDN addr",
			cmd:  protocol.CmdConnect,
			addr: protocol.AddrFromFQDN(
				string(make([]byte, 300)),
				80,
				"",
			),
			expectedErr: "socks host name is too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			got, err := protocol.BuildSocsk4TCPRequest(
				tt.cmd,
				tt.addr,
				tt.user,
				pool,
			)
			defer bufpool.PutBuffer(pool, got)

			if err != nil && tt.expectedErr == "" {
				t.Errorf("unexpected error %v", err)
			}

			if tt.expectedErr != "" {
				if tt.expectedErr == err.Error() {
					return
				} else {
					t.Errorf("wrong error %v", err)
				}
			}

			if !bytes.Equal(got, tt.expected) {
				t.Errorf(
					"BuildSocsk4TCPRequest() = %v, want %v",
					got,
					tt.expected,
				)
			}

			// Verify buffer is properly sized
			if len(got) != len(tt.expected) {
				t.Errorf(
					"BuildSocsk4TCPRequest() length = %d, want %d",
					len(got),
					len(tt.expected),
				)
			}
		})
	}
}

func TestReadSocks4TCPRequest(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantCmd     protocol.Cmd
		wantAddr    string
		wantUser    string
		expectError bool
	}{
		{
			name: "SOCKS4 IPv4 connect",
			data: []byte{
				1,     // CmdConnect (version already read)
				4, 56, // Port 1080
				192, 168, 1, 1, // IP address
				't', 'e', 's', 't', 'u', 's', 'e', 'r',
				0, // Null terminator
			},
			wantCmd:  protocol.CmdConnect,
			wantAddr: "192.168.1.1:1080",
			wantUser: "testuser",
		},
		{
			name: "SOCKS4 IPv4 bind with empty username",
			data: []byte{
				2,       // CmdBind
				31, 144, // Port 8080
				10, 0, 0, 1, // IP address
				0, // Empty username
			},
			wantCmd:  protocol.CmdBind,
			wantAddr: "10.0.0.1:8080",
			wantUser: "",
		},
		{
			name: "SOCKS4a FQDN connect",
			data: []byte{
				1,      // CmdConnect
				1, 187, // Port 443
				0, 0, 0, 1, // SOCKS4a identifier
				'a', 'l', 'i', 'c', 'e',
				0, // Null terminator for username
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.',
				'c', 'o', 'm',
				0, // Null terminator for hostname
			},
			wantCmd:  protocol.CmdConnect,
			wantAddr: "example.com:443",
			wantUser: "alice",
		},
		{
			name: "SOCKS4a FQDN bind with special chars in username",
			data: []byte{
				2,     // CmdBind
				0, 80, // Port 80
				0, 0, 0, 1, // SOCKS4a identifier
				'u', 's', 'e', 'r', '-', '_', '1', '2', '3',
				0, // Null terminator for username
				's', 'u', 'b', '.', 'd', 'o', 'm', 'a', 'i', 'n', '.', 'c', 'o', '.', 'u', 'k',
				0, // Null terminator for hostname
			},
			wantCmd:  protocol.CmdBind,
			wantAddr: "sub.domain.co.uk:80",
			wantUser: "user-_123",
		},
		{
			name: "SOCKS4a Too long user",
			data: func() []byte {
				ret := []byte{ //nolint
					2,     // CmdBind
					0, 80, // Port 80
					0, 0, 0, 1, // SOCKS4a identifier
				}

				for range 512 {
					ret = append(ret, []byte("a")...)
				}

				ret = append(
					ret,
					0, // Null terminator for username
					's',
					'u',
					'b',
					'.',
					'd',
					'o',
					'm',
					'a',
					'i',
					'n',
					'.',
					'c',
					'o',
					'.',
					'u',
					'k',
					0, // Null terminator for hostname
				)

				return ret
			}(),
			expectError: true,
		},
		{
			name: "SOCKS4 Too long user",
			data: func() []byte {
				ret := []byte{ //nolint
					2,     // CmdBind
					0, 80, // Port 80
					127, 0, 0, 1,
				}

				for range 512 {
					ret = append(ret, []byte("a")...)
				}

				ret = append(ret,
					0, // Null terminator for username
				)

				return ret
			}(),
			expectError: true,
		},
		{
			name: "SOCKS4a Too long host",
			data: func() []byte {
				ret := []byte{ //nolint
					2,     // CmdBind
					0, 80, // Port 80
					0, 0, 0, 1, // SOCKS4a identifier
					'a', 0, // Username
				}

				for range 512 {
					ret = append(ret, []byte("a")...)
				}

				return ret
			}(),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			reader := bytes.NewReader(tt.data)
			gotCmd, gotAddr, gotUser, err := protocol.ReadSocks4TCPRequest(
				reader,
				pool,
			)

			if tt.expectError {
				if err == nil {
					t.Errorf("ReadSocks4TCPRequest() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("ReadSocks4TCPRequest() unexpected error: %v", err)
				return
			}

			if gotCmd != tt.wantCmd {
				t.Errorf(
					"ReadSocks4TCPRequest() cmd = %v, want %v",
					gotCmd,
					tt.wantCmd,
				)
			}

			if gotAddr.String() != tt.wantAddr {
				t.Errorf(
					"ReadSocks4TCPRequest() addr = %v, want %v",
					gotAddr.String(),
					tt.wantAddr,
				)
			}

			if gotUser != tt.wantUser {
				t.Errorf(
					"ReadSocks4TCPRequest() user = %v, want %v",
					gotUser,
					tt.wantUser,
				)
			}
		})
	}
}

func TestBuildAndReadSocks4TCPRequest_RoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		cmd  protocol.Cmd
		addr protocol.Addr
		user string
	}{
		{
			name: "IPv4 connect",
			cmd:  protocol.CmdConnect,
			addr: protocol.AddrFromIP(net.IPv4(8, 8, 8, 8), 53, ""),
			user: "dnsuser",
		},
		{
			name: "IPv4 bind",
			cmd:  protocol.CmdBind,
			addr: protocol.AddrFromIP(net.IPv4(127, 0, 0, 1), 9090, ""),
			user: "",
		},
		{
			name: "SOCKS4a FQDN connect",
			cmd:  protocol.CmdConnect,
			addr: protocol.AddrFromFQDN("api.github.com", 443, ""),
			user: "gituser",
		},
		{
			name: "SOCKS4a FQDN bind",
			cmd:  protocol.CmdBind,
			addr: protocol.AddrFromFQDN("localhost", 3000, ""),
			user: "dev",
		},
		{
			name: "Long username and hostname",
			cmd:  protocol.CmdConnect,
			addr: protocol.AddrFromFQDN(
				"very-long-subdomain.example-domain.co.uk",
				8443,
				"",
			),
			user: "user_with_underscores_and.dots",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			// Build the request
			request, err := protocol.BuildSocsk4TCPRequest(
				tc.cmd,
				tc.addr,
				tc.user,
				pool,
			)
			defer bufpool.PutBuffer(pool, request)

			if err != nil {
				t.Errorf("unexpected error %v", err)
			}

			// Skip the first byte (version) as ReadSocks4TCPRequest expects
			reader := bytes.NewReader(request[1:])

			// Read the request
			readCmd, readAddr, readUser, err := protocol.ReadSocks4TCPRequest(
				reader,
				pool,
			)
			if err != nil {
				t.Errorf("ReadSocks4TCPRequest() failed: %v", err)
				return
			}

			// Compare results
			if readCmd != tc.cmd {
				t.Errorf("Cmd mismatch: got %v, want %v", readCmd, tc.cmd)
			}

			if readAddr.String() != tc.addr.String() {
				t.Errorf(
					"Addr mismatch: got %v, want %v",
					readAddr.String(),
					tc.addr.String(),
				)
			}

			if readUser != tc.user {
				t.Errorf("User mismatch: got %v, want %v", readUser, tc.user)
			}
		})
	}
}

func TestReadSocks4TCPRequest_ErrorCases(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "Incomplete header",
			data: []byte{1, 0, 80}, // Missing bytes
		},
		{
			name: "Missing username terminator",
			data: []byte{
				1,     // CmdConnect
				0, 80, // Port 80
				192, 168, 1, 1, // IP
				'u', 's', 'e', 'r', // No null terminator
			},
		},
		{
			name: "SOCKS4a missing hostname terminator",
			data: []byte{
				1,     // CmdConnect
				0, 80, // Port 80
				0, 0, 0, 1, // SOCKS4a identifier
				'u', 's', 'e', 'r',
				0,                  // Username terminator
				'h', 'o', 's', 't', // No null terminator
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			reader := bytes.NewReader(tt.data)
			_, _, _, err := protocol.ReadSocks4TCPRequest(reader, pool)

			if err == nil {
				t.Errorf("ReadSocks4TCPRequest() expected error, got nil")
			}
		})
	}
}

func TestBuildSocks4TCPReply(t *testing.T) {
	tests := []struct {
		name     string
		cmd      protocol.ReplyStatus
		addr     protocol.Addr
		expected []byte
	}{
		{
			name: "Granted reply with IPv4",
			cmd:  protocol.Granted,
			addr: protocol.AddrFromIP(net.IPv4(192, 168, 1, 100), 1080, ""),
			expected: []byte{
				0,                      // Reply version
				byte(protocol.Granted), // Command (90 = granted)
				4, 56,                  // Port 1080 (0x0438)
				192, 168, 1, 100, // IP address
			},
		},
		{
			name: "Failed reply with IPv4",
			cmd:  protocol.Rejected,
			addr: protocol.AddrFromIP(net.IPv4(10, 0, 0, 1), 8080, ""),
			expected: []byte{
				0,                       // Reply version
				byte(protocol.Rejected), // Command (91 = rejected)
				31, 144,                 // Port 8080 (0x1F90)
				10, 0, 0, 1, // IP address
			},
		},
		{
			name: "Reply with loopback address",
			cmd:  protocol.Granted,
			addr: protocol.AddrFromIP(net.IPv4(127, 0, 0, 1), 3000, ""),
			expected: []byte{
				0,                      // Reply version
				byte(protocol.Granted), // Command
				11, 184,                // Port 3000 (0x0BB8)
				127, 0, 0, 1, // Loopback IP
			},
		},
		{
			name: "Reply with non IP address",
			cmd:  protocol.Granted,
			addr: protocol.Addr{
				Type: protocol.FQDNAddr,
				Host: []byte("example.com"),
				Port: 3000,
			},
			expected: []byte{
				0,                      // Reply version
				byte(protocol.Granted), // Command
				11, 184,                // Port 3000 (0x0BB8)
				0, 0, 0, 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			got := protocol.BuildSocks4TCPReply(tt.cmd, tt.addr, pool)
			defer bufpool.PutBuffer(pool, got)

			if !bytes.Equal(got, tt.expected) {
				t.Errorf(
					"BuildSocsk4TCPReply() = %v, want %v",
					got,
					tt.expected,
				)
			}

			if len(got) != len(tt.expected) {
				t.Errorf(
					"BuildSocsk4TCPReply() length = %d, want %d",
					len(got),
					len(tt.expected),
				)
			}

			// Verify first byte is version 0
			if got[0] != 0 {
				t.Errorf("BuildSocsk4TCPReply() version = %d, want 0", got[0])
			}
		})
	}
}

func TestReadSocks4TCPReply(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantAddr string
		errorMsg string
	}{
		{
			name: "Successful Granted reply",
			data: []byte{
				0,                      // Reply version
				byte(protocol.Granted), // Granted (90)
				4, 56,                  // Port 1080
				192, 168, 1, 100, // IP address
			},
			wantAddr: "192.168.1.100:1080",
		},
		{
			name: "Successful Granted reply with 0.0.0.0",
			data: []byte{
				0,                      // Reply version
				byte(protocol.Granted), // Granted (90)
				1, 187,                 // Port 443
				0, 0, 0, 0, // 0.0.0.0
			},
			wantAddr: "0.0.0.0:443",
		},
		{
			name:     "Read error",
			data:     []byte{},
			errorMsg: "EOF",
		},
		{
			name: "Wrontg reply ver",
			data: []byte{
				42,                     // Reply version
				byte(protocol.Granted), // Granted (90)
				1, 187,                 // Port 443
				0, 0, 0, 0, // 0.0.0.0
			},
			errorMsg: "wrong socks4 reply version 42, should be 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.data)
			_, addr, err := protocol.ReadSocks4TCPReply(reader)

			if tt.errorMsg != "" {
				if err == nil {
					t.Errorf("ReadSocks4TCPReply() expected error, got nil")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf(
						"ReadSocks4TCPReply() error = %v, want error containing %q",
						err,
						tt.errorMsg,
					)
				}
				return
			}

			if err != nil {
				t.Errorf("ReadSocks4TCPReply() unexpected error: %v", err)
				return
			}

			if addr.String() != tt.wantAddr {
				t.Errorf(
					"ReadSocks4TCPReply() addr = %v, want %v",
					addr.String(),
					tt.wantAddr,
				)
			}
		})
	}
}

func TestBuildAndReadSocks4TCPReply_RoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		cmd  protocol.ReplyStatus
		addr protocol.Addr
	}{
		{
			name: "Granted with public IP",
			cmd:  protocol.Granted,
			addr: protocol.AddrFromIP(net.IPv4(8, 8, 4, 4), 53, ""),
		},
		{
			name: "Granted with private IP",
			cmd:  protocol.Granted,
			addr: protocol.AddrFromIP(net.IPv4(192, 168, 1, 10), 1080, ""),
		},
		{
			name: "Granted with 0.0.0.0",
			cmd:  protocol.Granted,
			addr: protocol.AddrFromIP(net.IPv4(0, 0, 0, 0), 0, ""),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close()

			// Build the reply
			reply := protocol.BuildSocks4TCPReply(tc.cmd, tc.addr, pool)
			defer bufpool.PutBuffer(pool, reply)

			// Read the reply (note: ReadSocks4TCPReply reads the entire reply, including version byte)
			reader := bytes.NewReader(reply)
			_, addr, err := protocol.ReadSocks4TCPReply(reader)

			// For non-Granted status codes, we expect an error
			if tc.cmd != protocol.Granted { //nolint netif
				if err == nil {
					t.Errorf(
						"ReadSocks4TCPReply() expected error for cmd %v, got nil",
						tc.cmd,
					)
				}
				// Verify the error message contains the expected status string
				if err != nil &&
					!strings.Contains(err.Error(), tc.cmd.String()) {
					t.Errorf(
						"ReadSocks4TCPReply() error = %v, want error containing %q",
						err,
						tc.cmd.String(),
					)
				}
			} else {
				// For Granted, verify the address matches
				if err != nil {
					t.Errorf("ReadSocks4TCPReply() unexpected error: %v", err)
					return
				}

				// Compare the address strings
				// Note: BuildSocsk4TCPReply converts non-IPv4 addresses to 0.0.0.0
				expectedIP := tc.addr.ToIP().To4()
				if expectedIP == nil {
					expectedIP = net.IPv4(0, 0, 0, 0).To4()
				}
				expectedAddr := protocol.AddrFromIP(expectedIP, tc.addr.Port, "").
					String()

				if addr.String() != expectedAddr {
					t.Errorf(
						"Addr mismatch: got %v, want %v",
						addr.String(),
						expectedAddr,
					)
				}
			}
		})
	}
}
