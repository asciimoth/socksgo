package internal_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/asciimoth/socksgo/internal"
)

func TestDialBlock(t *testing.T) {
	_, err := internal.DialBlock(context.Background(), "a", "b")
	if err.Error() != "BLOCKED" {
		t.Fatalf("got %s while BLOCKED expected", err)
	}
}

func TestNormalNet(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"tcp", "tcp", "tcp"},
		{"tcp4", "tcp4", "tcp"},
		{"tcp6", "tcp6", "tcp"},
		{"udp", "udp", "udp"},
		{"udp4", "udp4", "udp"},
		{"udp6", "udp6", "udp"},
		{"unknown", "unknown", "unknown"},
		{"unknown4", "unknown4", "unknown"},
		{"unknown6", "unknown6", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := internal.NormalNet(tt.input)
			if result != tt.expected {
				t.Errorf(
					"NormalNet(%q) = %q, want %q",
					tt.input,
					result,
					tt.expected,
				)
			}
		})
	}
}

func TestLookupPortOffline(t *testing.T) {
	tests := []struct {
		name    string
		network string
		service string
		wantErr bool
		errType string
	}{
		{"known tcp service", "tcp", "http", true, "DNSError"},
		{"known udp service", "udp", "domain", true, "DNSError"},
		{"unknown service", "tcp", "nonexistent", true, "DNSError"},
		{"empty service", "tcp", "", true, "DNSError"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, err := internal.LookupPortOffline(tt.network, tt.service)

			if tt.wantErr && err != nil { //nolint
				if dnsErr, ok := err.(*net.DNSError); ok { //nolint
					if !dnsErr.IsNotFound {
						t.Error("expected IsNotFound = true")
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if port < 0 || port > 65535 {
					t.Errorf("port %d out of range", port)
				}
			}
		})
	}
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		name      string
		network   string
		hostport  string
		defport   uint16
		expectedH string
		expectedP uint16
	}{
		// Valid host:port combinations
		{"ipv4 with port", "tcp", "192.168.1.1:8080", 80, "192.168.1.1", 8080},
		{"ipv6 with port", "tcp", "[::1]:8080", 80, "::1", 8080},
		{
			"hostname with port",
			"tcp",
			"example.com:443",
			80,
			"example.com",
			443,
		},

		// No port, use default
		{"no port", "tcp", "example.com", 443, "example.com", 443},
		{"no port ipv4", "tcp", "192.168.1.1", 80, "192.168.1.1", 80},

		// Invalid port, use default
		{
			"invalid port number",
			"tcp",
			"example.com:99999",
			443,
			"example.com",
			443,
		},
		{"negative port", "tcp", "example.com:-1", 443, "example.com", 443},

		// Service name (should fail lookup and use default)
		{"service name", "tcp", "example.com:http", 8080, "example.com", 80},

		// Edge cases
		{"empty hostport", "tcp", "", 80, "", 80},
		{"only port", "tcp", ":8080", 80, "", 8080},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := internal.SplitHostPort(
				tt.network,
				tt.hostport,
				tt.defport,
			)
			if host != tt.expectedH {
				t.Errorf("host = %q, want %q", host, tt.expectedH)
			}
			if port != tt.expectedP {
				t.Errorf("port = %d, want %d", port, tt.expectedP)
			}
		})
	}
}

func TestReadNullTerminatedString(t *testing.T) {
	t.Run("valid string", func(t *testing.T) {
		data := []byte("hello\x00world")
		r := bytes.NewReader(data)
		buf := make([]byte, 10)

		str, err := internal.ReadNullTerminatedString(r, buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if str != "hello" {
			t.Errorf("got %q, want %q", str, "hello")
		}

		// Check remaining data
		remaining, _ := io.ReadAll(r)
		if string(remaining) != "world" {
			t.Errorf("remaining data = %q, want %q", remaining, "world")
		}
	})

	t.Run("empty string", func(t *testing.T) {
		data := []byte("\x00rest")
		r := bytes.NewReader(data)
		buf := make([]byte, 10)

		str, err := internal.ReadNullTerminatedString(r, buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if str != "" {
			t.Errorf("got %q, want empty string", str)
		}
	})

	t.Run("string too long", func(t *testing.T) {
		// Create a string longer than buffer capacity
		data := []byte("1234567890")
		r := bytes.NewReader(append(data, 0))
		buf := make([]byte, 5) // Capacity of 5

		_, err := internal.ReadNullTerminatedString(r, buf)
		if err != internal.ErrTooLongString { //nolint
			t.Errorf("got error %v, want ErrTooLongString", err)
		}
	})

	t.Run("read error", func(t *testing.T) {
		r := &errorReader{err: io.EOF}
		buf := make([]byte, 10)

		_, err := internal.ReadNullTerminatedString(r, buf)
		if err != io.EOF { //nolint
			t.Errorf("got error %v, want io.EOF", err)
		}
	})
}

// Helper type for testing read errors
type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, e.err
}

func TestCopyBytes(t *testing.T) {
	t.Run("nil slice", func(t *testing.T) {
		result := internal.CopyBytes(nil)
		if result != nil {
			t.Errorf("CopyBytes(nil) = %v, want nil", result)
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		src := []byte{}
		result := internal.CopyBytes(src)
		if len(result) != 0 {
			t.Errorf("len = %d, want 0", len(result))
		}
		if cap(result) != 0 {
			t.Errorf("cap = %d, want 0", cap(result))
		}
	})

	t.Run("non-empty slice", func(t *testing.T) {
		src := []byte{1, 2, 3, 4, 5}
		result := internal.CopyBytes(src)

		if len(result) != len(src) {
			t.Errorf("len = %d, want %d", len(result), len(src))
		}

		for i := range src {
			if result[i] != src[i] {
				t.Errorf("result[%d] = %d, want %d", i, result[i], src[i])
			}
		}

		// Ensure it's a copy
		src[0] = 99
		if result[0] == 99 {
			t.Error("modifying source modified the copy")
		}
	})
}

func TestClosedNetworkErrToNil(t *testing.T) {
	tests := []struct {
		name     string
		input    error
		expected error
	}{
		{
			name:     "use of closed network connection",
			input:    errors.New("use of closed network connection"),
			expected: nil,
		},
		{
			name:     "EOF",
			input:    io.EOF,
			expected: nil,
		},
		{
			name:     "io: read/write on closed pipe",
			input:    errors.New("io: read/write on closed pipe"),
			expected: nil,
		},
		{
			name: "wrapped closed network connection",
			input: &net.OpError{
				Err: errors.New("use of closed network connection"),
			},
			expected: nil,
		},
		{
			name:     "other error",
			input:    errors.New("some other error"),
			expected: errors.New("some other error"),
		},
		{
			name:     "nil error",
			input:    nil,
			expected: nil,
		},
		{
			name: "double wrapped error",
			input: &net.OpError{
				Err: &osMockError{msg: "use of closed network connection"},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := internal.ClosedNetworkErrToNil(tt.input)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("got %v, want nil", result)
				}
			} else {
				if result == nil || result.Error() != tt.expected.Error() {
					t.Errorf("got %v, want %v", result, tt.expected)
				}
			}
		})
	}
}

// Mock for os.Error
type osMockError struct {
	msg string
}

func (o *osMockError) Error() string {
	return o.msg
}

func (o *osMockError) Timeout() bool   { return false }
func (o *osMockError) Temporary() bool { return false }

func TestWaitForClose(t *testing.T) {
	t.Run("read returns error", func(t *testing.T) {
		rc := &mockReadCloser{
			reads: []readResult{{n: 0, err: io.EOF}},
		}

		internal.WaitForClose(rc)

		if !rc.closed {
			t.Error("reader was not closed")
		}
		if rc.readCount != 1 {
			t.Errorf("read called %d times, expected 1", rc.readCount)
		}
	})

	t.Run("multiple reads then error", func(t *testing.T) {
		rc := &mockReadCloser{
			reads: []readResult{
				{n: 1, err: nil},
				{n: 1, err: nil},
				{n: 0, err: io.EOF},
			},
		}

		internal.WaitForClose(rc)

		if !rc.closed {
			t.Error("reader was not closed")
		}
		if rc.readCount != 3 {
			t.Errorf("read called %d times, expected 3", rc.readCount)
		}
	})
}

type readResult struct {
	n   int
	err error
}

type mockReadCloser struct {
	reads     []readResult
	readCount int
	closed    bool
}

func (m *mockReadCloser) Read(b []byte) (int, error) {
	if m.readCount >= len(m.reads) {
		return 0, io.EOF
	}
	result := m.reads[m.readCount]
	m.readCount++
	return result.n, result.err
}

func (m *mockReadCloser) Close() error {
	m.closed = true
	return nil
}

func TestJoinNetErrors(t *testing.T) {
	tests := []struct {
		name     string
		a        error
		b        error
		expected error
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: nil,
		},
		{
			name:     "a nil, b nil after conversion",
			a:        nil,
			b:        io.EOF,
			expected: nil,
		},
		{
			name:     "a nil after conversion, b nil",
			a:        errors.New("use of closed network connection"),
			b:        nil,
			expected: nil,
		},
		{
			name:     "a error, b nil after conversion",
			a:        errors.New("error1"),
			b:        io.EOF,
			expected: errors.New("error1"),
		},
		{
			name:     "a nil after conversion, b error",
			a:        errors.New("use of closed network connection"),
			b:        errors.New("error2"),
			expected: errors.New("error2"),
		},
		{
			name:     "both errors",
			a:        errors.New("error1"),
			b:        errors.New("error2"),
			expected: errors.Join(errors.New("error1"), errors.New("error2")),
		},
		{
			name:     "both converted to nil",
			a:        io.EOF,
			b:        errors.New("io: read/write on closed pipe"),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := internal.JoinNetErrors(tt.a, tt.b)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("got %v, want nil", result)
				}
			} else {
				if result == nil {
					t.Error("got nil, want error")
				} else if result.Error() != tt.expected.Error() {
					t.Errorf("got %v, want %v", result, tt.expected)
				}
			}
		})
	}
}

func TestAddrsSameHost(t *testing.T) {
	tcpAddr1 := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}
	tcpAddr2 := &net.TCPAddr{IP: net.ParseIP("192.168.1.2"), Port: 80}
	tcpAddr3 := &net.TCPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8080,
	} // Same IP, different port
	udpAddr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}
	udpAddr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 80}

	tests := []struct {
		name     string
		a        net.Addr
		b        net.Addr
		expected bool
	}{
		{"same TCPAddr pointer", tcpAddr1, tcpAddr1, true},
		{"same TCPAddr IP", tcpAddr1, tcpAddr3, true},
		{"different TCPAddr IP", tcpAddr1, tcpAddr2, false},
		{"same UDPAddr IP", udpAddr1, udpAddr1, true},
		{"different UDPAddr IP", udpAddr1, udpAddr2, false},
		{"nil a", nil, tcpAddr1, false},
		{"nil b", tcpAddr1, nil, false},
		{"both nil", nil, nil, true},
		{
			"string addr same",
			&mockAddr{"192.168.1.1:80"},
			&mockAddr{"192.168.1.1:80"},
			true,
		},
		{
			"string addr different",
			&mockAddr{"192.168.1.1:80"},
			&mockAddr{"192.168.1.2:80"},
			false,
		},
		{
			"string addr with port same host",
			&mockAddr{"192.168.1.1:80"},
			&mockAddr{"192.168.1.1:443"},
			true,
		},
		{
			"string addr no port",
			&mockAddr{"192.168.1.1"},
			&mockAddr{"192.168.1.1"},
			true,
		},
		{
			"mixed string and TCP",
			&mockAddr{"192.168.1.1:80"},
			tcpAddr1,
			true,
		}, // Both represent same IP
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := internal.AddrsSameHost(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf(
					"AddrsSameHost(%v, %v) = %v, want %v",
					tt.a,
					tt.b,
					result,
					tt.expected,
				)
			}
		})
	}
}

func TestIpEqual(t *testing.T) {
	if !internal.IpEqual(nil, nil) {
		t.Fatal("nil IPs should be equal")
	}
	if internal.IpEqual(nil, net.IPv4zero) {
		t.Fatal("nil IP should not be equal to non nil one")
	}
	if internal.IpEqual(net.IPv4zero, nil) {
		t.Fatal("nil IP should not be equal to non nil one")
	}
}

type mockAddr struct {
	addr string
}

func (m *mockAddr) Network() string { return "mock" }
func (m *mockAddr) String() string  { return m.addr }

func TestAddrsEq(t *testing.T) {
	tcpAddr1 := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}
	tcpAddr2 := &net.TCPAddr{IP: net.ParseIP("192.168.1.2"), Port: 80}
	tcpAddr3 := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	tcpAddr4 := &net.TCPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 80,
		Zone: "zone",
	}
	udpAddr1 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}
	udpAddr2 := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80}

	tests := []struct {
		name     string
		a        net.Addr
		b        net.Addr
		expected bool
	}{
		{"same TCPAddr pointer", tcpAddr1, tcpAddr1, true},
		{
			"equal TCPAddr",
			&net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 80},
			tcpAddr1,
			true,
		},
		{"different TCPAddr port", tcpAddr1, tcpAddr3, false},
		{"different TCPAddr IP", tcpAddr1, tcpAddr2, false},
		{
			"TCPAddr with zone",
			tcpAddr1,
			tcpAddr4,
			true,
		}, // Zone comparison not implemented
		{"same UDPAddr", udpAddr1, udpAddr2, true},
		// {"TCPAddr vs UDPAddr", tcpAddr1, udpAddr1, false},
		{"nil a", nil, tcpAddr1, false},
		{"nil b", tcpAddr1, nil, false},
		{"both nil", nil, nil, true},
		{
			"string addr equal",
			&mockAddr{"192.168.1.1:80"},
			&mockAddr{"192.168.1.1:80"},
			true,
		},
		{
			"string addr different",
			&mockAddr{"192.168.1.1:80"},
			&mockAddr{"192.168.1.2:80"},
			false,
		},
		{"different network types", &mockAddr{"tcp"}, &mockAddr{"udp"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := internal.AddrsEq(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf(
					"AddrsEq(%v, %v) = %v, want %v",
					tt.a,
					tt.b,
					result,
					tt.expected,
				)
			}
		})
	}
}

func TestWriteAllSlices(t *testing.T) {
	t.Run("Ok", func(t *testing.T) {
		r, w := io.Pipe()
		defer func() {
			_ = r.Close()
			_ = w.Close()
		}()
		go func() {
			defer func() { _ = r.Close() }()
			for {
				_, err := r.Read([]byte{0})
				if err != nil {
					return
				}
			}
		}()
		hello := []byte("hello ")
		world := []byte("world")
		n, err := internal.WriteAllSlices(w, hello, world)
		if err != nil {
			t.Fatal(err)
		}
		if n != int64(len(hello)+len(world)) {
			t.Fatal(n, int64(len(hello)+len(world)))
		}
	})
	t.Run("Err", func(t *testing.T) {
		r, w := io.Pipe()
		defer func() {
			_ = r.Close()
			_ = w.Close()
		}()
		go func() {
			defer func() { _ = r.Close() }()
			for range 5 {
				_, err := r.Read([]byte{0})
				if err != nil {
					return
				}
			}
		}()
		hello := []byte("hello ")
		world := []byte("world")
		_, err := internal.WriteAllSlices(w, hello, world)
		if err.Error() != "io: read/write on closed pipe" {
			t.Fatal(err)
		}
	})
}
