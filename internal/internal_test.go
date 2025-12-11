package internal_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/asciimoth/socks/common"
	"github.com/asciimoth/socks/internal"
)

// TODO: Tests for buffers leaks

// fakePacketConn implements internal.ReaderConn. It returns a sequence of byte slices
// on successive Read calls and provides a LocalAddr.
type fakePacketConn struct {
	seq   [][]byte
	index int
	local net.Addr
}

func (f *fakePacketConn) Read(b []byte) (int, error) {
	if f.index >= len(f.seq) {
		return 0, nil
	}
	n := copy(b, f.seq[f.index])
	f.index++
	return n, nil
}

func (f *fakePacketConn) LocalAddr() net.Addr { return f.local }

type fakeStreamConn struct {
	io.Reader
	local net.Addr
}

func (f *fakeStreamConn) LocalAddr() net.Addr { return f.local }

// recordingWriter is a fake writer that records the bytes actually written.
// It can simulate partial writes and/or returning an error.
type recordingWriter struct {
	buf       bytes.Buffer
	returnN   int   // if 0, behave like writeall and return len(b)
	returnErr error // if non-nil, returned after writing returnN bytes
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	n := len(b)
	if w.returnN != 0 && w.returnN < n {
		// simulate a partial write: only write the first returnN bytes
		w.buf.Write(b[:w.returnN])
		if w.returnErr != nil {
			return w.returnN, w.returnErr
		}
		return w.returnN, nil
	}
	// write everything
	w.buf.Write(b)
	if w.returnErr != nil {
		return n, w.returnErr
	}
	return n, nil
}

func buildDomainHeader(host string, port uint16) []byte {
	h := []byte{}
	h = append(h, 0, 0, 0, byte(common.DomAddr)) // RSV(2), FRAG, ATYP
	h = append(h, byte(len(host)))
	h = append(h, []byte(host)...)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, port)
	h = append(h, b...)
	return h
}

func buildIPv4Header(ip net.IP, port uint16) []byte {
	ip4 := ip.To4()
	h := []byte{0, 0, 0, byte(common.IP4Addr)}
	h = append(h, ip4...)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, port)
	h = append(h, b...)
	return h
}

func TestHeader5UDP(t *testing.T) {
	tests := []struct {
		name string
		atyp common.AddrType
		addr []byte
		port uint16
		want []byte
	}{
		{
			name: "IPv4",
			atyp: common.IP4Addr,
			addr: []byte(net.IPv4(127, 0, 0, 1).To4()),
			port: 1080,
			want: []byte{
				0, 0, // RSV
				0,            // FRAG
				1,            // ATYP IPv4
				127, 0, 0, 1, // ADDR
				0x04, 0x38, // PORT 1080
			},
		},
		{
			name: "Domain",
			atyp: common.DomAddr,
			addr: []byte("example.com"),
			port: 8080,
			want: append(
				[]byte{
					0, 0, // RSV
					0,  // FRAG
					3,  // ATYP DOMAIN
					11, // LEN("example.com")
				},
				append(
					[]byte("example.com"),
					0x1F, 0x90, // PORT 8080
				)...,
			),
		},
		{
			name: "IPv6",
			atyp: common.IP6Addr,
			addr: []byte(net.IPv6loopback.To16()), // ::1
			port: 5353,
			want: []byte{
				0, 0, // RSV
				0, // FRAG
				4, // ATYP IPv6
				// ADDR (16 bytes)
				0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 1,
				0x14, 0xE9, // PORT 5353
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, 0, len(tc.want))
			got := internal.Header5UDP(buf, tc.atyp, tc.addr, tc.port, 0)

			if len(got) != len(tc.want) {
				t.Fatalf("len mismatch: want=%d got=%d", len(tc.want), len(got))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("byte %d mismatch: want=%#02x got=%#02x\nwant=% x\ngot= % x",
						i, tc.want[i], got[i], tc.want, got)
				}
			}
		})
	}
}

func TestRead5UDPTun(t *testing.T) {
	type read struct {
		pSize             int
		errStr            string
		needAddr          bool
		wantAddrString    string
		wantPayloadString string
	}
	tests := []struct {
		name   string
		stream []byte
		reads  []read
	}{
		{
			name: "Happy Path",
			stream: []byte{
				// Pkg 0
				0, 12, // Payload length
				0,            // No fragmentation
				1,            // Atyp IPv4
				127, 0, 0, 1, // Addr
				0, 1, // Port
				// Payload: Hello World!
				0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,

				// Pkg 1
				0, 12, // Payload length
				0,                                              // No fragmentation
				4,                                              // Atyp IPv6
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // Addr
				0, 1, // Port
				// Payload: Hello World!
				0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,

				// Pkg 2
				0, 0, // Payload length
				0,                      // No fragmentation
				3,                      // Atyp FQDN
				4,                      // Addr len
				0x68, 0x6f, 0x73, 0x74, // Addr
				0, 10, // Port
				// No Payload

				// Pkg 3
				0, 12, // Payload length
				0,            // No fragmentation
				1,            // Atyp IPv4
				127, 0, 0, 1, // Addr
				0, 1, // Port
				// Payload: Hello World!
				0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
			},
			reads: []read{
				{
					pSize:             1024,
					needAddr:          true,
					wantAddrString:    "127.0.0.1:1",
					wantPayloadString: "Hello World!",
				},
				{
					pSize:             12,
					needAddr:          true,
					wantAddrString:    "[::1]:1",
					wantPayloadString: "Hello World!",
				},
				{
					pSize:          12,
					needAddr:       true,
					wantAddrString: "host:10",
				},
				{
					pSize:             5,
					needAddr:          true,
					wantAddrString:    "127.0.0.1:1",
					wantPayloadString: "Hello",
				},
			},
		},
		// TODO: More cases
	}

	pSize := 0
	for _, tc := range tests {
		for _, r := range tc.reads {
			pSize = max(r.pSize, pSize)
		}
	}

	rbuf := make([]byte, pSize)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &fakeStreamConn{
				Reader: bytes.NewBuffer(tc.stream),
				local:  &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999},
			}
			for _, r := range tc.reads {
				buf := rbuf[:r.pSize]
				n, addr, err := internal.Read5UDPTun(nil, conn, buf, r.needAddr)
				if err != nil {
					if r.errStr == "" {
						t.Fatalf("Read5UDPTun returned error: %v", err)
					} else {
						if r.errStr == err.Error() {
							continue
						}
						t.Fatalf("Read5UDPTun returned error: %v while expected %s", err, r.errStr)
					}
					return
				}
				if r.needAddr && addr.String() != r.wantAddrString {
					t.Fatalf("Read5UDPTun returned wrong addr: %s %s", r.wantAddrString, addr)
				}
				text := string(buf[:n])
				if r.wantPayloadString != text {
					t.Fatalf("Read5UDPTun returned wrong payload: %s %s", r.wantPayloadString, text)
				}
			}
		})
	}
}

func TestRead5UDP(t *testing.T) {
	payload := []byte("hello-socks5-udp-payload")
	ipv4Addr := []byte{127, 0, 0, 1}
	ipv6Addr := net.ParseIP("::1").To16()
	domain := []byte("example.com")

	// helper to make a full packet (header + payload) using Header5UDP
	makePacket := func(atyp common.AddrType, addr []byte, port uint16, pl []byte) []byte {
		capEstimate := len(addr) + len(pl) + 22 // Should be allways enougth
		hdr := internal.Header5UDP(
			make([]byte, 0, capEstimate), atyp, addr, port, 0,
		)
		return append(hdr, pl...)
	}

	tests := []struct {
		name            string
		reads           [][]byte // sequence of Read returns
		pSize           int      // size of destination buffer p
		needAddr        bool
		wantN           int
		wantPayload     []byte
		wantAddrPresent bool
		wantAddrString  string // if wantAddrPresent true, compare addr.String()
	}{
		{
			name:            "IPv4 needs addr",
			reads:           [][]byte{makePacket(common.IP4Addr, ipv4Addr, 1080, payload)},
			pSize:           len(payload),
			needAddr:        true,
			wantN:           len(payload),
			wantPayload:     payload,
			wantAddrPresent: true,
			wantAddrString:  (&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}).String(),
		},
		{
			name:            "Domain needs addr",
			reads:           [][]byte{makePacket(common.DomAddr, domain, 8080, payload)},
			pSize:           len(payload),
			needAddr:        true,
			wantN:           len(payload),
			wantPayload:     payload,
			wantAddrPresent: true,
			wantAddrString:  net.JoinHostPort(string(domain), strconv.Itoa(8080)),
		},
		{
			name:            "IPv6 needs addr",
			reads:           [][]byte{makePacket(common.IP6Addr, ipv6Addr, 5353, payload)},
			pSize:           len(payload),
			needAddr:        true,
			wantN:           len(payload),
			wantPayload:     payload,
			wantAddrPresent: true,
			wantAddrString:  (&net.UDPAddr{IP: net.ParseIP("::1"), Port: 5353}).String(),
		},
		{
			name:            "Domain but needAddr=false (addr must be nil)",
			reads:           [][]byte{makePacket(common.DomAddr, domain, 8080, payload)},
			pSize:           len(payload),
			needAddr:        false,
			wantN:           len(payload),
			wantPayload:     payload,
			wantAddrPresent: false,
		},
		{
			name: "first read too small then valid packet",
			reads: [][]byte{
				// too small (nn < 8), should be ignored by Read5UDP loop
				{0, 0, 0, 0, 1},
				// then a valid IPv4 packet
				makePacket(common.IP4Addr, ipv4Addr, 1080, payload),
			},
			pSize:           len(payload),
			needAddr:        true,
			wantN:           len(payload),
			wantPayload:     payload,
			wantAddrPresent: true,
			wantAddrString:  (&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1080}).String(),
		},
		{
			name:  "destination buffer shorter than payload (truncation)",
			reads: [][]byte{makePacket(common.IP4Addr, ipv4Addr, 1080, payload)},
			// choose p smaller than payload to test truncation/copy length
			pSize:           5,
			needAddr:        false,
			wantN:           5,
			wantPayload:     payload[:5],
			wantAddrPresent: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &fakePacketConn{
				seq:   tc.reads,
				index: 0,
				local: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 9999}, // Network() -> "udp"
			}
			p := make([]byte, tc.pSize)
			n, addr, err := internal.Read5UDP(nil, conn, p, tc.needAddr)
			if err != nil {
				t.Fatalf("Read5UDP returned error: %v", err)
			}
			if n != tc.wantN {
				t.Fatalf("wrong n: want=%d got=%d", tc.wantN, n)
			}
			if !bytes.Equal(p[:n], tc.wantPayload) {
				t.Fatalf("payload mismatch:\nwant: %q\ngot:  %q", tc.wantPayload, p[:n])
			}
			if tc.wantAddrPresent {
				if addr == nil {
					t.Fatalf("expected addr but got nil")
				}
				if addr.String() != tc.wantAddrString {
					t.Fatalf("addr.String() mismatch: want=%q got=%q", tc.wantAddrString, addr.String())
				}
			} else {
				if addr != nil {
					t.Fatalf("expected nil addr, got %T: %v", addr, addr)
				}
			}
		})
	}
}

func TestWrite5ToUDPaddr(t *testing.T) {
	tests := []struct {
		name          string
		ip            net.IP
		port          uint16
		payloadLen    int // p length passed to Write5ToUDPaddr (affects return value calc)
		writer        *recordingWriter
		wantWritten   []byte // exact bytes expected to be written to the writer
		wantReturnN   int    // expected n returned by Write5ToUDPaddr
		wantReturnErr error
	}{
		{
			name:       "IPv4 full write",
			ip:         net.IPv4(127, 0, 0, 1),
			port:       1080,
			payloadLen: 0,
			writer:     &recordingWriter{},
			wantWritten: []byte{
				0, 0, // RSV
				0,            // FRAG
				1,            // ATYP = IPv4
				127, 0, 0, 1, // IPv4 addr
				0x04, 0x38, // port 1080
			},
			// Write5ToUDPaddr computes n = max(0, n-10-len(p)).
			// writer wrote 10 bytes, payloadLen == 0 -> n = max(0, 10-10-0) = 0
			wantReturnN:   0,
			wantReturnErr: nil,
		},
		{
			name:       "IPv6 full write",
			ip:         net.ParseIP("::1"),
			port:       5353,
			payloadLen: 5,
			writer:     &recordingWriter{},
			wantWritten: func() []byte {
				b := make([]byte, 0, 22)
				// RSV, FRAG, ATYP
				b = append(b, 0, 0, 0, 4)
				// ::1 as 16 bytes
				for range 15 {
					b = append(b, 0)
				}
				b = append(b, 1)
				// port 5353 = 0x14E9
				b = append(b, 0x14, 0xE9)
				b = append(b, 0, 0, 0, 0, 0)
				return b
			}(),
			// writer wrote 22 bytes, Write5ToUDPaddr does n=max(0, n-22) = 0
			wantReturnN:   5,
			wantReturnErr: nil,
		},
		{
			name:       "writer returns error",
			ip:         net.IPv4(10, 0, 0, 1),
			port:       53,
			payloadLen: 0,
			writer: &recordingWriter{
				returnErr: errors.New("boom"),
				returnN:   0,
			},
			// In this case Write will attempt to write but return the error.
			// We don't expect any bytes in the buffer (returnN == 0).
			wantWritten:   nil,
			wantReturnN:   0,
			wantReturnErr: errors.New("boom"),
		},
		{
			name:       "partial header write (ipv4)",
			ip:         net.IPv4(192, 168, 0, 1),
			port:       1234,
			payloadLen: 0,
			// Simulate writer writing only 5 bytes out of the 10-byte IPv4 header.
			writer: &recordingWriter{
				returnN:   5,
				returnErr: nil,
			},
			// wantWritten is the first 5 bytes of the expected IPv4 header:
			// [0,0,0,1,192]
			wantWritten: func() []byte {
				full := []byte{
					0, 0, // RSV
					0,              // FRAG
					1,              // ATYP IPv4
					192, 168, 0, 1, // addr (4)
					0x04, 0xD2, // port 1234
				}
				return full[:5]
			}(),
			// The function computes n = max(0, written-10-len(p)).
			// written == 5, payloadLen == 0 -> max(0, 5-10-0) == 0
			wantReturnN:   0,
			wantReturnErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// prepare p slice with the requested length (content not used by Write5ToUDPaddr)
			p := make([]byte, tc.payloadLen)

			n, err := internal.Write5ToUDPaddr(nil, tc.writer, p, tc.ip, tc.port, false)

			// check error: compare presence and message (simple check)
			if tc.wantReturnErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.wantReturnErr)
				}
				if err.Error() != tc.wantReturnErr.Error() {
					t.Fatalf("expected error %v, got %v", tc.wantReturnErr, err)
				}
			}

			if n != tc.wantReturnN {
				t.Fatalf("returned n mismatch: want=%d got=%d", tc.wantReturnN, n)
			}

			if tc.wantReturnErr == nil {
				got := tc.writer.buf.Bytes()
				if !bytes.Equal(got, tc.wantWritten) {
					t.Fatalf("writer bytes mismatch:\nwant: % X\ngot:  % X", tc.wantWritten, got)
				}
			}
		})
	}
}

func TestWrite5ToUDPFQDN(t *testing.T) {
	tests := []struct {
		name        string
		addr        string // host:port (passed to Write5ToUDPFQDN)
		pLen        int
		writer      *recordingWriter
		wantWritten []byte
		wantN       int
		wantErr     error
	}{
		{
			name:   "domain full write",
			addr:   "example.com:8080",
			pLen:   0,
			writer: &recordingWriter{},
			// expected bytes are the domain-header only
			wantWritten: buildDomainHeader("example.com", 8080),
			// function sets n = max(0, n-7). writer wrote header len = 7 + len(host) => n = len(host)
			wantN:   len("example.com"),
			wantErr: nil,
		},
		{
			name:   "domain partial write (less than header)",
			addr:   "example.com:8080",
			pLen:   0,
			writer: &recordingWriter{returnN: 5},
			// writer writes first 5 bytes only
			wantWritten: buildDomainHeader("example.com", 8080)[:5],
			// returned n = max(0, 5-7) == 0
			wantN:   0,
			wantErr: nil,
		},
		{
			name:   "host is IPv4 (delegates to Write5ToUDPaddr)",
			addr:   "127.0.0.1:1080",
			pLen:   0,
			writer: &recordingWriter{},
			// expect IPv4 header written
			wantWritten: buildIPv4Header(net.ParseIP("127.0.0.1"), 1080),
			// Write5ToUDPaddr returns max(0, written-10-len(p)) for IPv4; written==10, pLen==0 => 0
			wantN:   0,
			wantErr: nil,
		},
		{
			name:    "missing port -> error",
			addr:    "example.com", // no :port
			pLen:    0,
			writer:  &recordingWriter{},
			wantN:   0,
			wantErr: errors.New("missing port or invalid address"),
		},
		{
			name:    "invalid port -> error",
			addr:    "example.com:badport",
			pLen:    0,
			writer:  &recordingWriter{},
			wantN:   0,
			wantErr: errors.New("invalid port"),
		},
		{
			name: "too long hostname -> error",
			// host part length 256
			addr: func() string {
				host := strings.Repeat("a", 256)
				return host + ":80"
			}(),
			pLen:   0,
			writer: &recordingWriter{},
			// original function returns fmt.Errorf("too long hostname")
			wantN:   0,
			wantErr: errors.New("too long hostname: " + strings.Repeat("a", 256)),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := make([]byte, tc.pLen)
			n, err := internal.Write5ToUDPFQDN(nil, tc.writer, p, tc.addr, false)

			// error handling — compare by presence and substring (since errors may differ)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.wantErr)
				}
				// compare by error message substring or exact match for known messages
				wantMsg := tc.wantErr.Error()
				gotMsg := err.Error()
				// because net.SplitHostPort and strconv produce different error messages,
				// we match for intuitive substrings for the invalid-port/missing-port cases.
				switch tc.name {
				case "missing port -> error":
					// net.SplitHostPort returns "missing port in address" on Go stdlib; allow a few variants
					if !strings.Contains(gotMsg, "missing port") && !strings.Contains(gotMsg, "missing port in address") {
						t.Fatalf("expected missing-port error, got: %v", err)
					}
				case "invalid port -> error":
					if !strings.Contains(gotMsg, "invalid") && !strings.Contains(gotMsg, "cannot") && !strings.Contains(gotMsg, "invalid syntax") {
						t.Fatalf("expected invalid-port error, got: %v", err)
					}
				default:
					// for other cases expect exact message
					if gotMsg != wantMsg {
						t.Fatalf("expected error %q, got %q", wantMsg, gotMsg)
					}
				}
				// don't continue further checks for error cases
				return
			}

			if n != tc.wantN {
				t.Fatalf("returned n mismatch: want=%d got=%d", tc.wantN, n)
			}

			got := tc.writer.buf.Bytes()
			if !bytes.Equal(got, tc.wantWritten) {
				t.Fatalf("writer bytes mismatch:\nwant: % X\ngot:  % X", tc.wantWritten, got)
			}
		})
	}
}
