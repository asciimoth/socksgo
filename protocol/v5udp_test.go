package protocol_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/protocol"
)

// Test cases for AppendSocks5UDPHeader
func TestAppendSocks5UDPHeader(t *testing.T) {
	tests := []struct {
		name     string
		rsv      uint16
		addrType protocol.AddrType
		host     string
		port     uint16
		expected []byte
	}{
		{
			name:     "IPv4 with RSV=0",
			rsv:      0,
			addrType: protocol.IP4Addr,
			host:     "192.168.1.1",
			port:     8080,
			expected: []byte{
				0x00,
				0x00,
				0x00,
				0x01,
				192,
				168,
				1,
				1,
				0x1F,
				0x90,
			},
		},
		{
			name:     "IPv4 with RSV=1234",
			rsv:      1234,
			addrType: protocol.IP4Addr,
			host:     "192.168.1.1",
			port:     8080,
			expected: []byte{0x04, 0xD2, 255, 0x01, 192, 168, 1, 1, 0x1F, 0x90},
		},
		{
			name:     "IPv6 with RSV=0",
			rsv:      0,
			addrType: protocol.IP6Addr,
			host:     "2001:db8::1",
			port:     443,
			expected: []byte{
				0x00, 0x00, 0x00, 0x04,
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				0x01, 0xBB,
			},
		},
		{
			name:     "FQDN with RSV=0",
			rsv:      0,
			addrType: protocol.FQDNAddr,
			host:     "example.com",
			port:     80,
			expected: []byte{
				0x00, 0x00, 0x00, 0x03,
				11, // length of domain
				'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
				0x00, 0x50,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf []byte
			addr := protocol.AddrFromString(tt.host, tt.port, "")

			result := protocol.AppendSocks5UDPHeader(buf, tt.rsv, addr)

			if !bytes.Equal(result, tt.expected) {
				t.Errorf(
					"AppendSocks5UDPHeader() = %v, want %v",
					result,
					tt.expected,
				)
			}
		})
	}
}

func TestReadSocks5UDPPacketAssoc(t *testing.T) {
	tests := []struct {
		name      string
		setupConn func() protocol.PacketConn
		skipAddr  bool
		wantN     int
		wantAddr  protocol.Addr
		wantErr   bool
	}{
		{
			name: "packetconn-ipv4-standard",
			setupConn: func() protocol.PacketConn {
				// Create a standard SOCKS5 UDP packet with IPv4
				buf := make([]byte, 0, 1024)
				buf = binary.BigEndian.AppendUint16(buf, 0)    // RSV=0
				buf = append(buf, 0)                           // FRAG=0
				buf = append(buf, byte(protocol.IP4Addr))      // ATYP=IPv4
				buf = append(buf, []byte{192, 168, 1, 1}...)   // IPv4
				buf = binary.BigEndian.AppendUint16(buf, 8080) // PORT
				buf = append(buf, []byte("payload data")...)   // payload

				conn := &MockPacketConn{
					Packets: []Packet{{
						Addr:    NetAddr{Addr: "192.168.1.1:8080", Net: "udp"},
						Payload: buf,
					}},
					Local:  NetAddr{Addr: "127.0.0.1:1080", Net: "udp"},
					Remote: NetAddr{Addr: "192.168.1.1:8080", Net: "udp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    12, // len("payload data")
			wantAddr: protocol.AddrFromString("192.168.1.1", 8080, "udp"),
			wantErr:  false,
		},
		{
			name: "packetconn-ipv6-standard",
			setupConn: func() protocol.PacketConn {
				buf := make([]byte, 0, 1024)
				buf = binary.BigEndian.AppendUint16(buf, 0) // RSV=0
				buf = append(buf, 0)                        // FRAG=0
				buf = append(buf, byte(protocol.IP6Addr))   // ATYP=IPv6
				// IPv6: 2001:db8::1
				buf = append(
					buf,
					[]byte{
						0x20,
						0x01,
						0x0d,
						0xb8,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						0,
						1,
					}...)
				buf = binary.BigEndian.AppendUint16(buf, 443) // PORT
				buf = append(buf, []byte("https data")...)    // payload

				conn := &MockPacketConn{
					Packets: []Packet{{
						Addr:    NetAddr{Addr: "[2001:db8::1]:443", Net: "udp"},
						Payload: buf,
					}},
					Local: NetAddr{Addr: "127.0.0.1:1080", Net: "udp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    10, // len("https data")
			wantAddr: protocol.AddrFromString("2001:db8::1", 443, "udp"),
			wantErr:  false,
		},
		{
			name: "packetconn-fqdn-standard",
			setupConn: func() protocol.PacketConn {
				buf := make([]byte, 0, 1024)
				buf = binary.BigEndian.AppendUint16(buf, 0)  // RSV=0
				buf = append(buf, 0)                         // FRAG=0
				buf = append(buf, byte(protocol.FQDNAddr))   // ATYP=FQDN
				buf = append(buf, byte(11))                  // Domain length
				buf = append(buf, []byte("example.com")...)  // Domain
				buf = binary.BigEndian.AppendUint16(buf, 53) // PORT (DNS)
				buf = append(buf, []byte("dns query")...)    // payload

				conn := &MockPacketConn{
					Packets: []Packet{{
						Addr:    NetAddr{Addr: "example.com:53", Net: "udp"},
						Payload: buf,
					}},
					Local: NetAddr{Addr: "127.0.0.1:1080", Net: "udp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    9, // len("dns query")
			wantAddr: protocol.AddrFromString("example.com", 53, "udp"),
			wantErr:  false,
		},
		{
			name: "packetconn-skip-addr",
			setupConn: func() protocol.PacketConn {
				buf := make([]byte, 0, 1024)
				buf = binary.BigEndian.AppendUint16(buf, 0)    // RSV=0
				buf = append(buf, 0)                           // FRAG=0
				buf = append(buf, byte(protocol.IP4Addr))      // ATYP=IPv4
				buf = append(buf, []byte{10, 0, 0, 1}...)      // IPv4
				buf = binary.BigEndian.AppendUint16(buf, 9000) // PORT
				buf = append(buf, []byte("test payload")...)   // payload

				conn := &MockPacketConn{
					Packets: []Packet{{
						Addr:    NetAddr{Addr: "10.0.0.1:9000", Net: "udp"},
						Payload: buf,
					}},
					Local: NetAddr{Addr: "127.0.0.1:1080", Net: "udp"},
				}
				return conn
			},
			skipAddr: true,
			wantN:    12, // len("test payload")
			wantErr:  false,
		},
		{
			name: "packetconn-fragmented-skip",
			setupConn: func() protocol.PacketConn {
				// First packet with FRAG != 0 (should be skipped)
				buf1 := make([]byte, 0, 1024)
				buf1 = binary.BigEndian.AppendUint16(buf1, 0) // RSV=0
				buf1 = append(
					buf1,
					1,
				) // FRAG=1 (fragmented)
				buf1 = append(buf1, byte(protocol.IP4Addr))    // ATYP=IPv4
				buf1 = append(buf1, []byte{192, 168, 1, 1}...) // IPv4
				buf1 = binary.BigEndian.AppendUint16(buf1, 80) // PORT
				buf1 = append(buf1, []byte("fragmented")...)   // payload

				// Second valid packet
				buf2 := make([]byte, 0, 1024)
				buf2 = binary.BigEndian.AppendUint16(buf2, 0)    // RSV=0
				buf2 = append(buf2, 0)                           // FRAG=0
				buf2 = append(buf2, byte(protocol.IP4Addr))      // ATYP=IPv4
				buf2 = append(buf2, []byte{10, 0, 0, 2}...)      // IPv4
				buf2 = binary.BigEndian.AppendUint16(buf2, 8080) // PORT
				buf2 = append(buf2, []byte("valid data")...)     // payload

				conn := &MockPacketConn{
					Packets: []Packet{
						{
							Addr: NetAddr{
								Addr: "192.168.1.1:80",
								Net:  "udp",
							},
							Payload: buf1,
						},
						{
							Addr:    NetAddr{Addr: "10.0.0.2:8080", Net: "udp"},
							Payload: buf2,
						},
					},
					Local: NetAddr{Addr: "127.0.0.1:1080", Net: "udp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    10, // len("valid data")
			wantAddr: protocol.AddrFromString("10.0.0.2", 8080, "udp"),
			wantErr:  false,
		},
		{
			name: "packetconn-rsv-not-zero-skip",
			setupConn: func() protocol.PacketConn {
				// First packet with RSV != 0 (should be skipped)
				buf1 := make([]byte, 0, 1024)
				buf1 = binary.BigEndian.AppendUint16(
					buf1,
					1,
				) // RSV=1 (not zero)
				buf1 = append(buf1, 0)                         // FRAG=0
				buf1 = append(buf1, byte(protocol.IP4Addr))    // ATYP=IPv4
				buf1 = append(buf1, []byte{192, 168, 1, 1}...) // IPv4
				buf1 = binary.BigEndian.AppendUint16(buf1, 80) // PORT
				buf1 = append(buf1, []byte("bad rsv")...)      // payload

				// Second valid packet
				buf2 := make([]byte, 0, 1024)
				buf2 = binary.BigEndian.AppendUint16(buf2, 0)    // RSV=0
				buf2 = append(buf2, 0)                           // FRAG=0
				buf2 = append(buf2, byte(protocol.IP4Addr))      // ATYP=IPv4
				buf2 = append(buf2, []byte{10, 0, 0, 3}...)      // IPv4
				buf2 = binary.BigEndian.AppendUint16(buf2, 9090) // PORT
				buf2 = append(buf2, []byte("good data")...)      // payload

				conn := &MockPacketConn{
					Packets: []Packet{
						{
							Addr: NetAddr{
								Addr: "192.168.1.1:80",
								Net:  "udp",
							},
							Payload: buf1,
						},
						{
							Addr:    NetAddr{Addr: "10.0.0.3:9090", Net: "udp"},
							Payload: buf2,
						},
					},
					Local: NetAddr{Addr: "127.0.0.1:1080", Net: "udp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    9, // len("good data")
			wantAddr: protocol.AddrFromString("10.0.0.3", 9090, "udp"),
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close() //nolint

			conn := tt.setupConn()
			buf := make([]byte, 500) // Buffer for reading

			n, addr, _, err := protocol.ReadSocks5AssocUDPPacket(
				pool,
				conn,
				buf,
				tt.skipAddr,
				nil,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf(
					"ReadSocks5UDPPacket() error = %v, wantErr %v",
					err,
					tt.wantErr,
				)
				return
			}

			if !tt.wantErr {
				if n != tt.wantN {
					t.Errorf(
						"ReadSocks5UDPPacket() n = %v, want %v",
						n,
						tt.wantN,
					)
				}

				if !tt.skipAddr {
					if tt.wantAddr.String() != addr.String() {
						t.Errorf(
							"expected addr %s but got %s",
							tt.wantAddr.String(),
							addr.String(),
						)
					}
				}
			}
		})
	}
}

func TestReadSocks5UDPPacketTUN(t *testing.T) {
	tests := []struct {
		name      string
		setupConn func() net.Conn
		skipAddr  bool
		wantN     int
		wantAddr  protocol.Addr
		wantErr   bool
	}{
		{
			name: "tcp-tun-ipv4",
			setupConn: func() net.Conn {
				payload := []byte("tcp tun payload")
				// Create TUN packet: RSV = payload length, FRAG = GOST flag
				buf := make([]byte, 0, 1024)
				buf = binary.BigEndian.AppendUint16(
					buf,
					uint16(len(payload)), //nolint
				) // RSV = payload length
				buf = append(
					buf,
					protocol.GOST_UDP_FRAG_FLAG,
				) // FRAG flag for TUN
				buf = append(
					buf,
					byte(protocol.IP4Addr),
				) // ATYP=IPv4
				buf = append(
					buf,
					[]byte{172, 16, 0, 1}...) // IPv4
				buf = binary.BigEndian.AppendUint16(
					buf,
					3306,
				) // PORT (MySQL)
				buf = append(
					buf,
					payload...) // payload

				conn := &MockConn{
					Buffer: *bytes.NewBuffer(buf),
					Local:  NetAddr{Addr: "127.0.0.1:1080", Net: "tcp"},
					Remote: NetAddr{Addr: "172.16.0.1:3306", Net: "tcp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    15, // len("tcp tun payload")
			wantAddr: protocol.AddrFromString("172.16.0.1", 3306, "udp"),
			wantErr:  false,
		},
		{
			name: "tcp-tun-ipv6",
			setupConn: func() net.Conn {
				payload := []byte("ipv6 tcp data")
				buf := make([]byte, 0, 1024)
				buf = binary.BigEndian.AppendUint16(
					buf,
					uint16(len(payload)), //nolint
				) // RSV
				buf = append(
					buf,
					protocol.GOST_UDP_FRAG_FLAG,
				) // FRAG flag
				buf = append(
					buf,
					byte(protocol.IP6Addr),
				) // ATYP=IPv6
				// IPv6: ::1
				buf = append(
					buf,
					[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}...)
				buf = binary.BigEndian.AppendUint16(
					buf,
					5432,
				) // PORT (PostgreSQL)
				buf = append(buf, payload...) // payload

				conn := &MockConn{
					Buffer: *bytes.NewBuffer(buf),
					Local:  NetAddr{Addr: "127.0.0.1:1080", Net: "tcp"},
					Remote: NetAddr{Addr: "[::1]:5432", Net: "tcp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    13, // len("ipv6 tcp data")
			wantAddr: protocol.AddrFromString("::1", 5432, "udp"),
			wantErr:  false,
		},
		{
			name: "tcp-tun-fqdn",
			setupConn: func() net.Conn {
				payload := []byte("domain payload")
				buf := make([]byte, 0, 1024)
				buf = binary.BigEndian.AppendUint16(
					buf,
					uint16(len(payload)), //nolint
				) // RSV
				buf = append(
					buf,
					protocol.GOST_UDP_FRAG_FLAG,
				) // FRAG flag
				buf = append(
					buf,
					byte(protocol.FQDNAddr),
				) // ATYP=FQDN
				buf = append(
					buf,
					byte(9),
				) // Domain length
				buf = append(
					buf,
					[]byte("localhost")...) // Domain
				buf = binary.BigEndian.AppendUint16(
					buf,
					6379,
				) // PORT (Redis)
				buf = append(
					buf,
					payload...) // payload

				conn := &MockConn{
					Buffer: *bytes.NewBuffer(buf),
					Local:  NetAddr{Addr: "127.0.0.1:1080", Net: "tcp"},
					Remote: NetAddr{Addr: "localhost:6379", Net: "tcp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    14, // len("domain payload")
			wantAddr: protocol.AddrFromString("localhost", 6379, "udp"),
			wantErr:  false,
		},
		{
			name: "tcp-tun-skip-addr",
			setupConn: func() net.Conn {
				payload := []byte("skip addr test")
				buf := make([]byte, 0, 1024)
				buf = binary.BigEndian.AppendUint16(
					buf,
					uint16(len(payload)), //nolint
				) // RSV
				buf = append(
					buf,
					protocol.GOST_UDP_FRAG_FLAG,
				) // FRAG flag
				buf = append(
					buf,
					byte(protocol.IP4Addr),
				) // ATYP=IPv4
				buf = append(
					buf,
					[]byte{192, 168, 0, 100}...) // IPv4
				buf = binary.BigEndian.AppendUint16(
					buf,
					22,
				) // PORT (SSH)
				buf = append(
					buf,
					payload...) // payload

				conn := &MockConn{
					Buffer: *bytes.NewBuffer(buf),
					Local:  NetAddr{Addr: "127.0.0.1:1080", Net: "tcp"},
				}
				return conn
			},
			skipAddr: true,
			wantN:    14, // len("skip addr test")
			wantErr:  false,
		},
		{
			name: "tcp-tun-fragmented-skip",
			setupConn: func() net.Conn {
				// First packet with fragmentation (should be skipped)
				payload1 := []byte("fragmented data")
				buf1 := make([]byte, 0, 1024)
				buf1 = binary.BigEndian.AppendUint16(
					buf1,
					uint16(len(payload1)), //nolint
				) // RSV
				buf1 = append(
					buf1,
					0x01,
				) // FRAG=1 (fragmented, not GOST flag)
				buf1 = append(
					buf1,
					byte(protocol.IP4Addr),
				) // ATYP=IPv4
				buf1 = append(
					buf1,
					[]byte{10, 0, 0, 1}...) // IPv4
				buf1 = binary.BigEndian.AppendUint16(
					buf1,
					80,
				) // PORT
				buf1 = append(
					buf1,
					payload1...) // payload

				// Second valid packet
				payload2 := []byte("valid tcp data")
				buf2 := make([]byte, 0, 1024)
				buf2 = binary.BigEndian.AppendUint16(
					buf2,
					uint16(len(payload2)), //nolint
				) // RSV
				buf2 = append(
					buf2,
					protocol.GOST_UDP_FRAG_FLAG,
				) // FRAG flag
				buf2 = append(
					buf2,
					byte(protocol.IP4Addr),
				) // ATYP=IPv4
				buf2 = append(
					buf2,
					[]byte{192, 168, 1, 10}...) // IPv4
				buf2 = binary.BigEndian.AppendUint16(
					buf2,
					8080,
				) // PORT
				buf2 = append(
					buf2,
					payload2...) // payload

				// Combine both packets
				conn := &MockConn{
					Buffer: *bytes.NewBuffer(append(buf1, buf2...)),
					Local:  NetAddr{Addr: "127.0.0.1:1080", Net: "tcp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    14, // len("valid tcp data")
			wantAddr: protocol.AddrFromString("192.168.1.10", 8080, "udp"),
			wantErr:  false,
		},
		{
			name: "tcp-tun-small-buffer",
			setupConn: func() net.Conn {
				// Create a payload larger than read buffer
				largePayload := bytes.Repeat([]byte("a"), 1000)
				buf := make([]byte, 0, 1024)
				buf = binary.BigEndian.AppendUint16(
					buf,
					uint16(len(largePayload)), //nolint
				) // RSV
				buf = append(
					buf,
					protocol.GOST_UDP_FRAG_FLAG,
				) // FRAG flag
				buf = append(
					buf,
					byte(protocol.IP4Addr),
				) // ATYP=IPv4
				buf = append(
					buf,
					[]byte{8, 8, 8, 8}...) // IPv4 (8.8.8.8)
				buf = binary.BigEndian.AppendUint16(
					buf,
					53,
				) // PORT (DNS)
				buf = append(
					buf,
					largePayload...) // payload

				conn := &MockConn{
					Buffer: *bytes.NewBuffer(buf),
					Local:  NetAddr{Addr: "127.0.0.1:1080", Net: "tcp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    500, // Buffer size in test
			wantAddr: protocol.AddrFromString("8.8.8.8", 53, "udp"),
			wantErr:  false,
		},
		{
			name: "tcp-tun-unknown-atyp",
			setupConn: func() net.Conn {
				buf := make([]byte, 0, 1024)
				buf = binary.BigEndian.AppendUint16(buf, 10)   // RSV
				buf = append(buf, protocol.GOST_UDP_FRAG_FLAG) // FRAG flag
				buf = append(buf, 0x99)                        // Unknown ATYP
				buf = append(buf, []byte("garbage")...)        // Garbage data

				conn := &MockConn{
					Buffer: *bytes.NewBuffer(buf),
					Local:  NetAddr{Addr: "127.0.0.1:1080", Net: "tcp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    0,
			wantErr:  true,
		},
		{
			name: "packetconn-too-small",
			setupConn: func() net.Conn {
				// Packet too small (only 5 bytes)
				conn := &MockPacketConn{
					Packets: []Packet{{
						Addr:    NetAddr{Addr: "192.168.1.1:80", Net: "udp"},
						Payload: []byte{0, 0, 0, 1, 192},
					}},
					Local: NetAddr{Addr: "127.0.0.1:1080", Net: "udp"},
				}
				return conn
			},
			skipAddr: false,
			wantN:    0,
			wantErr:  true, // Will hang because it keeps trying to read
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := bufpool.NewTestDebugPool(t)
			defer pool.Close() //nolint

			conn := tt.setupConn()
			buf := make([]byte, 500) // Buffer for reading

			n, addr, err := protocol.ReadSocks5TunUDPPacket(
				pool,
				conn,
				buf,
				tt.skipAddr,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf(
					"ReadSocks5UDPPacket() error = %v, wantErr %v",
					err,
					tt.wantErr,
				)
				return
			}

			if !tt.wantErr {
				if n != tt.wantN {
					t.Errorf(
						"ReadSocks5UDPPacket() n = %v, want %v",
						n,
						tt.wantN,
					)
				}

				if !tt.skipAddr {
					if tt.wantAddr.String() != addr.String() {
						t.Errorf(
							"expected addr %s but got %s",
							tt.wantAddr.String(),
							addr.String(),
						)
					}
				}
			}
		})
	}
}

type pkt struct {
	data []byte
	from net.Addr
}

// fakePacketConn implements the minimal subset of net.Conn+net.PacketConn
// needed by the tests. Two endpoints created by newPacketConnPair are peers:
// writes on one are delivered to the other's incoming channel.
type fakePacketConn struct {
	in     chan pkt
	local  net.Addr
	peer   *fakePacketConn
	closed chan struct{}
}

func newUDPAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
}

func newPacketConnPair() (*fakePacketConn, *fakePacketConn) {
	a := &fakePacketConn{
		in:     make(chan pkt, 16),
		local:  newUDPAddr(10000),
		closed: make(chan struct{}),
	}
	b := &fakePacketConn{
		in:     make(chan pkt, 16),
		local:  newUDPAddr(10001),
		closed: make(chan struct{}),
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (f *fakePacketConn) Read(b []byte) (int, error) {
	select {
	case p := <-f.in:
		n := copy(b, p.data)
		return n, nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakePacketConn) Write(b []byte) (int, error) {
	if f.peer == nil {
		return 0, nil
	}
	// deliver to peer
	payload := make([]byte, len(b))
	copy(payload, b)
	select {
	case f.peer.in <- pkt{data: payload, from: f.local}:
		return len(b), nil
	case <-f.peer.closed:
		return 0, io.EOF
	}
}

func (f *fakePacketConn) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

func (f *fakePacketConn) LocalAddr() net.Addr { return f.local }
func (f *fakePacketConn) RemoteAddr() net.Addr {
	if f.peer == nil {
		return nil
	}
	return f.peer.local
}
func (f *fakePacketConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error { return nil }

// PacketConn specific
func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-f.in:
		n := copy(b, p.data)
		return n, p.from, nil
	case <-f.closed:
		return 0, nil, io.EOF
	}
}

func (f *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// WriteTo is treated same as Write: push to peer
	return f.Write(b)
}

func TestAppendSocks5UDPHeader_IPv4_IPv6_FQDN_and_frag(t *testing.T) {
	ip4 := protocol.AddrFromIP(net.ParseIP("1.2.3.4"), 4321, "udp")
	h := protocol.AppendSocks5UDPHeader(nil, 0, ip4)
	// header length for IPv4: 2(rsv)+1(frag)+1(atyp)+4(ip)+2(port)=10
	if len(h) != 10 {
		t.Fatalf("expected ipv4 header len 10, got %d", len(h))
	}
	// rsv 0
	if h[0] != 0 || h[1] != 0 {
		t.Fatalf("expected rsv 0")
	}
	// frag 0 for rsv==0
	if h[2] != 0 {
		t.Fatalf("expected frag 0")
	}
	// check ip bytes
	if h[4] != 1 || h[5] != 2 || h[6] != 3 || h[7] != 4 {
		t.Fatalf("ipv4 bytes mismatch: %v", h[4:8])
	}

	// IPv6
	ip6 := protocol.AddrFromIP(net.ParseIP("::1"), 9999, "udp")
	h6 := protocol.AppendSocks5UDPHeader(nil, 0, ip6)
	// rsv 0, frag 0, type byte present:
	if h6[2] != 0 {
		t.Fatalf("expected frag 0 for ipv6")
	}
	if protocol.AddrType(h6[3]) != protocol.IP6Addr {
		t.Fatalf("expected IPv6 atyp")
	}

	// FQDN
	fq := protocol.AddrFromFQDN(
		net.JoinHostPort("example.test", "1234"),
		1234,
		"udp",
	)
	hfq := protocol.AppendSocks5UDPHeader(nil, 0, fq)
	if protocol.AddrType(hfq[3]) != protocol.FQDNAddr {
		t.Fatalf("expected FQDN atyp")
	}
	// test non-zero rsv sets GOST_UDP_FRAG_FLAG
	hfrag := protocol.AppendSocks5UDPHeader(nil, 12, ip4)
	if hfrag[2] != protocol.GOST_UDP_FRAG_FLAG {
		t.Fatalf("expected gost frag flag set for non-zero rsv")
	}
}

func TestWriteSocksAssoc5UDPPacket_WriteAndWriteTo(t *testing.T) {
	a, b := newPacketConnPair()
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()

	payload := []byte("hello-socks-udp")
	addr := protocol.AddrFromIP(net.ParseIP("9.9.9.9"), 5555, "udp")

	// Test Write path (peerAddr == nil) using a as conn; it should deliver to b
	n, err := protocol.WriteSocksAssoc5UDPPacket(nil, a, nil, addr, payload)
	if err != nil {
		t.Fatalf("WriteSocksAssoc5UDPPacket Write err: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("expected n == payload len, got %d", n)
	}

	// b should receive raw socks5 assoc packet. Read raw bytes and validate header+payload.
	raw := make([]byte, 1024)
	_, from, err := b.ReadFrom(raw)
	if err != nil {
		t.Fatalf("b.ReadFrom err: %v", err)
	}
	_ = from
	// parse header using existing parser.
	out := make([]byte, 1024)
	// Use ReadSocks5AssocUDPPacket to parse from b side: but ReadSocks5AssocUDPPacket calls conn.ReadFrom internally.
	// We already consumed one raw packet above, so send another via WriteTo to test WriteTo flow.
	n2, err := protocol.WriteSocksAssoc5UDPPacket(
		nil,
		a,
		b.LocalAddr(),
		addr,
		payload,
	)
	if err != nil {
		t.Fatalf("WriteSocksAssoc5UDPPacket WriteTo err: %v", err)
	}
	if n2 != len(payload) {
		t.Fatalf("expected n2 == payload len, got %d", n2)
	}

	// Now let the package parsing helper parse the packet.
	n3, gotAddr, _, err := protocol.ReadSocks5AssocUDPPacket(
		nil,
		b,
		out,
		false,
		nil,
	)
	if err != nil {
		t.Fatalf("ReadSocks5AssocUDPPacket err: %v", err)
	}
	if n3 != len(payload) {
		t.Fatalf(
			"parsed payload len mismatch: want %d got %d",
			len(payload),
			n3,
		)
	}
	if gotAddr.IsUnspecified() {
		t.Fatalf("parsed addr is unspecified")
	}

	// payload compare
	if string(out[:n3]) != string(payload) {
		t.Fatalf("payload mismatch: %q != %q", out[:n3], payload)
	}
}

func TestWriteSocks5TUNUDPPacket_and_ReadSocks5TunUDPPacket_IPv4_IPv6_FQDN_truncation(
	t *testing.T,
) {
	// net.Pipe for conn io
	c1, c2 := net.Pipe()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	payload := []byte("tun-data-1234")
	addr := protocol.AddrFromIP(net.ParseIP("4.3.2.1"), 4444, "udp")

	// write on c1, read from c2
	go func() {
		n, err := protocol.WriteSocks5TUNUDPPacket(nil, c1, addr, payload)
		if err != nil {
			return
		}
		if n != len(payload) {
			return
		}
	}()

	// Now parse using ReadSocks5TunUDPPacket
	out := make([]byte, 2048)
	n, gotAddr, err := protocol.ReadSocks5TunUDPPacket(nil, c2, out, false)
	if err != nil {
		t.Fatalf("ReadSocks5TunUDPPacket err: %v", err)
	}
	if n != len(payload) {
		t.Fatalf(
			"tun payload len mismatch: got %d expected %d",
			n,
			len(payload),
		)
	}
	if gotAddr.IsUnspecified() {
		t.Fatalf("gotAddr unspecified")
	}

	// Test truncation: create bigger than 65535 payload
	huge := make([]byte, 70000)
	for i := range huge {
		huge[i] = byte(i)
	}
	c3, c4 := net.Pipe()
	defer func() {
		_ = c3.Close()
		_ = c4.Close()
	}()
	go func() {
		// Write will truncate internally
		_, _ = protocol.WriteSocks5TUNUDPPacket(nil, c3, addr, huge)
	}()
	out2 := make([]byte, 70000)
	n2, _, err := protocol.ReadSocks5TunUDPPacket(
		nil,
		c4,
		out2,
		true,
	) // skipAddr true to test skip branch
	if err != nil {
		t.Fatalf("ReadSocks5TunUDPPacket huge err: %v", err)
	}
	// truncated to 65535
	if n2 != 65535 {
		t.Fatalf("expected truncated length 65535, got %d", n2)
	}
}

func TestReadSocks5AssocUDPPacket_ignore_small_and_checkAddr(t *testing.T) {
	// Use a single receiver fake conn (no peer) and push packets directly into it.
	receiver := &fakePacketConn{
		in:     make(chan pkt, 8),
		local:  newUDPAddr(20000),
		closed: make(chan struct{}),
	}

	// small malformed packet first (len<8) should be ignored
	receiver.in <- pkt{data: []byte{1, 2, 3}, from: newUDPAddr(1)}

	// now a proper packet
	payload := []byte("abc-123")
	addr := protocol.AddrFromIP(net.ParseIP("7.7.7.7"), 7777, "udp")
	header := protocol.AppendSocks5UDPHeader(nil, 0, addr)
	full := append(header, payload...) //nolint
	receiver.in <- pkt{data: full, from: newUDPAddr(30000)}

	// call ReadSocks5AssocUDPPacket; it should skip the first and return the second
	out := make([]byte, 1024)
	n, gotAddr, incAddr, err := protocol.ReadSocks5AssocUDPPacket(
		nil,
		receiver,
		out,
		false,
		nil,
	)
	if err != nil {
		t.Fatalf("ReadSocks5AssocUDPPacket err: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("payload len mismatch: want %d got %d", len(payload), n)
	}
	if incAddr == nil {
		t.Fatalf("expected incAddr not nil")
	}
	if gotAddr.IsUnspecified() {
		t.Fatalf("expected parsed addr from header")
	}

	// Now test checkAddr filtering: place a packet from "wrong" source, then from "good" - the wrong should be ignored
	receiver2 := &fakePacketConn{
		in:     make(chan pkt, 8),
		local:  newUDPAddr(20001),
		closed: make(chan struct{}),
	}
	wrong := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 11111}
	good := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22222}
	hdr := protocol.AppendSocks5UDPHeader(nil, 0, addr)
	receiver2.in <- pkt{data: append(hdr, payload...), from: wrong}
	receiver2.in <- pkt{data: append(hdr, payload...), from: good}

	out2 := make([]byte, 1024)
	n2, _, incAddr2, err := protocol.ReadSocks5AssocUDPPacket(
		nil,
		receiver2,
		out2,
		false,
		good,
	)
	if err != nil {
		t.Fatalf("ReadSocks5AssocUDPPacket with checkAddr err: %v", err)
	}
	if n2 != len(payload) {
		t.Fatalf("expected payload len %d got %d", len(payload), n2)
	}
	if incAddr2 == nil {
		t.Fatalf("expected incAddr2 present")
	}
}

func TestReadSocks5TunUDPPacket_IPv4_IPv6_FQDN(t *testing.T) {
	// For this test write a properly formatted TUN packet into a net.Pipe and read it back.

	// Helper to build a raw TUN packet: rsv (2) | frag | atyp | addr... | port | payload
	build := func(rsv uint16, a protocol.Addr, payload []byte) []byte {
		h := protocol.AppendSocks5UDPHeader(nil, rsv, a)
		// Append payload
		return append(h, payload...)
	}

	// IPv4
	c1, c2 := net.Pipe()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()
	go func() {
		buf := build(
			uint16(len([]byte("p1"))), //nolint
			protocol.AddrFromIP(net.ParseIP("8.8.8.8"), 8888, "udp"),
			[]byte("p1"),
		)
		// For TUN, WriteSocks5TUNUDPPacket would write rsv then rest. We mirror that.
		_, _ = c1.Write(buf)
	}()
	out := make([]byte, 1024)
	n, addr, err := protocol.ReadSocks5TunUDPPacket(nil, c2, out, false)
	if err != nil {
		t.Fatalf("ReadSocks5TunUDPPacket ipv4 err: %v", err)
	}
	if n != 2 || string(out[:n]) != "p1" {
		t.Fatalf("unexpected ipv4 payload")
	}
	if addr.IsUnspecified() {
		t.Fatalf("expected addr")
	}

	// IPv6
	c3, c4 := net.Pipe()
	defer func() {
		_ = c3.Close()
		_ = c4.Close()
	}()
	go func() {
		buf := build(
			uint16(len([]byte("p2"))), //nolint
			protocol.AddrFromIP(net.ParseIP("::1"), 9999, "udp"),
			[]byte("p2"),
		)
		_, _ = c3.Write(buf)
	}()
	out2 := make([]byte, 1024)
	n2, addr2, err := protocol.ReadSocks5TunUDPPacket(nil, c4, out2, false)
	if err != nil {
		t.Fatalf("ReadSocks5TunUDPPacket ipv6 err: %v", err)
	}
	if n2 != 2 || string(out2[:n2]) != "p2" {
		t.Fatalf("unexpected ipv6 payload")
	}
	if addr2.IsUnspecified() {
		t.Fatalf("expected addr2")
	}

	// FQDN
	c5, c6 := net.Pipe()
	defer func() {
		_ = c5.Close()
		_ = c6.Close()
	}()
	go func() {
		host := "host.local"
		a := protocol.AddrFromFQDN(
			net.JoinHostPort(host, strconv.Itoa(3210)),
			3210,
			"udp",
		)
		buf := build(uint16(len([]byte("p3"))), a, []byte("p3")) //nolint
		_, _ = c5.Write(buf)
	}()
	out3 := make([]byte, 1024)
	n3, addr3, err := protocol.ReadSocks5TunUDPPacket(nil, c6, out3, false)
	if err != nil {
		t.Fatalf("ReadSocks5TunUDPPacket fqdn err: %v", err)
	}
	if n3 != 2 || string(out3[:n3]) != "p3" {
		t.Fatalf("unexpected fqdn payload")
	}
	if addr3.IsUnspecified() {
		t.Fatalf("expected addr3")
	}
}

func TestSocks5UDPClientAssoc_and_TUN_basic_methods(t *testing.T) {
	// Assoc tests using fakePacketConn pair
	a, b := newPacketConnPair()
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()

	oncCalled := false
	onc := func() { oncCalled = true }

	addr := protocol.AddrFromIP(net.ParseIP("2.3.4.5"), 2222, "udp")
	assoc := protocol.NewSocks5UDPClientAssoc(a, &addr, nil, onc)
	defer func() { _ = assoc.Close() }()

	// Write should write default header + payload
	payload := []byte("assoc-client")
	n, err := assoc.Write(payload)
	if err != nil {
		t.Fatalf("assoc.Write err: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("assoc.Write n mismatch: %d != %d", n, len(payload))
	}

	// b should be able to parse packet using ReadSocks5AssocUDPPacket
	out := make([]byte, 1024)
	n2, gotAddr, _, err := protocol.ReadSocks5AssocUDPPacket(
		nil,
		b,
		out,
		false,
		nil,
	)
	if err != nil {
		t.Fatalf("ReadSocks5AssocUDPPacket after assoc.Write err: %v", err)
	}
	if n2 != len(payload) || string(out[:n2]) != string(payload) {
		t.Fatalf("assoc payload mismatch")
	}
	if gotAddr.IsUnspecified() {
		t.Fatalf("assoc addr unspecified")
	}

	// Test WriteToIpPort
	n3, err := assoc.WriteToIpPort([]byte("x"), net.ParseIP("1.1.1.1"), 1111)
	if err != nil {
		t.Fatalf("WriteToIpPort err: %v", err)
	}
	if n3 != 1 {
		t.Fatalf("WriteToIpPort n mismatch")
	}

	// Test ReadFromUDP: send an IPv4 formatted packet directly into assoc.PacketConn (which is 'a')
	header := protocol.AppendSocks5UDPHeader(
		nil,
		0,
		protocol.AddrFromIP(net.ParseIP("9.9.9.9"), 9090, "udp"),
	)
	a.in <- pkt{data: append(header, []byte("u")...), from: newUDPAddr(5000)}
	outBuf := make([]byte, 1024)
	n4, udpAddr, err := assoc.ReadFromUDP(outBuf)
	if err != nil {
		t.Fatalf("assoc.ReadFromUDP err: %v", err)
	}
	if n4 != 1 || udpAddr == nil {
		t.Fatalf("assoc.ReadFromUDP unexpected result")
	}

	// Close should call onc
	_ = assoc.Close()
	if !oncCalled {
		t.Fatalf("expected onClose to be called")
	}

	// TUN client tests using net.Pipe
	laddr := protocol.AddrFromHostPort("0.0.0.0:0", "udp")
	var raddr *protocol.Addr
	c1, c2 := net.Pipe()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	tun := protocol.NewSocks5UDPClientTUN(c1, laddr, raddr, nil)
	defer func() { _ = tun.Close() }()

	// Write small payload - this will write header+payload to underlying conn (c1),
	// read from c2 and parse header to confirm payload transmission.
	go func() {
		_, _ = tun.Write([]byte("tunw"))
	}()
	// Read header first bytes to observe exists
	buf := make([]byte, 2048)
	nTun, err := c2.Read(buf)
	if err != nil {
		t.Fatalf("reading from pipe failed: %v", err)
	}
	if nTun == 0 {
		t.Fatalf("expected some bytes")
	}

	// Try ReadFrom on tun: construct a TUN-style packet and write into c2 so tun.ReadFrom reads it.
	// For convenience, use AppendSocks5UDPHeader to build a TUN packet (with non-zero RSV).
	header2 := protocol.AppendSocks5UDPHeader(
		nil,
		uint16(len([]byte("T"))), //nolint
		protocol.AddrFromIP(net.ParseIP("5.5.5.5"), 5555, "udp"),
	)
	go func() {
		_, _ = c2.Write(append(header2, []byte("T")...))
	}()
	out3 := make([]byte, 1024)
	nr, addrr, err := tun.ReadFrom(out3)
	if err != nil {
		t.Fatalf("tun.ReadFrom err: %v", err)
	}
	if nr != 1 || addrr == nil {
		t.Fatalf("tun.ReadFrom unexpected")
	}
}

func TestSocks5UDPClientAssoc_RemoteAddr_Read_ReadFrom_WriteTo_WriteToUDP(
	t *testing.T,
) {
	// Setup fake packet conn pair
	a, b := newPacketConnPair()
	defer func() {
		_ = a.Close()
		_ = b.Close()
	}()

	// 1) RemoteAddr: when raddr is set on client it should return that,
	//    when raddr is nil it should fallback to PacketConn.RemoteAddr()
	addr := protocol.AddrFromIP(net.ParseIP("10.10.10.10"), 1010, "udp")
	uc := protocol.NewSocks5UDPClientAssoc(a, &addr, nil, nil)

	// RemoteAddr() should return our configured raddr
	ra := uc.RemoteAddr()
	if ra == nil {
		t.Fatalf("RemoteAddr() returned nil")
	}
	if ra.String() != addr.String() {
		t.Fatalf(
			"RemoteAddr mismatch: want %q got %q",
			addr.String(),
			ra.String(),
		)
	}

	// Force fallback: set internal raddr to nil and expect PacketConn.RemoteAddr
	uc.Raddr = nil
	fallback := uc.RemoteAddr()
	if fallback == nil {
		t.Fatalf("RemoteAddr fallback returned nil")
	}
	if fallback.String() != a.RemoteAddr().String() {
		t.Fatalf(
			"RemoteAddr fallback mismatch: want %q got %q",
			a.RemoteAddr().String(),
			fallback.String(),
		)
	}

	// 2) Read(): push a socks5 assoc packet into underlying conn and expect Read to parse payload
	payload := []byte("assoc-read")
	header := protocol.AppendSocks5UDPHeader(
		nil,
		0,
		protocol.AddrFromIP(net.ParseIP("4.3.2.1"), 4321, "udp"),
	)
	a.in <- pkt{data: append(header, payload...), from: a.local}

	readBuf := make([]byte, 1024)
	nr, err := uc.Read(readBuf)
	if err != nil {
		t.Fatalf("uc.Read error: %v", err)
	}
	if nr != len(payload) || string(readBuf[:nr]) != string(payload) {
		t.Fatalf("uc.Read payload mismatch: got %q len=%d", readBuf[:nr], nr)
	}

	// 3) ReadFrom(): similar but returns parsed remote net.Addr
	a.in <- pkt{data: append(header, payload...), from: a.local}
	rfBuf := make([]byte, 1024)
	nrf, raddr, err := uc.ReadFrom(rfBuf)
	if err != nil {
		t.Fatalf("uc.ReadFrom error: %v", err)
	}
	if nrf != len(payload) {
		t.Fatalf("uc.ReadFrom len mismatch: want %d got %d", len(payload), nrf)
	}
	if raddr == nil {
		t.Fatalf("uc.ReadFrom returned nil addr")
	}

	// 4) WriteTo(): ensure it returns payload size and peer receives the packet
	wn, err := uc.WriteTo([]byte("WTO"), b.LocalAddr())
	if err != nil {
		t.Fatalf("uc.WriteTo error: %v", err)
	}
	if wn != 3 {
		t.Fatalf("uc.WriteTo returned wrong n: %d", wn)
	}

	// Read raw on b to verify a packet was delivered (ReadFrom will parse it).
	out := make([]byte, 1024)
	nout, gotAddr, _, err := protocol.ReadSocks5AssocUDPPacket(
		nil,
		b,
		out,
		false,
		nil,
	)
	if err != nil {
		t.Fatalf("ReadSocks5AssocUDPPacket after WriteTo error: %v", err)
	}
	if nout != 3 || string(out[:nout]) != "WTO" {
		t.Fatalf("payload mismatch after WriteTo: %q", out[:nout])
	}
	if gotAddr.IsUnspecified() {
		t.Fatalf("parsed addr after WriteTo unspecified")
	}

	// 5) WriteToUDP(): same as WriteTo but typed UDPAddr
	uaddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
	wn2, err := uc.WriteToUDP([]byte("UDP"), uaddr)
	if err != nil {
		t.Fatalf("uc.WriteToUDP error: %v", err)
	}
	if wn2 != 3 {
		t.Fatalf("uc.WriteToUDP returned wrong n: %d", wn2)
	}

	// consume packet on b
	out2 := make([]byte, 1024)
	nout2, _, _, err := protocol.ReadSocks5AssocUDPPacket(
		nil,
		b,
		out2,
		false,
		nil,
	)
	if err != nil {
		t.Fatalf("ReadSocks5AssocUDPPacket after WriteToUDP error: %v", err)
	}
	if nout2 != 3 {
		t.Fatalf("payload len mismatch after WriteToUDP")
	}
}

func TestSocks5UDPClientTUN_RemoteLocal_Read_ReadFromUDP_WriteTo_variants(
	t *testing.T,
) {
	// Use net.Pipe for conn pair; client will use one side.
	c1, c2 := net.Pipe()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	// Setup laddr and raddr for client
	laddr := protocol.AddrFromHostPort("1.1.1.1:1111", "udp")
	raddr := protocol.AddrFromHostPort("2.2.2.2:2222", "udp")
	tun := protocol.NewSocks5UDPClientTUN(c1, laddr, &raddr, nil)

	// 1) RemoteAddr() & LocalAddr() when fields are set
	if tun.RemoteAddr().String() != raddr.String() {
		t.Fatalf(
			"tun.RemoteAddr mismatch: want %q got %q",
			raddr.String(),
			tun.RemoteAddr().String(),
		)
	}
	if tun.LocalAddr().String() != laddr.String() {
		t.Fatalf(
			"tun.LocalAddr mismatch: want %q got %q",
			laddr.String(),
			tun.LocalAddr().String(),
		)
	}

	// Underlying conn's LocalAddr/RemoteAddr are non-nil but for net.Pipe they are nil,
	// so we only assert they are not nil when set previously. Restore fields.
	tun.Laddr = laddr
	tun.Raddr = &raddr

	// 2) Read(): build a TUN packet on c2 and ensure Read parses payload when skipAddr=true
	pl := []byte("tun-read")
	header := protocol.AppendSocks5UDPHeader(
		nil,
		uint16(len(pl)), //nolint
		protocol.AddrFromIP(net.ParseIP("3.3.3.3"), 3333, "udp"),
	)
	go func() {
		_, _ = c2.Write(append(header, pl...))
	}()

	readBuf := make([]byte, 1024)
	nr, err := tun.Read(readBuf)
	if err != nil {
		t.Fatalf("tun.Read error: %v", err)
	}
	if nr != len(pl) || string(readBuf[:nr]) != string(pl) {
		t.Fatalf("tun.Read payload mismatch: got=%q", readBuf[:nr])
	}

	// 3) ReadFromUDP(): write a TUN packet with IPv4 addr into c2 and expect *net.UDPAddr
	pl2 := []byte("tun-rfrom-udp")
	hdr2 := protocol.AppendSocks5UDPHeader(
		nil,
		uint16(len(pl2)), //nolint
		protocol.AddrFromIP(net.ParseIP("5.5.5.5"), 5555, "udp"),
	)
	go func() {
		_, _ = c2.Write(append(hdr2, pl2...))
	}()

	out := make([]byte, 2048)
	nr2, udpAddr, err := tun.ReadFromUDP(out)
	if err != nil {
		t.Fatalf("tun.ReadFromUDP error: %v", err)
	}
	if nr2 != len(pl2) || string(out[:nr2]) != string(pl2) {
		t.Fatalf("tun.ReadFromUDP payload mismatch")
	}
	if udpAddr == nil {
		t.Fatalf("tun.ReadFromUDP returned nil udp addr")
	}
	if udpAddr.Port != 5555 {
		t.Fatalf(
			"tun.ReadFromUDP port mismatch: want 5555 got %d",
			udpAddr.Port,
		)
	}

	// 4) WriteTo(): write a TUN packet to underlying conn using Addr (IP) and ensure other side receives it
	dstAddr := protocol.AddrFromIP(net.ParseIP("7.7.7.7"), 7777, "udp")
	payload := []byte("tun-wto")
	// Call WriteTo (writes header then payload to c1 -> c2)
	wnchan := make(chan int, 1)
	errchan := make(chan error, 1)
	go func() {
		wn, err := tun.WriteTo(payload, dstAddr)
		errchan <- err
		wnchan <- wn
	}()
	// Read back on c2 using ReadSocks5TunUDPPacket to verify payload
	out2 := make([]byte, 4096)
	nr3, gotAddr, err := protocol.ReadSocks5TunUDPPacket(nil, c2, out2, false)
	if err != nil {
		t.Fatalf("ReadSocks5TunUDPPacket after tun.WriteTo error: %v", err)
	}
	err = <-errchan
	wn := <-wnchan
	if err != nil {
		t.Fatalf("tun.WriteTo error: %v", err)
	}
	if wn != len(payload) {
		t.Fatalf("tun.WriteTo returned wrong n: %d", wn)
	}
	if nr3 != len(payload) || string(out2[:nr3]) != string(payload) {
		t.Fatalf("payload mismatch after tun.WriteTo")
	}
	if gotAddr.IsUnspecified() {
		t.Fatalf("gotAddr unspecified after tun.WriteTo")
	}

	// 5) WriteToUDP(): similar but use *net.UDPAddr
	uaddr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 8888}
	go func() {
		wn, err := tun.WriteToUDP([]byte("tun-udp"), uaddr)
		errchan <- err
		wnchan <- wn
	}()
	// Read and parse it
	out3 := make([]byte, 4096)
	nr4, _, err := protocol.ReadSocks5TunUDPPacket(nil, c2, out3, true)
	if err != nil {
		t.Fatalf("ReadSocks5TunUDPPacket after tun.WriteToUDP error: %v", err)
	}
	err = <-errchan
	if err != nil {
		t.Fatalf("tun.WriteToUDP error: %v", err)
	}
	wn = <-wnchan
	if wn != 7 {
		t.Fatalf("tun.WriteToUDP returned wrong n: %d", wn)
	}
	if nr4 != 7 {
		t.Fatalf("expected 7 bytes from tun.WriteToUDP, got %d", nr4)
	}

	// 6) WriteToIpPort(): test writing by raw ip+port
	go func() {
		wn, err := tun.WriteToIpPort(
			[]byte("by-ip"),
			net.ParseIP("9.9.9.9"),
			9999,
		)
		errchan <- err
		wnchan <- wn
	}()
	// parse and confirm
	out4 := make([]byte, 4096)
	nr5, _, err := protocol.ReadSocks5TunUDPPacket(nil, c2, out4, true)
	if err != nil {
		t.Fatalf("ReadSocks5TunUDPPacket after tun.WriteToIpPort err: %v", err)
	}
	err = <-errchan
	if err != nil {
		t.Fatalf("tun.WriteToIpPort error: %v", err)
	}
	wn = <-wnchan
	if wn != 5 {
		t.Fatalf("tun.WriteToIpPort returned wrong n: %d", wn)
	}
	if nr5 != 5 {
		t.Fatalf("expected 5 bytes from tun.WriteToIpPort, got %d", nr5)
	}

	// cleanup
	_ = tun.Close()
}

// Test ProxySocks5UDPTun in the "unbinded" case (proxy.WriteTo path)
func TestProxySocks5UDPTun_Unbinded(t *testing.T) {
	// net.Pipe for tun side: pass one end into Proxy, use the other to drive/observe
	tunLocal, tunRemote := net.Pipe()
	defer tunLocal.Close() //nolint
	// fake PacketConn pair for proxy: pass one end into Proxy, use peer to observe/send
	proxyA, proxyB := newPacketConnPair()
	defer proxyA.Close() //nolint
	defer proxyB.Close() //nolint

	// Run ProxySocks5UDPTun in goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- protocol.ProxySocks5UDPTun(
			tunLocal,
			proxyA,
			false, // binded=false -> WriteTo path
			nil,   // no default addr
			nil,   // pool nil fine for tests
			2048,  // bufSize
		)
	}()

	// 1) tun -> proxy: write a TUN packet into tunRemote and expect proxyB to receive raw payload
	payload := []byte("proxy-tun-unbinded")
	addr := protocol.AddrFromIP(net.ParseIP("10.11.12.13"), 31337, "udp")
	header := protocol.AppendSocks5UDPHeader(
		nil,
		uint16(len(payload)), //nolint
		addr,
	) //nolint
	_, _ = tunRemote.Write(append(header, payload...))

	// Read on proxyB in goroutine so we can timeout safely
	type readRes struct {
		n   int
		a   net.Addr
		err error
		buf []byte
	}
	gotCh := make(chan readRes, 1)
	go func() {
		buf := make([]byte, 4096)
		n, from, err := proxyB.ReadFrom(buf)
		r := readRes{n: n, a: from, err: err, buf: buf[:n]}
		gotCh <- r
	}()

	select {
	case r := <-gotCh:
		if r.err != nil {
			t.Fatalf("proxyB.ReadFrom error: %v", r.err)
		}
		if string(r.buf) != string(payload) {
			t.Fatalf(
				"tun->proxy payload mismatch: want %q got %q",
				payload,
				r.buf,
			)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout waiting for proxy to receive payload from tun")
	}

	// 2) proxy -> tun: write a packet from proxyB side (peer) so Proxy will ReadFrom it and write TUN packet to tunLocal.
	reversePayload := []byte("reverse-to-tun")
	// Write on proxyB (this will deliver into proxyA.in which Proxy reads from)
	_, _ = proxyB.Write(reversePayload)

	// Read on tunRemote using ReadSocks5TunUDPPacket (it will parse header+payload written by Proxy)
	tunGotCh := make(chan struct {
		n   int
		err error
		buf []byte
	}, 1)
	go func() {
		out := make([]byte, 8192)
		n, _, err := protocol.ReadSocks5TunUDPPacket(
			nil,
			tunRemote,
			out,
			true,
		) // skipAddr true ok for payload check
		tunGotCh <- struct {
			n   int
			err error
			buf []byte
		}{n: n, err: err, buf: append([]byte(nil), out[:n]...)}
	}()

	select {
	case r := <-tunGotCh:
		if r.err != nil {
			t.Fatalf("failed to read TUN packet written by Proxy: %v", r.err)
		}
		if r.n != len(reversePayload) ||
			string(r.buf) != string(reversePayload) {
			t.Fatalf(
				"proxy->tun payload mismatch: want %q got %q",
				reversePayload,
				r.buf,
			)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout waiting for tun to receive reverse payload")
	}

	// Close proxyA to cause ProxySocks5UDPTun to finish
	_ = proxyA.Close()

	// Wait for the Proxy to return
	select {
	case <-errCh:
		// function may return nil or an EOF-joined error — accept nil or non-nil (we just ensure it returned)
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for ProxySocks5UDPTun to exit (unbinded)")
	}
}

// Test ProxySocks5UDPTun in the "binded" case (proxy.Write path)
func TestProxySocks5UDPTun_Binded(t *testing.T) {
	tunLocal, tunRemote := net.Pipe()
	defer tunLocal.Close() //nolint

	proxyA, proxyB := newPacketConnPair()
	defer proxyA.Close() //nolint
	defer proxyB.Close() //nolint

	errCh := make(chan error, 1)
	go func() {
		errCh <- protocol.ProxySocks5UDPTun(
			tunLocal,
			proxyA,
			true, // binded=true -> proxy.Write path
			nil,
			nil,
			2048,
		)
	}()

	// 1) tun -> proxy (binded uses proxy.Write)
	payload := []byte("proxy-tun-binded")
	addr := protocol.AddrFromIP(net.ParseIP("1.2.3.4"), 4444, "udp")
	hdr := protocol.AppendSocks5UDPHeader(
		nil,
		uint16(len(payload)), //nolint
		addr,
	) //nolint
	_, _ = tunRemote.Write(append(hdr, payload...))

	got := make(chan struct {
		n int
		b []byte
	}, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _, _ := proxyB.ReadFrom(buf)
		got <- struct {
			n int
			b []byte
		}{n: n, b: append([]byte(nil), buf[:n]...)}
	}()

	select {
	case r := <-got:
		if r.n != len(payload) || string(r.b) != string(payload) {
			t.Fatalf(
				"binded tun->proxy payload mismatch: want %q got %q",
				payload,
				r.b,
			)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf(
			"timeout waiting for proxy to receive payload from tun (binded)",
		)
	}

	// 2) proxy -> tun: use proxyB.Write (peer) so proxyA.ReadFrom will receive and Proxy will write to tun
	reverse := []byte("binded-reverse")
	_, _ = proxyB.Write(reverse)

	tunGot := make(chan struct {
		n int
		b []byte
	}, 1)
	go func() {
		out := make([]byte, 8192)
		n, _, err := protocol.ReadSocks5TunUDPPacket(nil, tunRemote, out, true)
		if err != nil {
			tunGot <- struct {
				n int
				b []byte
			}{n: -1, b: []byte(err.Error())}
			return
		}
		tunGot <- struct {
			n int
			b []byte
		}{n: n, b: append([]byte(nil), out[:n]...)}
	}()

	select {
	case r := <-tunGot:
		if r.n != len(reverse) || string(r.b) != string(reverse) {
			t.Fatalf(
				"binded proxy->tun payload mismatch: want %q got %q",
				reverse,
				r.b,
			)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout waiting for tun to receive reverse payload (binded)")
	}

	_ = proxyA.Close()

	select {
	case <-errCh:
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for ProxySocks5UDPTun to exit (binded)")
	}
}

// fakeCtrlConn simulates a control connection whose RemoteAddr returns the
// provided addr. Read() blocks until Close() is called and then returns EOF.
// This matches how internal.WaitForClose likely waits for ctrl to be closed.
type fakeCtrlConn struct {
	closed chan struct{}
	remote net.Addr
}

func newFakeCtrlConn(remote net.Addr) *fakeCtrlConn {
	return &fakeCtrlConn{
		closed: make(chan struct{}),
		remote: remote,
	}
}

func (f *fakeCtrlConn) Read(b []byte) (int, error) {
	<-f.closed
	return 0, io.EOF
}
func (f *fakeCtrlConn) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeCtrlConn) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}
func (f *fakeCtrlConn) LocalAddr() net.Addr                { return nil }
func (f *fakeCtrlConn) RemoteAddr() net.Addr               { return f.remote }
func (f *fakeCtrlConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeCtrlConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeCtrlConn) SetWriteDeadline(t time.Time) error { return nil }

// Test ProxySocks5UDPAssoc unbinded path (binded=false)
func TestProxySocks5UDPAssoc_Unbinded(t *testing.T) {
	assocA, assocB := newPacketConnPair()
	defer assocA.Close() //nolint
	defer assocB.Close() //nolint

	proxyA, proxyB := newPacketConnPair()
	defer proxyA.Close() //nolint
	defer proxyB.Close() //nolint

	// ctrl.RemoteAddr must match client's incAddr host for clientUDPAddr selection.
	clientIP := net.ParseIP("127.0.0.1")
	ctrlAddr := &net.UDPAddr{IP: clientIP, Port: 60000}
	ctrl := newFakeCtrlConn(ctrlAddr)

	doneCh := make(chan error, 1)
	go func() {
		err := protocol.ProxySocks5UDPAssoc(
			assocA,        // assoc PacketConn
			proxyA,        // proxy PacketConn
			ctrl,          // ctrl conn
			false,         // binded=false -> unbinded path
			nil,           // defaultAddr
			nil,           // pool
			2048,          // bufSize
			1*time.Second, // timeOut
		)
		doneCh <- err
	}()

	// 1) assoc -> proxy: send a socks5 assoc UDP packet into assocA.
	clientFrom := &net.UDPAddr{IP: clientIP, Port: 50001}
	payload := []byte("assoc-to-proxy-unbinded")
	dst := protocol.AddrFromIP(net.ParseIP("9.9.9.9"), 9999, "udp")
	hdr := protocol.AppendSocks5UDPHeader(nil, 0, dst)
	assocA.in <- pkt{data: append(hdr, payload...), from: clientFrom}

	// Expect proxyB to receive payload forwarded from assoc
	readCh := make(chan struct {
		n   int
		buf []byte
	}, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _, _ := proxyB.ReadFrom(
			buf,
		) // fakePacketConn.ReadFrom returns (n, from, nil)
		readCh <- struct {
			n   int
			buf []byte
		}{n: n, buf: append([]byte(nil), buf[:n]...)}
	}()

	select {
	case r := <-readCh:
		if r.n != len(payload) || string(r.buf) != string(payload) {
			t.Fatalf(
				"assoc->proxy payload mismatch: want %q got %q",
				payload,
				r.buf,
			)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout waiting for proxy to receive assoc packet (unbinded)")
	}

	// 2) proxy -> assoc (reverse): write a packet to proxyB; expect assocB to receive a socks5 assoc packet
	reverse := []byte("proxy-to-assoc-unbinded")
	_, _ = proxyB.Write(
		reverse,
	) // sends to proxyA.in; reverse goroutine should read and forward to assoc

	// assocB should be able to parse the socks5 assoc packet produced by reverse goroutine.
	out := make([]byte, 4096)
	n, gotAddr, _, err := protocol.ReadSocks5AssocUDPPacket(
		nil,
		assocB,
		out,
		false,
		nil,
	)
	if err != nil {
		t.Fatalf("ReadSocks5AssocUDPPacket (reverse) err: %v", err)
	}
	if n != len(reverse) || string(out[:n]) != string(reverse) {
		t.Fatalf(
			"proxy->assoc payload mismatch: want %q got %q",
			reverse,
			out[:n],
		)
	}
	if gotAddr.IsUnspecified() {
		t.Fatalf("proxy->assoc parsed addr unspecified")
	}

	// shutdown ctrl to stop ProxySocks5UDPAssoc
	_ = ctrl.Close()

	select {
	case <-doneCh:
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for ProxySocks5UDPAssoc to exit (unbinded)")
	}
}

// Test ProxySocks5UDPAssoc binded path (binded=true)
func TestProxySocks5UDPAssoc_Binded(t *testing.T) {
	assocA, assocB := newPacketConnPair()
	defer assocA.Close() //nolint
	defer assocB.Close() //nolint

	proxyA, proxyB := newPacketConnPair()
	defer proxyA.Close() //nolint
	defer proxyB.Close() //nolint

	clientIP := net.ParseIP("127.0.0.1")
	ctrlAddr := &net.UDPAddr{IP: clientIP, Port: 61000}
	ctrl := newFakeCtrlConn(ctrlAddr)

	doneCh := make(chan error, 1)
	go func() {
		err := protocol.ProxySocks5UDPAssoc(
			assocA,
			proxyA,
			ctrl,
			true, // binded=true -> proxy.Write path
			nil,
			nil,
			2048,
			1*time.Second,
		)
		doneCh <- err
	}()

	// 1) assoc -> proxy (binded): send header+payload into assocA; proxyB should receive the payload via Write.
	clientFrom := &net.UDPAddr{IP: clientIP, Port: 50002}
	payload := []byte("assoc-to-proxy-binded")
	dst := protocol.AddrFromIP(net.ParseIP("8.8.4.4"), 8888, "udp")
	hdr := protocol.AppendSocks5UDPHeader(nil, 0, dst)
	assocA.in <- pkt{data: append(hdr, payload...), from: clientFrom}

	// read from proxyB
	readCh := make(chan struct {
		n   int
		buf []byte
	}, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _, _ := proxyB.ReadFrom(buf)
		readCh <- struct {
			n   int
			buf []byte
		}{n: n, buf: append([]byte(nil), buf[:n]...)}
	}()

	select {
	case r := <-readCh:
		if r.n != len(payload) || string(r.buf) != string(payload) {
			t.Fatalf(
				"binded assoc->proxy payload mismatch: want %q got %q",
				payload,
				r.buf,
			)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("timeout waiting for proxy to receive assoc packet (binded)")
	}

	// 2) proxy -> assoc (reverse): proxyB.Write(reverse) should result in a TUN-like packet on assocB
	reverse := []byte("proxy-to-assoc-binded")
	_, _ = proxyB.Write(reverse)

	out := make([]byte, 4096)
	n, gotAddr, _, err := protocol.ReadSocks5AssocUDPPacket(
		nil,
		assocB,
		out,
		false,
		nil,
	)
	if err != nil {
		t.Fatalf("ReadSocks5AssocUDPPacket (binded reverse) err: %v", err)
	}
	if n != len(reverse) || string(out[:n]) != string(reverse) {
		t.Fatalf(
			"binded proxy->assoc payload mismatch: want %q got %q",
			reverse,
			out[:n],
		)
	}
	if gotAddr.IsUnspecified() {
		t.Fatalf("binded proxy->assoc parsed addr unspecified")
	}

	// shutdown ctrl to stop ProxySocks5UDPAssoc
	_ = ctrl.Close()

	select {
	case <-doneCh:
	case <-time.After(1 * time.Second):
		t.Fatalf("timeout waiting for ProxySocks5UDPAssoc to exit (binded)")
	}
}
