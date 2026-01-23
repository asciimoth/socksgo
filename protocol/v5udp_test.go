package protocol_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

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
			expected: []byte{0x00, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x1F, 0x90},
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
				t.Errorf("AppendSocks5UDPHeader() = %v, want %v", result, tt.expected)
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
				buf = append(buf, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}...)
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
				buf1 = binary.BigEndian.AppendUint16(buf1, 0)  // RSV=0
				buf1 = append(buf1, 1)                         // FRAG=1 (fragmented)
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
							Addr:    NetAddr{Addr: "192.168.1.1:80", Net: "udp"},
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
				buf1 = binary.BigEndian.AppendUint16(buf1, 1)  // RSV=1 (not zero)
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
							Addr:    NetAddr{Addr: "192.168.1.1:80", Net: "udp"},
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
			conn := tt.setupConn()
			buf := make([]byte, 500) // Buffer for reading

			n, addr, _, err := protocol.ReadSocks5AssocUDPPacket(nil, conn, buf, tt.skipAddr, nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("ReadSocks5UDPPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if n != tt.wantN {
					t.Errorf("ReadSocks5UDPPacket() n = %v, want %v", n, tt.wantN)
				}

				if !tt.skipAddr {
					if tt.wantAddr.String() != addr.String() {
						t.Errorf("expected addr %s but got %s", tt.wantAddr.String(), addr.String())
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
				buf = binary.BigEndian.AppendUint16(buf, uint16(len(payload))) // RSV = payload length
				buf = append(buf, protocol.GOST_UDP_FRAG_FLAG)                 // FRAG flag for TUN
				buf = append(buf, byte(protocol.IP4Addr))                      // ATYP=IPv4
				buf = append(buf, []byte{172, 16, 0, 1}...)                    // IPv4
				buf = binary.BigEndian.AppendUint16(buf, 3306)                 // PORT (MySQL)
				buf = append(buf, payload...)                                  // payload

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
				buf = binary.BigEndian.AppendUint16(buf, uint16(len(payload))) // RSV
				buf = append(buf, protocol.GOST_UDP_FRAG_FLAG)                 // FRAG flag
				buf = append(buf, byte(protocol.IP6Addr))                      // ATYP=IPv6
				// IPv6: ::1
				buf = append(buf, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}...)
				buf = binary.BigEndian.AppendUint16(buf, 5432) // PORT (PostgreSQL)
				buf = append(buf, payload...)                  // payload

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
				buf = binary.BigEndian.AppendUint16(buf, uint16(len(payload))) // RSV
				buf = append(buf, protocol.GOST_UDP_FRAG_FLAG)                 // FRAG flag
				buf = append(buf, byte(protocol.FQDNAddr))                     // ATYP=FQDN
				buf = append(buf, byte(9))                                     // Domain length
				buf = append(buf, []byte("localhost")...)                      // Domain
				buf = binary.BigEndian.AppendUint16(buf, 6379)                 // PORT (Redis)
				buf = append(buf, payload...)                                  // payload

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
				buf = binary.BigEndian.AppendUint16(buf, uint16(len(payload))) // RSV
				buf = append(buf, protocol.GOST_UDP_FRAG_FLAG)                 // FRAG flag
				buf = append(buf, byte(protocol.IP4Addr))                      // ATYP=IPv4
				buf = append(buf, []byte{192, 168, 0, 100}...)                 // IPv4
				buf = binary.BigEndian.AppendUint16(buf, 22)                   // PORT (SSH)
				buf = append(buf, payload...)                                  // payload

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
				buf1 = binary.BigEndian.AppendUint16(buf1, uint16(len(payload1))) // RSV
				buf1 = append(buf1, 0x01)                                         // FRAG=1 (fragmented, not GOST flag)
				buf1 = append(buf1, byte(protocol.IP4Addr))                       // ATYP=IPv4
				buf1 = append(buf1, []byte{10, 0, 0, 1}...)                       // IPv4
				buf1 = binary.BigEndian.AppendUint16(buf1, 80)                    // PORT
				buf1 = append(buf1, payload1...)                                  // payload

				// Second valid packet
				payload2 := []byte("valid tcp data")
				buf2 := make([]byte, 0, 1024)
				buf2 = binary.BigEndian.AppendUint16(buf2, uint16(len(payload2))) // RSV
				buf2 = append(buf2, protocol.GOST_UDP_FRAG_FLAG)                  // FRAG flag
				buf2 = append(buf2, byte(protocol.IP4Addr))                       // ATYP=IPv4
				buf2 = append(buf2, []byte{192, 168, 1, 10}...)                   // IPv4
				buf2 = binary.BigEndian.AppendUint16(buf2, 8080)                  // PORT
				buf2 = append(buf2, payload2...)                                  // payload

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
				buf = binary.BigEndian.AppendUint16(buf, uint16(len(largePayload))) // RSV
				buf = append(buf, protocol.GOST_UDP_FRAG_FLAG)                      // FRAG flag
				buf = append(buf, byte(protocol.IP4Addr))                           // ATYP=IPv4
				buf = append(buf, []byte{8, 8, 8, 8}...)                            // IPv4 (8.8.8.8)
				buf = binary.BigEndian.AppendUint16(buf, 53)                        // PORT (DNS)
				buf = append(buf, largePayload...)                                  // payload

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
			conn := tt.setupConn()
			buf := make([]byte, 500) // Buffer for reading

			n, addr, err := protocol.ReadSocks5TunUDPPacket(nil, conn, buf, tt.skipAddr)

			if (err != nil) != tt.wantErr {
				t.Errorf("ReadSocks5UDPPacket() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if n != tt.wantN {
					t.Errorf("ReadSocks5UDPPacket() n = %v, want %v", n, tt.wantN)
				}

				if !tt.skipAddr {
					if tt.wantAddr.String() != addr.String() {
						t.Errorf("expected addr %s but got %s", tt.wantAddr.String(), addr.String())
					}
				}
			}
		})
	}
}
