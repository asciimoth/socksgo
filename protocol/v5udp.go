package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/asciimoth/socks/internal"
)

// For standart socks UDP ASSOC leave rsv == 0.
// For gost's UDP TUN extension
func AppendSocks5UDPHeader(
	buf []byte,
	rsv uint16,
	addr Addr,
) []byte {
	buf = binary.BigEndian.AppendUint16(buf, rsv)
	frag := byte(0)
	if rsv != 0 {
		// gost's UDP TUN extension used
		frag = GOST_UDP_FRAG_FLAG
	}
	buf = append(buf, frag, byte(addr.Type))
	if ip := addr.ToIP(); ip != nil {
		buf = append(buf, ip...)
	} else {
		host := addr.Host
		if len(host) > MAX_HEADER_STR_LENGTH {
			host = host[:MAX_HEADER_STR_LENGTH]
		}
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = binary.BigEndian.AppendUint16(buf, addr.Port)
	return buf
}

func WriteSocks5UDPPacket(
	pool BufferPool,
	conn net.Conn,
	addr Addr,
	data []byte,
) (n int, err error) {
	if _, ok := conn.(net.PacketConn); ok {
		// conn is a packet one (udp)
		// standart UDP ASSOC should be used

		buf := internal.GetBuffer(pool, MAX_SOCKS_UDP_HEADER_LEN+len(data))[:0]
		defer internal.PutBuffer(pool, buf)

		buf = AppendSocks5UDPHeader(buf, 0, addr)
		hlen := len(buf) // header length
		buf = append(buf, data...)

		n64, err := io.Copy(conn, bytes.NewReader(data))
		n = max(0, int(n64)-hlen)
		return n, err
	} else {
		// conn is not a packet one (udp) conn
		// gost's UDP TUN extension should be used

		if len(data) > 65535 {
			data = data[:65535]
		}
		rsv := uint16(len(data))

		buf := internal.GetBuffer(pool, MAX_SOCKS_UDP_HEADER_LEN)[:0]
		defer internal.PutBuffer(pool, buf)

		header := AppendSocks5UDPHeader(buf, rsv, addr)
		_, err = io.Copy(conn, bytes.NewReader(header))
		if err != nil {
			return
		}
		n64, err := io.Copy(conn, bytes.NewReader(data))
		n = int(n64)
		return n, err
	}
}

func readStandartSocks5UDPPacket(
	pool BufferPool,
	conn net.Conn,
	p []byte,
	skipAddr bool,
) (n int, addr Addr, err error) {
	buf := internal.GetBuffer(pool, len(p)+MAX_SOCKS_UDP_HEADER_LEN)
	defer internal.PutBuffer(pool, buf)
loop:
	for {
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		if n < 8 {
			// Packet is too small to contain any meaningfull socks5 header
			continue
		}

		if buf[0] != 0 || buf[1] != 0 {
			// RSV is not 0
			continue
		}
		if buf[2] != 0 {
			// Fragmentation is not supported
			// TODO: Add fragmentation support
			continue
		}

		start := 0 // Place in pkg where paylaod starts
		switch AddrType(buf[3]) {
		case IP4Addr:
			if n < 10 {
				// Packet is too small
				continue loop
			}
			start = 10

			if !skipAddr {
				ip := net.IP(internal.CopyBytes(buf[4:8]))
				port := binary.BigEndian.Uint16(buf[8:10])
				addr = AddrFromIP(ip, port, conn.LocalAddr().Network())
			}
		case IP6Addr:
			if n < 22 {
				// Packet is too small
				continue loop
			}
			start = 22

			if !skipAddr {
				ip := net.IP(internal.CopyBytes(buf[4:20]))
				port := binary.BigEndian.Uint16(buf[20:22])
				addr = AddrFromIP(ip, port, conn.LocalAddr().Network())
			}
		case FQDNAddr:
			ln := int(buf[4])
			if n < 7+ln {
				// Packet is too small
				continue loop
			}
			start = 7 + ln

			if !skipAddr {
				dom := string(buf[5 : 5+ln])
				port := binary.BigEndian.Uint16(buf[5+ln : 5+ln+2])
				host := net.JoinHostPort(dom, strconv.Itoa(int(port)))
				addr = AddrFromFQDN(host, port, conn.LocalAddr().Network())
			}
		default:
			// Unknown address type
			continue loop
		}
		n = copy(p, buf[start:n])
		return n, addr, nil
	}
}

func readSocks5TunUDPPacket(
	pool BufferPool,
	conn net.Conn,
	p []byte,
	skipAddr bool,
) (n int, addr Addr, err error) {
	hbuf := p // Header buffer
	if len(hbuf) < MAX_SOCKS_TCP_HEADER_LEN {
		hbuf = make([]byte, MAX_SOCKS_TCP_HEADER_LEN)
	}

	for {
		// If pkg is malformed or unsupproted for any reason we still need to
		// read it before continue to next one.
		skip := false

		_, err = io.ReadFull(conn, hbuf[:5])
		if err != nil {
			return
		}

		plen := int(binary.BigEndian.Uint16(hbuf[:2])) // payload length
		atyp := AddrType(hbuf[3])                      // Addr type
		fb := hbuf[4]                                  // First byte of addr

		// If frag, then we should just read whole package and drop it
		frag := hbuf[2] != 0 && hbuf[2] != GOST_UDP_FRAG_FLAG

		if frag {
			skip = true
		}

		switch atyp {
		case IP4Addr:
			_, err = io.ReadFull(conn, hbuf[:5]) // ip4 + port - 1
			if err != nil {
				return
			}
			if !skipAddr && !skip {
				ip := net.IP([]byte{fb, hbuf[0], hbuf[1], hbuf[2]})
				port := binary.BigEndian.Uint16(hbuf[3:5])
				addr = AddrFromIP(ip, port, conn.LocalAddr().Network())
			}
		case IP6Addr:
			_, err = io.ReadFull(conn, hbuf[:17]) // ip6 + port - 1
			if err != nil {
				return
			}
			if !skipAddr && !skip {
				ip := net.IP([]byte{
					fb, hbuf[0], hbuf[1], hbuf[2],
					hbuf[3], hbuf[4], hbuf[5], hbuf[6],
					hbuf[7], hbuf[8], hbuf[9], hbuf[10],
					hbuf[11], hbuf[12], hbuf[13], hbuf[14],
				})
				port := binary.BigEndian.Uint16(hbuf[15:17])
				addr = AddrFromIP(ip, port, conn.LocalAddr().Network())
			}
		case FQDNAddr:
			ln := int(fb)
			_, err = io.ReadFull(conn, hbuf[:ln+2]) // dom + port
			if err != nil {
				return
			}
			if !skipAddr && !skip {
				port := binary.BigEndian.Uint16(hbuf[ln : ln+2])
				host := net.JoinHostPort(string(hbuf[:ln]), strconv.Itoa(int(port)))
				addr = AddrFromFQDN(host, port, conn.LocalAddr().Network())
			}
		default:
			err = fmt.Errorf("unknown atyp: %s", atyp)
			return
		}
		if len(p) < plen {
			// Read with tmp buffer
			tmpbuf := internal.GetBuffer(pool, plen)
			_, err = io.ReadFull(conn, tmpbuf)
			if err == nil {
				n = copy(p, tmpbuf)
			}
			internal.PutBuffer(pool, tmpbuf)
		} else {
			n, err = io.ReadFull(conn, p[:plen])
		}
		if err != nil {
			return
		}
		if skip {
			continue
		}
		return
	}
}

func ReadSocks5UDPPacket(
	pool BufferPool,
	conn net.Conn,
	p []byte,
	skipAddr bool, // Optimisation option
) (n int, addr Addr, err error) {
	if _, ok := conn.(net.PacketConn); ok {
		// conn is a packet one (udp)
		// standart UDP ASSOC should be used
		return readStandartSocks5UDPPacket(pool, conn, p, skipAddr)
	} else {
		// conn is not a packet one (udp) conn
		// gost's UDP TUN extension should be used
		return readSocks5TunUDPPacket(pool, conn, p, skipAddr)
	}
}
