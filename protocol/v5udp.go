package protocol

// SOCKS5 UDP protocol implementation.
//
// This file implements SOCKS5 UDP ASSOCIATE (RFC 1928) and Gost's UDP Tunnel
// extension for UDP relay over SOCKS5 proxies.
//
// # Standard UDP ASSOC (RFC 1928)
//
// The UDP ASSOCIATE command establishes a UDP relay association. The client
// sends a UDP ASSOCIATE request over TCP, and the server responds with a
// bound UDP address. UDP packets are then sent to/from this address with a
// SOCKS5 UDP header:
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
//
// Where:
//   - RSV: Reserved (0x0000)
//   - FRAG: Fragment flag (0x00 = no fragmentation)
//   - ATYP: Address type
//   - DST.ADDR/DST.PORT: Destination address
//   - DATA: UDP payload
//
// # Gost UDP Tunnel Extension
//
// Gost's UDP Tunnel encapsulates UDP packets over TCP instead of UDP.
// The format differs from standard UDP ASSOC:
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
//
// Where:
//   - RSV: Payload length (big-endian uint16)
//   - FRAG: Always 0xFF (GOST_UDP_FRAG_FLAG)
//   - ATYP: Address type
//   - DST.ADDR/DST.PORT: Destination address
//   - DATA: UDP payload
//
// # Implementations
//
//   - Socks5UDPClientAssoc: Standard UDP ASSOC over UDP
//   - Socks5UDPClientTUN: Gost UDP Tunnel over TCP

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect/helpers"
	"github.com/asciimoth/socksgo/internal"
)

// Socks5UDPClient is the interface for SOCKS5 UDP clients.
//
// This interface combines net.Conn and net.PacketConn to support both
// stream-oriented and packet-oriented operations. It's implemented by:
//   - Socks5UDPClientAssoc: Standard UDP ASSOC
//   - Socks5UDPClientTUN: Gost UDP Tunnel
//
// # Methods
//
//   - Read/Write: Stream-oriented I/O (uses default remote address)
//   - ReadFrom/WriteTo: Packet-oriented I/O with explicit addresses
//   - ReadFromUDP/WriteToUDP: UDP-specific packet I/O
//   - WriteToIpPort: Write to a specific IP and port
type Socks5UDPClient interface {
	net.Conn
	net.PacketConn

	WriteToIpPort(p []byte, ip net.IP, port uint16) (n int, err error)

	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
}

var (
	_ Socks5UDPClient = &Socks5UDPClientAssoc{}
	_ Socks5UDPClient = &Socks5UDPClientTUN{}
)

type PacketConn interface {
	net.Conn
	net.PacketConn
}

func WriteToAddrUDP(conn PacketConn, addr Addr, b []byte) (err error) {
	if udpProxy, ok := conn.(*net.UDPConn); ok {
		// For some fucking reason net.UDPConn.WriteTo just crashing on any
		// net.Addr that is not *net.UDPAddr so we handling it individually
		udpAddr := addr.ToUDP()
		if udpAddr == nil {
			return nil
		}
		_, err = udpProxy.WriteToUDP(b, udpAddr)
	} else {
		// For all others PacketConn implementations
		_, err = conn.WriteTo(b, addr)
	}
	return
}

// AppendSocks5UDPHeader appends a SOCKS5 UDP header to a buffer.
//
// Builds the header for either standard UDP ASSOC or Gost UDP Tunnel:
//   - Standard: rsv=0, frag=0
//   - Gost TUN: rsv=payload length, frag=0xFF
//
// # Header Format
//
//	+----+------+------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |
//	+----+------+------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     |
//	+----+------+------+----------+----------+
//
// # Parameters
//
//   - buf: Buffer to append to (may be nil for new allocation)
//   - rsv: Reserved field (0 for standard, payload length for Gost)
//   - addr: Destination address
//
// # Returns
//
// The buffer with the header appended.
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
		host = host[:min(len(host), MAX_HEADER_STR_LENGTH)]
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = binary.BigEndian.AppendUint16(buf, addr.Port)
	return buf
}

// Builds and writes socks5 UDP Assoc packet to conn
func WriteSocksAssoc5UDPPacket(
	pool bufpool.Pool,
	conn PacketConn,
	peerAddr net.Addr,
	addr Addr,
	data []byte,
) (n int, err error) {
	// conn is a packet one (udp)
	// standard UDP ASSOC should be used

	buf := bufpool.GetBuffer(pool, MAX_SOCKS_UDP_HEADER_LEN+len(data))[:0]
	defer bufpool.PutBuffer(pool, buf)

	buf = AppendSocks5UDPHeader(buf, 0, addr)
	hlen := len(buf) // header length
	buf = append(buf, data...)

	if peerAddr == nil {
		n, err = conn.Write(buf)
	} else {
		n, err = conn.WriteTo(buf, peerAddr)
	}
	n = max(0, n-hlen)
	return n, err
}

// Builds ans writes gost's socks5 extension's UDP TUN packet to conn
func WriteSocks5TUNUDPPacket(
	pool bufpool.Pool,
	conn net.Conn,
	addr Addr,
	data []byte,
) (n int, err error) {
	if len(data) > 65535 {
		data = data[:65535]
	}
	rsv := uint16(len(data)) //nolint

	buf := bufpool.GetBuffer(pool, MAX_SOCKS_UDP_HEADER_LEN)[:0]
	defer bufpool.PutBuffer(pool, buf)

	header := AppendSocks5UDPHeader(buf, rsv, addr)
	_, err = io.Copy(conn, bytes.NewReader(header))
	if err == nil {
		var n64 int64
		n64, err = io.Copy(conn, bytes.NewReader(data))
		n = int(n64)
	}
	return n, err
}

func ReadSocks5AssocUDPPacket(
	pool bufpool.Pool,
	conn net.PacketConn,
	p []byte,
	skipAddr bool,
	checkAddr net.Addr,
) (n int, addr Addr, incAddr net.Addr, err error) {
	buf := bufpool.GetBuffer(pool, len(p)+MAX_SOCKS_UDP_HEADER_LEN)
	defer bufpool.PutBuffer(pool, buf)
loop:
	for {
		n, incAddr, err = conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if (checkAddr != nil && !helpers.AddrsSameHost(checkAddr, incAddr)) ||
			// Packet is too small to contain any meaningful socks5 header
			n < 8 ||
			// RSV is not 0
			buf[0] != 0 || buf[1] != 0 ||
			// Fragmentation is not supported
			// TODO: Add fragmentation support
			buf[2] != 0 {
			continue
		}

		var start int // Place in pkg where payload starts
		switch AddrType(buf[3]) {
		case IP4Addr:
			if n < 10 {
				// Packet is too small
				continue loop
			}
			start = 10

			if !skipAddr {
				ip := net.IP(slices.Clone(buf[4:8]))
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
				ip := net.IP(slices.Clone(buf[4:20]))
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
		return n, addr, incAddr, nil
	}
}

func ReadSocks5TunUDPPacket(
	pool bufpool.Pool,
	conn net.Conn,
	p []byte,
	skipAddr bool,
) (n int, addr Addr, err error) {
	hbuf := p // Header buffer
	if len(hbuf) < MAX_SOCKS_TCP_HEADER_LEN {
		hbuf = make([]byte, MAX_SOCKS_TCP_HEADER_LEN)
	}

	for {
		// If pkg is malformed or unsupported for any reason we still need to
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
				host := net.JoinHostPort(
					string(hbuf[:ln]),
					strconv.Itoa(int(port)),
				)
				addr = AddrFromFQDN(host, port, conn.LocalAddr().Network())
			}
		default:
			err = UnknownAddrTypeError{atyp}
			return
		}
		if len(p) < plen {
			// Read with tmp buffer
			tmpbuf := bufpool.GetBuffer(pool, plen)
			_, err = io.ReadFull(conn, tmpbuf)
			if err == nil {
				n = copy(p, tmpbuf)
			}
			bufpool.PutBuffer(pool, tmpbuf)
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

// Socks5UDPClientAssoc implements standard SOCKS5 UDP ASSOCIATE.
//
// This type wraps a UDP PacketConn to provide SOCKS5 UDP relay functionality.
// It adds SOCKS5 UDP headers to outgoing packets and parses them from
// incoming packets.
//
// # Usage
//
// After a successful UDP ASSOCIATE command over TCP, use the returned
// server UDP address to create this client:
//
//	udpConn, _ := net.DialUDP("udp", nil, serverUDPAddr)
//	client := protocol.NewSocks5UDPClientAssoc(udpConn, &bindAddr, pool, onClose)
//	defer client.Close()
//
//	// Send UDP packet
//	client.WriteToUDP(data, &net.UDPAddr{IP: targetIP, Port: targetPort})
//
//	// Receive UDP packet
//	n, addr, err := client.ReadFromUDP(buf)
type Socks5UDPClientAssoc struct {
	PacketConn
	DefaultHeader []byte // For binded UDP connections (ones with fixed raddr)
	Pool          bufpool.Pool
	Raddr         net.Addr
	OnClose       func()
}

// NewSocks5UDPClientAssoc creates a new standard UDP ASSOC client.
//
// # Parameters
//
//   - conn: Underlying UDP PacketConn (already connected to server's UDP address)
//   - addr: Bound address from UDP ASSOCIATE reply (used as default remote)
//   - pool: Buffer pool for allocations
//   - onc: Optional callback called once on Close()
//
// # Returns
//
// A new Socks5UDPClientAssoc instance.
func NewSocks5UDPClientAssoc(
	conn PacketConn, addr *Addr, pool bufpool.Pool, onc func(),
) *Socks5UDPClientAssoc {
	raddr := AddrFromHostPort("0.0.0.0:0", "udp").WithDefaultAddr(addr)

	buf := bufpool.GetBuffer(pool, MAX_SOCKS_UDP_HEADER_LEN)[:0]

	client := &Socks5UDPClientAssoc{
		PacketConn:    conn,
		Pool:          pool,
		Raddr:         raddr,
		DefaultHeader: AppendSocks5UDPHeader(buf, 0, raddr),
	}

	client.OnClose = sync.OnceFunc(func() {
		dh := client.DefaultHeader
		client.DefaultHeader = nil
		bufpool.PutBuffer(pool, dh)
		if onc != nil {
			onc()
		}
	})
	return client
}

func (uc *Socks5UDPClientAssoc) Close() error {
	err := uc.PacketConn.Close()
	uc.OnClose()
	return err
}

func (uc *Socks5UDPClientAssoc) RemoteAddr() net.Addr {
	return internal.FirstNonNil( //nolint forcetypeassert
		uc.Raddr, uc.PacketConn.RemoteAddr()).(net.Addr)
}

func (uc *Socks5UDPClientAssoc) Read(b []byte) (n int, err error) {
	n, _, _, err = ReadSocks5AssocUDPPacket(
		uc.Pool,
		uc.PacketConn,
		b,
		true,
		nil,
	)
	return
}

func (uc *Socks5UDPClientAssoc) Write(b []byte) (n int, err error) {
	buf := bufpool.GetBuffer(uc.Pool, len(uc.DefaultHeader)+len(b))[:0]
	defer bufpool.PutBuffer(uc.Pool, buf)
	buf = append(buf, uc.DefaultHeader...)
	buf = append(buf, b...)

	n, err = uc.PacketConn.Write(buf)
	if err == nil {
		n = max(0, n-len(uc.DefaultHeader))
	}

	return n, nil
}

func (uc *Socks5UDPClientAssoc) ReadFrom(
	p []byte,
) (n int, addr net.Addr, err error) {
	n, addr, _, err = ReadSocks5AssocUDPPacket(
		uc.Pool,
		uc.PacketConn,
		p,
		false,
		nil,
	)
	return
}

func (uc *Socks5UDPClientAssoc) ReadFromUDP(
	b []byte,
) (n int, addr *net.UDPAddr, err error) {
	for {
		var ad Addr
		n, ad, _, err = ReadSocks5AssocUDPPacket(
			uc.Pool,
			uc.PacketConn,
			b,
			false,
			nil,
		)
		if err != nil {
			return
		}
		addr = ad.ToUDP()
		if addr != nil {
			return
		}
	}
}

func (uc *Socks5UDPClientAssoc) WriteTo(
	p []byte,
	addr net.Addr,
) (n int, err error) {
	return WriteSocksAssoc5UDPPacket(
		uc.Pool, uc.PacketConn, nil, AddrFromNetAddr(addr), p,
	)
}

func (uc *Socks5UDPClientAssoc) WriteToUDP(
	b []byte,
	addr *net.UDPAddr,
) (int, error) {
	return WriteSocksAssoc5UDPPacket(
		uc.Pool, uc.PacketConn, nil, AddrFromUDPAddr(addr), b,
	)
}

func (uc *Socks5UDPClientAssoc) WriteToIpPort(
	p []byte,
	ip net.IP,
	port uint16,
) (n int, err error) {
	return WriteSocksAssoc5UDPPacket(
		uc.Pool, uc.PacketConn, nil, AddrFromIP(ip, port, "udp"), p,
	)
}

// Socks5UDPClientTUN implements Gost's UDP Tunnel extension.
//
// This type wraps a TCP Conn to provide UDP-over-TCP relay. Unlike standard
// UDP ASSOC which uses a separate UDP connection, Gost's tunnel encapsulates
// UDP packets within a TCP stream.
//
// # Wire Format
//
// Each UDP packet is prefixed with a header:
//   - RSV (2 bytes): Payload length (big-endian)
//   - FRAG (1 byte): Always 0xFF
//   - ATYP (1 byte): Address type
//   - DST.ADDR/DST.PORT: Destination address
//   - DATA: UDP payload
//
// # Usage
//
// After a successful GostUDPTun command over TCP:
//
//	client := protocol.NewSocks5UDPClientTUN(tcpConn, bindAddr, &targetAddr, pool)
//	defer client.Close()
//
//	// Send UDP packet (automatically encapsulated in TCP)
//	client.WriteToUDP(data, &net.UDPAddr{IP: targetIP, Port: targetPort})
//
//	// Receive UDP packet
//	n, addr, err := client.ReadFromUDP(buf)
type Socks5UDPClientTUN struct {
	net.Conn
	DefaultHeader []byte // For binded UDP connections (ones with fixed raddr)
	Pool          bufpool.Pool
	Laddr, Raddr  net.Addr
	OnClose       func()
}

// NewSocks5UDPClientTUN creates a new Gost UDP Tunnel client.
//
// # Parameters
//
//   - conn: Underlying TCP connection (already upgraded to UDP tunnel)
//   - laddr: Local bound address
//   - raddr: Optional remote address (nil for unbound)
//   - pool: Buffer pool for allocations
//
// # Returns
//
// A new Socks5UDPClientTUN instance.
func NewSocks5UDPClientTUN(
	conn net.Conn, laddr Addr, raddr *Addr, pool bufpool.Pool,
) *Socks5UDPClientTUN {
	var nraddr Addr
	if raddr != nil {
		nraddr = raddr.Copy()
	} else {
		nraddr = AddrFromHostPort("0.0.0.0:0", "udp")
	}

	buf := bufpool.GetBuffer(pool, MAX_SOCKS_UDP_HEADER_LEN)[:0]

	client := &Socks5UDPClientTUN{
		Conn:          conn,
		Pool:          pool,
		Raddr:         raddr,
		Laddr:         laddr,
		DefaultHeader: AppendSocks5UDPHeader(buf, 0, nraddr),
	}

	client.OnClose = sync.OnceFunc(func() {
		dh := client.DefaultHeader
		client.DefaultHeader = nil
		bufpool.PutBuffer(pool, dh)
	})
	return client
}

func (uc *Socks5UDPClientTUN) Close() error {
	err := uc.Conn.Close()
	uc.OnClose()
	return err
}

func (uc *Socks5UDPClientTUN) RemoteAddr() net.Addr {
	return internal.FirstNonNil( //nolint forcetypeassert
		uc.Raddr, uc.Conn.RemoteAddr()).(net.Addr)
}

func (uc *Socks5UDPClientTUN) LocalAddr() net.Addr {
	return internal.FirstNonNil( //nolint forcetypeassert
		uc.Laddr, uc.Conn.LocalAddr()).(net.Addr)
}

func (uc *Socks5UDPClientTUN) Read(b []byte) (n int, err error) {
	n, _, err = ReadSocks5TunUDPPacket(uc.Pool, uc.Conn, b, true)
	return
}

func (uc *Socks5UDPClientTUN) Write(b []byte) (n int, err error) {
	// Trim b cause we do not support fragmentation
	b = b[:min(len(b), 65535)]

	buf := bufpool.GetBuffer(uc.Pool, len(uc.DefaultHeader)+len(b))[:0]
	defer bufpool.PutBuffer(uc.Pool, buf)
	buf = binary.BigEndian.AppendUint16(
		buf, uint16(len(b)), //nolint
	) // RSV
	buf = append(
		buf,
		uc.DefaultHeader[2:]...) // Header without RSV
	buf = append(buf, b...)

	n, err = uc.Conn.Write(buf)
	if err == nil {
		n = max(0, n-len(uc.DefaultHeader))
	}
	return n, err
}

func (uc *Socks5UDPClientTUN) ReadFrom(
	p []byte,
) (n int, addr net.Addr, err error) {
	return ReadSocks5TunUDPPacket(uc.Pool, uc.Conn, p, false)
}

func (uc *Socks5UDPClientTUN) ReadFromUDP(
	b []byte,
) (n int, addr *net.UDPAddr, err error) {
	for {
		var ad Addr
		n, ad, err = ReadSocks5TunUDPPacket(uc.Pool, uc.Conn, b, false)
		if err != nil {
			return
		}
		addr = ad.ToUDP()
		if addr != nil {
			return
		}
	}
}

func (uc *Socks5UDPClientTUN) WriteTo(
	p []byte,
	addr net.Addr,
) (n int, err error) {
	return WriteSocks5TUNUDPPacket(
		uc.Pool, uc.Conn, AddrFromNetAddr(addr), p,
	)
}

func (uc *Socks5UDPClientTUN) WriteToUDP(
	b []byte,
	addr *net.UDPAddr,
) (int, error) {
	return WriteSocks5TUNUDPPacket(
		uc.Pool, uc.Conn, AddrFromUDPAddr(addr), b,
	)
}

func (uc *Socks5UDPClientTUN) WriteToIpPort(
	p []byte,
	ip net.IP,
	port uint16,
) (n int, err error) {
	return WriteSocks5TUNUDPPacket(
		uc.Pool, uc.Conn, AddrFromIP(ip, port, "udp"), p,
	)
}

// ProxySocks5UDPAssoc proxies UDP packets between a SOCKS5 client and a
// target UDP server using standard UDP ASSOCIATE.
//
// This function runs two goroutines:
//  1. Client -> Proxy: Reads SOCKS5 UDP packets, strips headers, forwards to target
//  2. Proxy -> Client: Reads UDP responses, adds SOCKS5 headers, sends to client
//
// The control connection (ctrl) is monitored for closure. When it closes,
// both UDP connections are closed and the function returns.
//
// # Parameters
//
//   - assoc: Client's UDP association (from UDP ASSOCIATE command)
//   - proxy: Outgoing UDP connection to target server
//   - ctrl: Control TCP connection (monitored for closure)
//   - binded: If true, all packets use a fixed remote address
//   - defaultAddr: Default destination for unbound packets
//   - pool: Buffer pool for allocations
//   - bufSize: Buffer size for packet copying
//   - timeOut: Idle timeout for UDP association
//
// # Returns
//
// Error if any connection fails, including ErrUDPAssocTimeout on timeout.
//
// # Thread Safety
//
// This function spawns goroutines and blocks until all connections close.
func ProxySocks5UDPAssoc(
	assoc, proxy PacketConn, ctrl net.Conn,
	binded bool,
	defaultAddr *Addr, // Addr to send packets with 0.0.0.0 / :: as dst
	pool bufpool.Pool, bufSize int,
	timeOut time.Duration,
) (err error) {
	assoc2proxy := bufpool.GetBuffer(pool, bufSize)
	proxy2assoc := bufpool.GetBuffer(pool, bufSize)
	defer bufpool.PutBuffer(pool, assoc2proxy)
	defer bufpool.PutBuffer(pool, proxy2assoc)

	done := make(chan error, 2)

	go func() {
		// assoc -> proxy goroutine
		var reverseProxyStarted bool
		defer func() {
			// Only close ctrl if reverse proxy goroutine was not started
			// (the reverse proxy goroutine handles closing ctrl)
			if !reverseProxyStarted {
				_ = ctrl.Close()
			}
		}()
		var clientUDPAddr net.Addr
		ctrlAddr := ctrl.RemoteAddr()
		for {
			// Enforce assoc udp conn idle timeout
			deadline := time.Now().Add(timeOut)
			err := assoc.SetReadDeadline(deadline)
			if err != nil {
				done <- err
				if clientUDPAddr == nil {
					done <- nil
				}
				return
			}
			n, addr, incAddr, err := ReadSocks5AssocUDPPacket(
				pool,
				assoc,
				assoc2proxy,
				false,
				clientUDPAddr,
			)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					err = errors.Join(ErrUDPAssocTimeout, err)
				}
				done <- err
				if clientUDPAddr == nil {
					done <- nil
				}
				return
			}
			// It was first packet from client
			if clientUDPAddr == nil {
				if !helpers.AddrsSameHost(incAddr, ctrlAddr) {
					// Packet is not from our client
					continue
				}

				// Now we should remember client's host:port and reject all packets
				// with other addrs appearing at assoc
				clientUDPAddr = incAddr

				// Only now after clientUDPAddr is known, we can start reverse
				// directional proxy too
				reverseProxyStarted = true
				go func() {
					// assoc <- proxy goroutine
					defer func() { _ = ctrl.Close() }()
					for {
						n, addr, err := proxy.ReadFrom(proxy2assoc)
						if err != nil {
							done <- err
							return
						}
						_, err = WriteSocksAssoc5UDPPacket(
							pool,
							assoc,
							clientUDPAddr,
							AddrFromNetAddr(addr),
							proxy2assoc[:n],
						)
						if err != nil {
							done <- err
							return
						}
					}
				}()
			}

			if binded { //nolint nestif
				// For binded connections (ones with fixed remote addr)
				_, err = proxy.Write(assoc2proxy[:n])
			} else {
				// For unbinded connections (ones without fixed remote addr)
				addr = addr.WithDefaultAddr(defaultAddr)
				err = WriteToAddrUDP(proxy, addr, assoc2proxy[:n])
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	helpers.ReadUntilClose(ctrl)
	_ = assoc.Close()
	_ = proxy.Close()

	return JoinNetErrors(<-done, <-done)
}

// ProxySocks5UDPTun proxies UDP packets between a Gost UDP Tunnel client
// and a target UDP server.
//
// Unlike ProxySocks5UDPAssoc, this function works with a TCP connection
// (tun) that carries encapsulated UDP packets. No separate control
// connection is needed since the TCP connection itself carries the data.
//
// This function runs two goroutines:
//  1. Client -> Proxy: Reads Gost UDP packets from TCP, forwards to target
//  2. Proxy -> Client: Reads UDP responses, encapsulates in Gost format, sends via TCP
//
// # Parameters
//
//   - tun: Client's TCP connection (Gost UDP Tunnel)
//   - proxy: Outgoing UDP connection to target server
//   - binded: If true, all packets use a fixed remote address
//   - defaultAddr: Default destination for unbound packets
//   - pool: Buffer pool for allocations
//   - bufSize: Buffer size for packet copying
//
// # Returns
//
// Error if any connection fails.
//
// # Thread Safety
//
// This function spawns goroutines and blocks until all connections close.
func ProxySocks5UDPTun(
	tun net.Conn, proxy PacketConn,
	binded bool,
	defaultAddr *Addr, // Addr to send packets with 0.0.0.0 / :: as dst
	pool bufpool.Pool, bufSize int,
) (err error) {
	tun2proxy := bufpool.GetBuffer(pool, bufSize)
	tun2assoc := bufpool.GetBuffer(pool, bufSize)
	defer bufpool.PutBuffer(pool, tun2proxy)
	defer bufpool.PutBuffer(pool, tun2assoc)

	done := make(chan error, 1)

	go func() {
		// tun -> proxy
		defer func() {
			_ = tun.Close()
			_ = proxy.Close()
		}()

		for {
			n, addr, err := ReadSocks5TunUDPPacket(pool, tun, tun2proxy, false)
			if err != nil {
				done <- err
				return
			}
			if binded { //nolint nestif
				// For binded connections (ones with fixed remote addr)
				_, err = proxy.Write(tun2proxy[:n])
			} else {
				// For unbinded connections (ones without fixed remote addr)
				addr = addr.WithDefaultAddr(defaultAddr)
				err = WriteToAddrUDP(proxy, addr, tun2proxy[:n])
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	// tun <- proxy
	for {
		n, addr, err := proxy.ReadFrom(tun2assoc)
		if err != nil {
			break
		}
		_, err = WriteSocks5TUNUDPPacket(
			pool, tun, AddrFromNetAddr(addr), tun2assoc[:n],
		)
		if err != nil {
			done <- err
			break
		}
	}

	_ = tun.Close()
	_ = proxy.Close()

	return JoinNetErrors(err, <-done)
}
