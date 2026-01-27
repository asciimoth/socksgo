package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/internal"
)

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

// For standard socks UDP ASSOC leave rsv == 0.
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

func WriteSocks5TUNUDPPacket(
	pool bufpool.Pool,
	conn net.Conn,
	addr Addr,
	data []byte,
) (n int, err error) {
	// conn is not a packet one (udp) conn
	// gost's UDP TUN extension should be used

	if len(data) > 65535 {
		data = data[:65535]
	}
	rsv := uint16(len(data)) //nolint

	buf := bufpool.GetBuffer(pool, MAX_SOCKS_UDP_HEADER_LEN)[:0]
	defer bufpool.PutBuffer(pool, buf)

	header := AppendSocks5UDPHeader(buf, rsv, addr)
	_, err = io.Copy(conn, bytes.NewReader(header))
	if err != nil {
		return
	}
	n64, err := io.Copy(conn, bytes.NewReader(data))
	n = int(n64)
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
		if checkAddr != nil && !internal.AddrsSameHost(checkAddr, incAddr) {
			continue
		}
		if n < 8 {
			// Packet is too small to contain any meaningful socks5 header
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

		var start int // Place in pkg where payload starts
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

type Socks5UDPClientAssoc struct {
	PacketConn
	DefaultHeader []byte // For binded UDP connections (ones with fixed raddr)
	Pool          bufpool.Pool
	raddr         net.Addr
	onClose       func()
}

func NewSocks5UDPClientAssoc(
	conn PacketConn, addr *Addr, pool bufpool.Pool, onc func(),
) *Socks5UDPClientAssoc {
	var raddr Addr
	if addr != nil {
		raddr = addr.Copy()
	} else {
		raddr = AddrFromHostPort("0.0.0.0:0", "udp")
	}

	buf := bufpool.GetBuffer(pool, MAX_SOCKS_UDP_HEADER_LEN)[:0]

	client := &Socks5UDPClientAssoc{
		PacketConn:    conn,
		Pool:          pool,
		raddr:         raddr,
		DefaultHeader: AppendSocks5UDPHeader(buf, 0, raddr),
	}

	client.onClose = sync.OnceFunc(func() {
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
	uc.onClose()
	return err
}

func (uc *Socks5UDPClientAssoc) RemoteAddr() net.Addr {
	if uc.raddr != nil {
		return uc.raddr
	}
	return uc.PacketConn.RemoteAddr()
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
	if err != nil {
		return 0, err
	}

	n = max(0, n-len(uc.DefaultHeader))
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

type Socks5UDPClientTUN struct {
	net.Conn
	DefaultHeader []byte // For binded UDP connections (ones with fixed raddr)
	Pool          bufpool.Pool
	laddr, raddr  net.Addr
	onClose       func()
}

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
		raddr:         raddr,
		laddr:         laddr,
		DefaultHeader: AppendSocks5UDPHeader(buf, 0, nraddr),
	}

	client.onClose = sync.OnceFunc(func() {
		dh := client.DefaultHeader
		client.DefaultHeader = nil
		bufpool.PutBuffer(pool, dh)
	})
	return client
}

func (uc *Socks5UDPClientTUN) Close() error {
	err := uc.Conn.Close()
	uc.onClose()
	return err
}

func (uc *Socks5UDPClientTUN) RemoteAddr() net.Addr {
	if uc.raddr != nil {
		return uc.raddr
	}
	return uc.Conn.RemoteAddr()
}

func (uc *Socks5UDPClientTUN) LocalAddr() net.Addr {
	if uc.laddr != nil {
		return uc.laddr
	}
	return uc.Conn.LocalAddr()
}

func (uc *Socks5UDPClientTUN) Read(b []byte) (n int, err error) {
	n, _, err = ReadSocks5TunUDPPacket(uc.Pool, uc.Conn, b, true)
	return
}

func (uc *Socks5UDPClientTUN) Write(b []byte) (n int, err error) {
	// Trim b cause we do not support fragmentation
	if len(b) > 65535 {
		b = b[:65535]
	}

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
	if err != nil {
		return 0, err
	}

	n = max(0, n-len(uc.DefaultHeader))
	return n, nil
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

	// Possibly the worst code I've ever written
	go func() {
		// assoc -> proxy
		defer func() { _ = ctrl.Close() }()
		var clientUDPAddr net.Addr
		ctrlAddr := ctrl.RemoteAddr()
		for {
			deadline := time.Now().Add(timeOut)
			err := assoc.SetReadDeadline(deadline)
			if err != nil {
				done <- err
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
				return
			}
			// First packet
			if clientUDPAddr == nil {
				if !internal.AddrsSameHost(incAddr, ctrlAddr) {
					// Incoming packet from uncnown client
					continue
				}
				clientUDPAddr = incAddr
				go func() {
					// assoc <- proxy
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
				_, err = proxy.Write(assoc2proxy[:n])
			} else {
				if addr.IsUnspecified() && defaultAddr != nil {
					addr = *defaultAddr
				}
				// For some fucking reason net.UDPConn.WriteTo just crashing on any
				// net.Addr that is not *net.UDPAddr so we handling it individually
				if udpProxy, ok := proxy.(*net.UDPConn); ok {
					udpAddr := addr.ToUDP()
					if udpAddr == nil {
						continue
					}
					_, err = udpProxy.WriteToUDP(assoc2proxy[:n], udpAddr)
				} else {
					_, err = proxy.WriteTo(assoc2proxy[:n], addr)
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	internal.WaitForClose(ctrl)
	_ = assoc.Close()
	_ = proxy.Close()

	return internal.JoinNetErrors(<-done, <-done)
}

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
				_, err = proxy.Write(tun2proxy[:n])
			} else {
				if addr.IsUnspecified() && defaultAddr != nil {
					addr = *defaultAddr
				}
				// For some fucking reason net.UDPConn.WriteTo just crashing on any
				// net.Addr that is not *net.UDPAddr so we handling it individually
				if udpProxy, ok := proxy.(*net.UDPConn); ok {
					udpAddr := addr.ToUDP()
					if udpAddr == nil {
						continue
					}
					_, err = udpProxy.WriteToUDP(tun2proxy[:n], udpAddr)
				} else {
					_, err = proxy.WriteTo(tun2proxy[:n], addr)
				}
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
			break
		}
	}

	_ = tun.Close()
	_ = proxy.Close()

	return internal.JoinNetErrors(err, <-done)
}
