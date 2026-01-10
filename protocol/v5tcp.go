package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/asciimoth/socksgo/internal"
)

// request is a buffer retrieved from provided pool and should be putted back
func BuildSocks5TCPRequest(
	cmd Cmd, addr Addr, pool BufferPool,
) (request []byte, err error) {
	if addr.Len() > MAX_HEADER_STR_LENGTH {
		return nil, fmt.Errorf("too long host: %s", addr.ToFQDN())
	}

	request = internal.GetBuffer(pool, 6+addr.Len())[:0]
	request = append(request,
		5, // socks version
		byte(cmd),
		0, // reserved
		byte(addr.Type),
	)
	if addr.Type == FQDNAddr {
		request = append(request, byte(len(addr.Host)))
		request = append(request, []byte(addr.Host)...)
	} else {
		request = append(request, addr.ToIP()...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(addr.Port))
	return
}

func ReadSocks5TCPRequest(reader io.Reader, pool BufferPool) (
	cmd Cmd, addr Addr, err error,
) {
	buf := internal.GetBuffer(pool, MAX_SOCKS_TCP_HEADER_LEN)
	defer internal.PutBuffer(pool, buf)

	_, err = io.ReadFull(reader, buf[:4])
	if err != nil {
		return
	}

	if buf[0] != 5 {
		err = fmt.Errorf(
			"wrong protocol version %d in socks5 request", int(buf[0]),
		)
		return
	}

	cmd = Cmd(buf[1])
	atyp := AddrType(buf[3])

	switch atyp {
	case IP4Addr:
		_, err = io.ReadFull(reader, buf[:6])
		if err != nil {
			return
		}
		port := binary.BigEndian.Uint16(buf[4:6])
		addr = AddrFromIP(net.IP(internal.CopyBytes(buf[:4])), port, "")
		return
	case IP6Addr:
		_, err = io.ReadFull(reader, buf[:18])
		if err != nil {
			return
		}
		port := binary.BigEndian.Uint16(buf[16:18])
		addr = AddrFromIP(net.IP(internal.CopyBytes(buf[:16])), port, "")
		return
	case FQDNAddr:
		_, err = io.ReadFull(reader, buf[:1])
		if err != nil {
			return
		}
		ln := int(buf[0])
		_, err = io.ReadFull(reader, buf[:ln+2])
		if err != nil {
			return
		}
		port := binary.BigEndian.Uint16(buf[ln : ln+2])
		addr = AddrFromFQDN(string(buf[:ln]), port, "")
		return
	}
	err = fmt.Errorf("unknown address type: %s", atyp.String())
	return
}

// reply is a buffer retrieved from provided pool and should be putted back
func BuildSocks5TCPReply(
	stat ReplyStatus, addr Addr, pool BufferPool,
) (reply []byte, err error) {
	// Socks5 request & reply have nearly same format
	// except meaning of cmd/reply codes
	cmd := Cmd(stat.To5())
	return BuildSocks5TCPRequest(cmd, addr, pool)
}

func ReadSocks5TCPReply(reader io.Reader, pool BufferPool) (
	stat ReplyStatus, addr Addr, err error,
) {
	// Socks5 request & reply have nearly same format
	// except meaning of cmd/reply codes
	var cmd Cmd
	cmd, addr, err = ReadSocks5TCPRequest(reader, pool)
	stat = ReplyStatus(cmd).To5()
	return
}
