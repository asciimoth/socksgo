package protocol

import (
	"encoding/binary"
	"io"
	"net"
	"slices"

	"github.com/asciimoth/bufpool"
)

// BuildSocks5TCPRequest builds a SOCKS5 TCP request.
//
// Creates a request packet for the given command and address.
//
// # Wire Format (RFC 1928)
//
//	+----+-----+-------+------+----------+----------+
//	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  |   1   |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
//
// Where:
//   - VER: Protocol version (0x05)
//   - CMD: Command code (Connect, Bind, UDPAssoc, etc.)
//   - RSV: Reserved (0x00)
//   - ATYP: Address type (IP4=0x01, IP6=0x04, FQDN=0x03)
//   - DST.ADDR: Destination address (4/16 bytes for IP, variable for FQDN)
//   - DST.PORT: Destination port (big-endian)
//
// # Parameters
//
//   - cmd: Command code (CmdConnect, CmdBind, CmdUDPAssoc, or extension commands)
//   - addr: Target address
//   - pool: Buffer pool for allocation
//
// # Returns
//
// The request byte slice, or an error if the hostname is too long.
// The returned buffer must be returned to the pool after use.
//
// # Examples
//
//	addr := protocol.AddrFromFQDN("example.com", 80, "tcp")
//	req, err := protocol.BuildSocks5TCPRequest(protocol.CmdConnect, addr, pool)
//	defer bufpool.PutBuffer(pool, req)
func BuildSocks5TCPRequest(
	cmd Cmd, addr Addr, pool bufpool.Pool,
) (request []byte, err error) {
	if addr.Len() > MAX_HEADER_STR_LENGTH {
		return nil, ErrTooLongHost
	}

	request = bufpool.GetBuffer(pool, 7+addr.Len())[:0]
	request = append(request,
		5, // socks version
		byte(cmd),
		0, // reserved
		byte(addr.Type),
	)
	if addr.Type == FQDNAddr {
		request = append(request, byte(len(addr.Host)))
		request = append(request, addr.Host...)
	} else {
		request = append(request, addr.ToIP()...)
	}
	request = binary.BigEndian.AppendUint16(request, addr.Port)
	return
}

// ReadSocks5TCPRequest reads and parses a SOCKS5 TCP request.
//
// Reads a request packet and extracts the command and address.
// Supports all three address types: IPv4, IPv6, and FQDN.
//
// # Parameters
//
//   - reader: Source to read from
//   - pool: Buffer pool for temporary allocations
//
// # Returns
//
//   - cmd: Command code
//   - addr: Target address
//   - err: Error if parsing fails
//
// # Errors
//
//   - WrongProtocolVerError: If version byte is not 0x05
//   - UnknownAddrTypeError: If address type is not recognized
func ReadSocks5TCPRequest(reader io.Reader, pool bufpool.Pool) (
	cmd Cmd, addr Addr, err error,
) {
	buf := bufpool.GetBuffer(pool, MAX_SOCKS_TCP_HEADER_LEN)
	defer bufpool.PutBuffer(pool, buf)

	_, err = io.ReadFull(reader, buf[:4])
	if err != nil {
		return
	}

	if buf[0] != 5 {
		err = WrongProtocolVerError{int(buf[0])}
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
		addr = AddrFromIP(net.IP(slices.Clone(buf[:4])), port, "")
		return
	case IP6Addr:
		_, err = io.ReadFull(reader, buf[:18])
		if err != nil {
			return
		}
		port := binary.BigEndian.Uint16(buf[16:18])
		addr = AddrFromIP(net.IP(slices.Clone(buf[:16])), port, "")
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
	err = UnknownAddrTypeError{atyp}
	return
}

// BuildSocks5TCPReply builds a SOCKS5 TCP reply.
//
// Creates a reply packet with the given status and bound address.
// The reply format is identical to the request format, with the CMD
// field repurposed to carry the status code.
//
// # Wire Format (RFC 1928)
//
//	+----+-----+-------+------+----------+----------+
//	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  |   1   |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
//
// Where:
//   - VER: Protocol version (0x05)
//   - REP: Reply status code (SuccReply, FailReply, etc.)
//   - RSV: Reserved (0x00)
//   - ATYP: Address type
//   - BND.ADDR: Bound address
//   - BND.PORT: Bound port
//
// # Parameters
//
//   - stat: Reply status code (automatically converted to SOCKS5 format)
//   - addr: Bound address (typically the server's listening address)
//   - pool: Buffer pool for allocation
//
// # Returns
//
// The reply byte slice. The returned buffer must be returned to the pool
// after use.
//
// # Examples
//
//	addr := protocol.AddrFromIP(net.ParseIP("192.168.1.1"), 8080, "tcp")
//	reply, err := protocol.BuildSocks5TCPReply(protocol.SuccReply, addr, pool)
//	defer bufpool.PutBuffer(pool, reply)
func BuildSocks5TCPReply(
	stat ReplyStatus, addr Addr, pool bufpool.Pool,
) (reply []byte, err error) {
	// Socks5 request & reply have nearly same format
	// except meaning of cmd/reply codes
	cmd := Cmd(stat.To5())
	return BuildSocks5TCPRequest(cmd, addr, pool)
}

// ReadSocks5TCPReply reads and parses a SOCKS5 TCP reply.
//
// Reads a reply packet and extracts the status code and bound address.
// Internally uses ReadSocks5TCPRequest since the wire format is identical,
// then converts the command code to a status code.
//
// # Parameters
//
//   - reader: Source to read from
//   - pool: Buffer pool for temporary allocations
//
// # Returns
//
//   - stat: Reply status code (converted to SOCKS5 format)
//   - addr: Bound address (only valid if status indicates success)
//   - err: Error if parsing fails
func ReadSocks5TCPReply(reader io.Reader, pool bufpool.Pool) (
	stat ReplyStatus, addr Addr, err error,
) {
	// Socks5 request & reply have nearly same format
	// except meaning of cmd/reply codes
	var cmd Cmd
	cmd, addr, err = ReadSocks5TCPRequest(reader, pool)
	stat = ReplyStatus(cmd).To5()
	return
}
