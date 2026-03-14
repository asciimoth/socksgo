package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/internal"
)

// BuildSocsk4TCPRequest builds a SOCKS4 or SOCKS4a TCP request.
//
// For IPv4 addresses, builds a standard SOCKS4 request.
// For other address types (FQDN), builds a SOCKS4a request with the
// domain name appended after the username.
//
// # Wire Format (SOCKS4)
//
//	+----+----+----+----+----+----+----+----+----+----+ ... +----+
//	| VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
//	+----+----+----+----+----+----+----+----+----+----+ ... +----+
//	   1    1      2              4           variable        1
//
// # Wire Format (SOCKS4a)
//
//	+----+----+----+----+----+----+----+----+----+----+ ... +----+----+ ... +----+
//	| VN | CD | DSTPORT |      DSTIP        | USERID       |NULL| HOST       |NULL|
//	+----+----+----+----+----+----+----+----+----+----+ ... +----+----+ ... +----+
//	   1    1      2              4           variable      1      variable    1
//
// # Parameters
//
//   - cmd: Command code (typically CmdConnect)
//   - addr: Target address
//   - user: Username (may be empty)
//   - pool: Buffer pool for allocation
//
// # Returns
//
// The request byte slice, or an error if the hostname is too long.
// The returned buffer must be returned to the pool after use.
//
// # Examples
//
//	addr := protocol.AddrFromIP(net.ParseIP("192.168.1.1"), 80, "")
//	req, err := protocol.BuildSocsk4TCPRequest(protocol.CmdConnect, addr, "", pool)
//	defer bufpool.PutBuffer(pool, req)
func BuildSocsk4TCPRequest(
	cmd Cmd, addr Addr, user string, pool bufpool.Pool,
) (request []byte, err error) {
	if addr.Type == IP4Addr {
		// Socks4
		request = bufpool.GetBuffer(pool, 9+len(user))[:0] //nolint mnd
		request = append(request, 4)                       //nolint mnd
		request = append(request, byte(cmd))
		request = binary.BigEndian.AppendUint16(request, addr.Port)
		request = append(request, addr.ToIP().To4()...)
		request = append(request, []byte(user)...)
		request = append(request, 0)
		return
	}
	// Socks4a
	if addr.Len() > MAX_HEADER_STR_LENGTH {
		return nil, ErrTooLongHost
	}
	host := addr.ToFQDN() // String representation
	request = bufpool.GetBuffer(pool, 10+len(user)+len(host))[:0]
	request = append(request, 4) //nolint mnd
	request = append(request, byte(cmd))
	request = binary.BigEndian.AppendUint16(request, addr.Port)
	request = append(request, 0, 0, 0, 1) // inadmissible addr
	request = append(request, []byte(user)...)
	request = append(request, 0)
	request = append(request, []byte(host)...)
	request = append(request, 0)
	return
}

// ReadSocks4TCPRequest reads and parses a SOCKS4/4a TCP request.
//
// Reads the request from the reader and extracts the command, address,
// and username. Automatically detects SOCKS4a extension by checking for
// the special address pattern (0.0.0.1 with non-zero domain).
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
//   - user: Username (may be empty)
//   - err: Error if parsing fails
//
// # Note
//
// The function expects to be called AFTER reading the version byte.
// It reads from the command byte onward.
func ReadSocks4TCPRequest(reader io.Reader, pool bufpool.Pool) (
	cmd Cmd, addr Addr, user string, err error,
) {
	var resp [7]byte
	_, err = io.ReadFull(reader, resp[:])
	if err != nil {
		return
	}

	cmd = Cmd(resp[0])
	port := binary.BigEndian.Uint16(resp[1:3])

	buf := bufpool.GetBuffer(pool, MAX_HEADER_STR_LENGTH)
	defer bufpool.PutBuffer(pool, buf)
	user, err = internal.ReadNullTerminatedString(reader, buf)
	if err != nil {
		if errors.Is(err, internal.ErrTooLongString) {
			err = ErrTooLongUser
		}
		return
	}

	if resp[3] == 0 && resp[4] == 0 && resp[5] == 0 && resp[6] != 0 {
		// socks4a extension
		var fqdn string
		fqdn, err = internal.ReadNullTerminatedString(reader, buf)
		if err != nil {
			if errors.Is(err, internal.ErrTooLongString) {
				err = ErrTooLongHost
			}
			return
		}
		addr = AddrFromFQDN(fqdn, port, "")
	} else {
		// basic socks4
		ip := net.IP(resp[3:7])
		addr = AddrFromIP(ip, port, "")
	}
	return
}

// BuildSocks4TCPReply builds a SOCKS4 TCP reply.
//
// Creates a reply packet with the given status and bound address.
// If the address is not IPv4, uses 0.0.0.0 as the IP.
//
// # Wire Format
//
//		+----+----+----+----+----+----+----+----+
//		| VN | CD | DSTPORT |      DSTIP        |
//		+----+----+----+----+----+----+----+----+
//	   1     1      2              4
//
// Where:
//   - VN: Reply version (always 0)
//   - CD: Status code (Granted, Rejected, etc.)
//   - DSTPORT: Bound port (big-endian)
//   - DSTIP: Bound IP address
//
// # Parameters
//
//   - stat: Reply status code (automatically converted to SOCKS4 format)
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
//	addr := protocol.AddrFromIP(net.ParseIP("192.168.1.1"), 8080, "")
//	reply := protocol.BuildSocks4TCPReply(protocol.Granted, addr, pool)
//	defer bufpool.PutBuffer(pool, reply)
func BuildSocks4TCPReply(
	stat ReplyStatus, addr Addr, pool bufpool.Pool,
) (request []byte) {
	ip := addr.ToIP().To4()
	if ip == nil {
		ip = net.IPv4(0, 0, 0, 0).To4()
	}
	request = bufpool.GetBuffer(pool, 9)[:0] //nolint mnd
	request = append(request, 0)             // Reply ver
	request = append(request, byte(stat.To4()))
	request = binary.BigEndian.AppendUint16(request, addr.Port)
	request = append(request, ip...)
	return
}

// ReadSocks4TCPReply reads and parses a SOCKS4 TCP reply.
//
// Reads an 8-byte reply packet and extracts the status code and bound
// address.
//
// # Wire Format
//
//	+----+----+----+----+----+----+----+----+
//	| VN | CD | DSTPORT |      DSTIP        |
//	+----+----+----+----+----+----+----+----+
//	# bytes:   1    1      2           4
//
// # Parameters
//
//   - reader: Source to read from
//
// # Returns
//
//   - stat: Reply status code (converted to SOCKS4 format)
//   - addr: Bound address (only valid if status is Granted)
//   - err: Error if parsing fails or version is invalid
//
// # Errors
//
// Returns Wrong4ReplyVerError if the version byte is not 0.
func ReadSocks4TCPReply(reader io.Reader) (
	stat ReplyStatus,
	addr Addr,
	err error,
) {
	var resp [8]byte
	_, err = io.ReadFull(reader, resp[:])
	if err != nil {
		return
	}

	if resp[0] != 0 {
		err = Wrong4ReplyVerError{int(resp[0])}
		return
	}

	stat = ReplyStatus(resp[1]).To4()
	if stat.Ok() {
		addr = AddrFromIP(
			net.IP(internal.CopyBytes(resp[4:8])),
			binary.BigEndian.Uint16(resp[2:4]),
			"",
		)
	}
	return
}
