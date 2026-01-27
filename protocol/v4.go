package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/internal"
)

// request is a buffer retrieved from provided pool and should be putted back
func BuildSocsk4TCPRequest(
	cmd Cmd, addr Addr, user string, pool bufpool.Pool,
) (request []byte, err error) {
	if addr.Type == IP4Addr {
		// Socks4
		request = bufpool.GetBuffer(pool, 9+len(user))[:0]
		request = append(request, 4) // Socks version
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
	request = append(request, 4) // Socks version
	request = append(request, byte(cmd))
	request = binary.BigEndian.AppendUint16(request, addr.Port)
	request = append(request, 0, 0, 0, 1) // inadmissible addr
	request = append(request, []byte(user)...)
	request = append(request, 0)
	request = append(request, []byte(host)...)
	request = append(request, 0)
	return
}

// Reading request WITHOUT first byte.
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
		if errors.Is(err, internal.TooLongStringErr) {
			err = ErrTooLongUser
		}
		return
	}

	if resp[3] == 0 && resp[4] == 0 && resp[5] == 0 && resp[6] != 0 {
		// socks4a extension
		var fqdn string
		fqdn, err = internal.ReadNullTerminatedString(reader, buf)
		if err != nil {
			if errors.Is(err, internal.TooLongStringErr) {
				err = ErrTooLongUser
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

// reply is a buffer retrieved from provided pool and should be putted back
func BuildSocks4TCPReply(
	stat ReplyStatus, addr Addr, pool bufpool.Pool,
) (request []byte) {
	ip := addr.ToIP().To4()
	if ip == nil {
		ip = net.IPv4(0, 0, 0, 0).To4()
	}
	request = bufpool.GetBuffer(pool, 9)[:0]
	request = append(request, 0) // Reply ver
	request = append(request, byte(stat.To4()))
	request = binary.BigEndian.AppendUint16(request, addr.Port)
	request = append(request, addr.ToIP().To4()...)
	return
}

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
