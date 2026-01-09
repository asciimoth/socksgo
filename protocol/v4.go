package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/asciimoth/socks/internal"
)

// request is a buffer retireved from provided pool and should be putted back
func BuildSocsk4TCPRequest(
	cmd Cmd, addr Addr, user string, pool BufferPool,
) (request []byte, err error) {
	if addr.Type == IP4Addr {
		// Socks4
		request = internal.GetBuffer(pool, 9+len(user))[:0]
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
		return nil, fmt.Errorf("too long host: %s", addr.ToFQDN())
	}
	host := addr.ToFQDN() // String representation
	request = internal.GetBuffer(pool, 10+len(user)+len(host))[:0]
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
func ReadSocks4TCPReqest(reader io.Reader, pool BufferPool) (
	cmd Cmd, addr Addr, user string, err error,
) {
	var resp [7]byte
	_, err = io.ReadFull(reader, resp[:])
	if err != nil {
		return
	}

	cmd = Cmd(resp[0])
	port := binary.BigEndian.Uint16(resp[1:3])

	buf := internal.GetBuffer(pool, MAX_HEADER_STR_LENGTH)
	defer internal.PutBuffer(pool, buf)
	user, err = internal.ReadNullTerminatedString(reader, buf)
	if err != nil {
		if errors.Is(err, internal.TooLongStringErr) {
			// TODO: Use sentinel err var
			err = errors.New("user name is too long")
		}
		return
	}

	if resp[3] == 0 && resp[4] == 0 && resp[5] == 0 && resp[6] != 0 {
		// socks4a extension
		var fqdn string
		fqdn, err = internal.ReadNullTerminatedString(reader, buf)
		if err != nil {
			if errors.Is(err, internal.TooLongStringErr) {
				// TODO: Use sentinel err var
				err = errors.New("user name is too long")
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

// reply is a buffer retireved from provided pool and should be putted back
func BuildSocsk4TCPReply(
	stat ReplyStatus, addr Addr, pool BufferPool,
) (request []byte) {
	ip := addr.ToIP().To4()
	if ip == nil {
		ip = net.IPv4(0, 0, 0, 0).To4()
	}
	request = internal.GetBuffer(pool, 9)[:0]
	request = append(request, 4) // Socks version
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
