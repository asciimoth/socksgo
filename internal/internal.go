package internal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/asciimoth/socks/common"
)

type NetAddr struct {
	Net  string
	Host string
}

func (a NetAddr) Network() string {
	return a.Net
}

func (a NetAddr) String() string {
	return a.Host
}

type Socks5Reply struct {
	Rep  common.ReplyStatus
	Atyp common.AddrType
	Addr []byte
	Port uint16
}

func (r Socks5Reply) ToNetAddr(network string) net.Addr {
	switch r.Atyp {
	case common.IP4Addr:
		n := "tcp4"
		if strings.HasPrefix(network, "udp") {
			n = "udp4"
		}
		return NetAddr{
			Net:  n,
			Host: net.JoinHostPort(net.IP(r.Addr).To4().String(), strconv.Itoa(int(r.Port))),
		}
	case common.IP6Addr:
		n := "tcp6"
		if strings.HasPrefix(network, "udp") {
			n = "udp6"
		}
		return NetAddr{
			Net:  n,
			Host: net.JoinHostPort(net.IP(r.Addr).To16().String(), strconv.Itoa(int(r.Port))),
		}
	case common.DomAddr:
		return NetAddr{
			Net:  network,
			Host: string(r.Addr),
		}
	}
	return nil
}

// TODO: Test
func Make4TCPRequest(cmd common.Cmd, ip4 net.IP, port uint16, uid string) []byte {
	request := make([]byte, 0, 9+len(uid))
	request = append(request, common.V4)
	request = append(request, byte(cmd))
	request = binary.BigEndian.AppendUint16(request, port)
	request = append(request, ip4...)
	request = append(request, []byte(uid)...)
	request = append(request, 0)
	return request
}

// TODO: Test
func Make4aTCPRequest(cmd common.Cmd, host string, port uint16, uid string) []byte {
	request := make([]byte, 0, 10+len(uid)+len(host))
	request = append(request, common.V4)
	request = append(request, byte(cmd))
	request = binary.BigEndian.AppendUint16(request, port)
	request = append(request, 0, 0, 0, 1)
	request = append(request, []byte(uid)...)
	request = append(request, 0)
	request = append(request, []byte(host)...)
	request = append(request, 0)
	return request
}

// TODO: Test
func Read4TCPResponse(reader io.Reader) (net.IP, uint16, error) {
	var resp [8]byte
	i, err := reader.Read(resp[:])
	if err != nil {
		return nil, 0, err
	} else if i != 8 {
		// TODO: Better error
		return nil, 0, fmt.Errorf("Unexpected EOF")
	}

	switch common.CmdResp4(resp[1]) {
	case common.Cmdr4Granted:
		return net.IP(resp[4:8]), binary.BigEndian.Uint16(resp[2:4]), nil
	default:
		// TODO: Better error
		return nil, 0, fmt.Errorf("%s", common.CmdResp4(resp[1]).String())
	}
}

// TODO: Test
func Read5TCPResponse(reader io.Reader) (Socks5Reply, error) {
	header := make([]byte, 4)
	_, err := io.ReadFull(reader, header)
	if err != nil {
		return Socks5Reply{}, err
	}
	// TODO: Check that first byte is 0x05
	rep := common.ReplyStatus(header[1])
	atyp := common.AddrType(header[3])
	if rep != common.SuccReply {
		return Socks5Reply{}, fmt.Errorf("%s", rep.String())
	}
	var addr []byte
	var port uint16
	switch atyp {
	case common.IP4Addr:
		host := make([]byte, 6)
		_, err := io.ReadFull(reader, host)
		if err != nil {
			return Socks5Reply{}, err
		}
		addr = host[0:4]
		port = binary.BigEndian.Uint16(host[4:6])
	case common.IP6Addr:
		host := make([]byte, 6)
		_, err := io.ReadFull(reader, host)
		if err != nil {
			return Socks5Reply{}, err
		}
		addr = host[0:16]
		port = binary.BigEndian.Uint16(host[16:18])
	case common.DomAddr:
		ln := make([]byte, 1)
		_, err := io.ReadFull(reader, ln)
		if err != nil {
			return Socks5Reply{}, err
		}
		addr := make([]byte, int(ln[0]))
		_, err = io.ReadFull(reader, addr)
		if err != nil {
			return Socks5Reply{}, err
		}
	default:
		return Socks5Reply{}, fmt.Errorf("unknown address type: %s", atyp.String())
	}
	return Socks5Reply{
		Rep:  rep,
		Atyp: atyp,
		Addr: addr,
		Port: port,
	}, nil
}

type ReaderConn interface {
	Read(b []byte) (n int, err error)
	LocalAddr() net.Addr
}

func Read5UDP(
	pool common.BufferPool,
	conn ReaderConn,
	p []byte,
	needAddr bool, // If false addr is allways nil. (optimisation option)
) (n int, addr net.Addr, err error) {
	buf := common.GetBuffer(pool, len(p)+22) // heuristic
	defer common.PutBuffer(pool, buf)
loop:
	for {
		nn, err := conn.Read(buf)
		if err != nil {
			return 0, nil, err
		}
		if nn < 8 {
			// Packet is too small to contain any meaningfull socks5 header
			continue
		}
		// TODO: Check that buf[0] == buf[1] == 0
		if buf[2] != 0 {
			// TODO: Implement fragmentation support
			continue
		}
		start := 0
		switch common.AddrType(buf[3]) {
		case common.IP4Addr:
			if nn < 10 {
				// Packet is too small
				continue loop
			}
			start = 10

			if needAddr {
				ip := net.IP(append([]byte(nil), buf[4:8]...))
				port := binary.BigEndian.Uint16(buf[8:10])
				addr = &net.UDPAddr{
					IP:   ip,
					Port: int(port),
				}
			}
		case common.IP6Addr:
			if nn < 22 {
				// Packet is too small
				continue loop
			}
			start = 22

			if needAddr {
				ip := net.IP(append([]byte(nil), buf[4:20]...))
				port := binary.BigEndian.Uint16(buf[20:22])
				addr = &net.UDPAddr{
					IP:   ip,
					Port: int(port),
				}
			}
		case common.DomAddr:
			ln := int(buf[4])
			if nn < 7+ln {
				// Packet is too small
				continue loop
			}
			start = 7 + ln

			if needAddr {
				dom := string(buf[5 : 5+ln])
				port := binary.BigEndian.Uint16(buf[5+ln : 5+ln+2])
				host := net.JoinHostPort(dom, strconv.Itoa(int(port)))
				addr = NetAddr{
					Net:  conn.LocalAddr().Network(),
					Host: host,
				}
			}
		default:
			// Unknown address type
			continue loop
		}
		n = copy(p, buf[start:])
		return n, addr, nil
	}
}

// Header5UDP writes a socks5 UDP header to buf.
// buf must have len == 0 and cap == len(header) + len(payload)
// TODO: Rewrite this comment
func Header5UDP(buf []byte, atyp common.AddrType, addr []byte, port uint16) []byte {
	buf = append(
		buf,
		0, 0, // Reserved
		0,          // No fragmentation
		byte(atyp), // Addr type
	)
	if atyp == common.DomAddr {
		buf = append(buf, byte(len(addr)))
	}
	buf = append(buf, addr...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(port))
	return buf
}

func BuildHeader5UDP(addr string) ([]byte, error) {
	host, strport, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// TODO: If strport is "" -> err missinng port
	port, err := strconv.Atoi(strport)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return Header5UDP([]byte{}, common.IP4Addr, ip4, uint16(port)), nil
		}
		if ip6 := ip.To16(); ip6 != nil {
			return Header5UDP([]byte{}, common.IP6Addr, ip6, uint16(port)), nil
		}
	}

	if len(host) > 255 {
		// TODO: Better error
		return nil, fmt.Errorf("too long hostname")
	}

	return Header5UDP([]byte{}, common.DomAddr, []byte(host), uint16(port)), nil
}

func Write5ToUDPaddr(
	pool common.BufferPool,
	writer io.Writer,
	p []byte,
	ip net.IP,
	port uint16,
) (n int, err error) {
	if ip4 := ip.To4(); ip4 != nil {
		buf := common.GetBuffer(pool, len(p)+10)
		defer common.PutBuffer(pool, buf)
		buf = buf[:0]
		buf = Header5UDP(buf, common.IP4Addr, ip4, uint16(port))

		n, err := writer.Write(buf)
		if err != nil {
			return 0, err
		}
		n = max(0, n-10-len(p))
		return n, nil
	}

	buf := common.GetBuffer(pool, len(p)+22)
	defer common.PutBuffer(pool, buf)
	buf = buf[:0]
	buf = Header5UDP(buf, common.IP6Addr, ip.To16(), uint16(port))

	n, err = writer.Write(buf)
	if err != nil {
		return 0, err
	}
	n = max(0, n-22)
	return n, nil
}

func Write5ToUDPFQDN(
	pool common.BufferPool,
	writer io.Writer,
	p []byte,
	addr string,
) (n int, err error) {
	host, strport, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	// TODO: If strport is "" -> err missinng port
	port, err := strconv.Atoi(strport)
	if err != nil {
		return 0, err
	}

	ip := net.ParseIP(host)
	if ip != nil {
		return Write5ToUDPaddr(pool, writer, p, ip, uint16(port))
	}

	if len(host) > 255 {
		// TODO: Better error
		return 0, fmt.Errorf("too long hostname")
	}

	buf := common.GetBuffer(pool, len(p)+7+len(host))
	defer common.PutBuffer(pool, buf)
	buf = buf[:0]
	buf = Header5UDP(buf, common.DomAddr, []byte(host), uint16(port))
	n, err = writer.Write(buf)
	if err != nil {
		return 0, err
	}
	n = max(0, n-7)
	return n, nil
}

func Run5PassAuthHandshake(conn net.Conn, uid, password string) error {
	user := []byte(uid)
	pass := []byte(password)
	if len(user) > 255 {
		return fmt.Errorf("too big username: %d bytes", len(user))
	}
	if len(pass) > 255 {
		return fmt.Errorf("too big password: %d bytes", len(pass))
	}

	pack := make([]byte, 0, 3+len(user)+len(pass))
	pack = append(pack, 1)
	pack = append(pack, byte(len(user)))
	pack = append(pack, user...)
	pack = append(pack, byte(len(pass)))
	pack = append(pack, pass...)

	_, err := io.Copy(conn, bytes.NewReader(pack))
	if err != nil {
		// TODO: Better error
		return err
	}

	var resp [2]byte
	i, err := conn.Read(resp[:])
	if err != nil {
		// TODO: Better error
		return err
	} else if i != 2 {
		// TODO: Better error
		return fmt.Errorf("Unexpected EOF")
	}

	if resp[1] != 0 {
		// TODO: Better error
		return fmt.Errorf("user/pass auth failed")
	}

	return nil
}

func Run5Auth(conn net.Conn, uid, password *string) error {
	var pack []byte
	if uid == nil && password == nil {
		pack = []byte{common.V5, 1, byte(common.NoAuth)}
	} else {
		pack = []byte{common.V5, 2, byte(common.NoAuth), byte(common.PassAuth)}
	}
	_, err := io.Copy(conn, bytes.NewReader(pack))
	if err != nil {
		// TODO: Better error
		return err
	}
	var resp [2]byte
	i, err := conn.Read(resp[:])
	if err != nil {
		return err
	} else if i != 2 {
		// TODO: Better error
		return fmt.Errorf("Unexpected EOF")
	}
	method := common.AuthMethod(resp[1])
	switch method {
	case common.NoAuth:
		return nil
	case common.PassAuth:
		if uid == nil && password == nil {
			// TODO: Better error
			return fmt.Errorf("wrong auth method reqested by server: %s", method)
		}
		return Run5PassAuthHandshake(conn, *uid, *password)
	default:
		// TODO: Better error
		return fmt.Errorf("wrong auth method reqested by server: %s", method)
	}
}
