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
