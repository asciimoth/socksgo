package internal

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
)

// tcp | tcp4 | tcp6 -> tcp
// udp | udp4 | udp6 -> udp
func NormalNet(network string) string {
	if network == "" {
		return ""
	}
	if strings.HasSuffix(network, "4") {
		return strings.TrimRight(network, "4")
	}
	if strings.HasSuffix(network, "6") {
		return strings.TrimRight(network, "6")
	}
	return network
}

func LookupPortOffline(network, service string) (port int, err error) {
	// A bit dirty hack to prevent Resolver for sending DNS requests
	// and force only local lookup
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return nil, errors.New("BLOCKED")
		},
	}
	port, err = r.LookupPort(context.Background(), network, service)
	if err != nil {
		err = &net.DNSError{
			Err:        "unknown port",
			Name:       network + "/" + service,
			IsNotFound: true,
		}
	}
	return
}

// defport will be used as port if there is no port in hostport or it is invalid.
func SplitHostPort(network, hostport string, defport uint16) (host string, port uint16) {
	const MAX_UINT16 = 65535

	host, strPort, err := net.SplitHostPort(hostport)
	if err != nil {
		// There is no port in hostport, only host
		return hostport, defport
	}

	port = defport
	intPort, err := strconv.Atoi(strPort)
	if err != nil {
		intPort, err = LookupPortOffline(network, strPort)
	}
	if err == nil && intPort <= MAX_UINT16 {
		port = uint16(intPort)
	}

	return host, port
}

var TooLongStringErr = errors.New("string is too long")

// Should be cap(buf) >= 1
func ReadNullTerminatedString(r io.Reader, buf []byte) (string, error) {
	buf = buf[:1]
	for {
		n, err := r.Read(buf[len(buf)-1:])
		if err != nil {
			return "", err
		}
		if n < 1 {
			continue
		}
		if buf[len(buf)-1] == 0 {
			buf = buf[:len(buf)-1]
			break
		}
		if len(buf) == cap(buf) {
			return "", TooLongStringErr
		}
		buf = buf[:len(buf)+1] //grow
	}
	return string(buf), nil
}

func CopyBytes(src []byte) (dst []byte) {
	if src == nil {
		return nil
	}
	dst = make([]byte, len(src))
	copy(dst, src)
	return
}

func ClosedNetworkErrToNil(err error) error {
	var unwrapped = err
	for {
		u := errors.Unwrap(unwrapped)
		if u == nil {
			break
		}
		unwrapped = u
	}
	if unwrapped != nil && unwrapped.Error() == "use of closed network connection" {
		return nil
	}
	return err
}

// Try to read until read fails, close rc, returns
func WaitForClose(rc io.ReadCloser) {
	defer rc.Close()
	b := []byte{0}
	for {
		_, err := rc.Read(b)
		if err != nil {
			return
		}
	}
}

func JoinNetErrors(a, b error) (err error) {
	a = ClosedNetworkErrToNil(a)
	b = ClosedNetworkErrToNil(b)
	if a != nil && b == nil {
		err = a
	} else if b != nil && a == nil {
		err = b
	} else if a != nil && b != nil {
		err = errors.Join(a, b)
	}
	return
}

func AddrsSameHost(a, b net.Addr) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	switch aa := a.(type) {
	case *net.TCPAddr:
		if bb, ok := b.(*net.TCPAddr); ok {
			return ipEqual(aa.IP, bb.IP)
		}
	case *net.UDPAddr:
		if bb, ok := b.(*net.UDPAddr); ok {
			return ipEqual(aa.IP, bb.IP)
		}
	}

	ahost := a.String()
	bhost := b.String()

	if host, _, err := net.SplitHostPort(ahost); err == nil {
		ahost = host
	}
	if host, _, err := net.SplitHostPort(bhost); err == nil {
		bhost = host
	}

	return ahost == bhost
}

// Fast net.Addr comparison
func AddrsEq(a, b net.Addr) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	switch aa := a.(type) {
	case *net.TCPAddr:
		if bb, ok := b.(*net.TCPAddr); ok {
			return tcpUDPAddrEqual(aa.IP, aa.Port, bb.IP, bb.Port)
		}
	case *net.UDPAddr:
		if bb, ok := b.(*net.UDPAddr); ok {
			return tcpUDPAddrEqual(aa.IP, aa.Port, bb.IP, bb.Port)
		}
	}

	// Fallback: compare string representation
	return a.String() == b.String()
}

func ipEqual(a, b net.IP) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}

// compare IP + port + zone
func tcpUDPAddrEqual(aIP net.IP, aPort int, bIP net.IP, bPort int) bool {
	if aPort != bPort {
		return false
	}
	return ipEqual(aIP, bIP)
}
