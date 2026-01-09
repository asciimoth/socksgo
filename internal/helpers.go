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
