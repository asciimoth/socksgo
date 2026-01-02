package common

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
)

const (
	V4 = 0x04
	V5 = 0x05

	IP4Addr AddrType = 0x01
	IP6Addr AddrType = 0x04
	DomAddr AddrType = 0x03

	CmdConnect       Cmd = 0x01
	CmdBind          Cmd = 0x02
	CmdUDPAssoc      Cmd = 0x03
	CmdTorResolve    Cmd = 0xF0
	CmdTorResolvePtr Cmd = 0xF1
	CmdGostMuxBind   Cmd = 0xF2
	CmdGostUDPTun    Cmd = 0xF3

	Cmdr4Granted       CmdResp4 = 90
	Cmdr4Rejected      CmdResp4 = 91
	Cmdr4IdentRequired CmdResp4 = 92
	Cmdr4IdentFailed   CmdResp4 = 93

	NoAuth    AuthMethod = 0x0
	GSSAuth   AuthMethod = 0x1
	PassAuth  AuthMethod = 0x02
	NoAccAuth AuthMethod = 0xff

	SuccReply        ReplyStatus = 0x0
	FailReply        ReplyStatus = 0x1
	DisallowReply    ReplyStatus = 0x2
	NetUnreachReply  ReplyStatus = 0x3
	HostUnreachReply ReplyStatus = 0x4
	ConnRefusedReply ReplyStatus = 0x5
	TTLExpiredReply  ReplyStatus = 0x6
	CmdNotSuppReply  ReplyStatus = 0x7
	AddrNotSuppReply ReplyStatus = 0x80
	// Codes from tor's socks extension
	// https://spec.torproject.org/socks-extensions.html
	TorDescNotFound ReplyStatus = 0xf0
	TorDescInvalid  ReplyStatus = 0xf1
	TorIntroFail    ReplyStatus = 0xf2
	TorRendFailed   ReplyStatus = 0xf3
	TorMissAuth     ReplyStatus = 0xf4
	TorWrongAuth    ReplyStatus = 0xf5
	TorInvalidAddr  ReplyStatus = 0xf6
	TorIntroTimeOut ReplyStatus = 0xf7
)

var (
	_ net.Addr = Addr{}
)

type Resolver interface {
	LookupPort(ctx context.Context, network, service string) (port int, err error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupAddr(ctx context.Context, address string) ([]string, error)
}

type Dialer = func(ctx context.Context, network, address string) (net.Conn, error)

type Listener = func(ctx context.Context, network, address string) (net.Listener, error)

// Return true if dial should go through a proxy, false if direct
// network may be "" if it is unknown
type DirectFilter = func(network, address string) bool

type AddrType uint8

func (a AddrType) String() string {
	switch a {
	case IP4Addr:
		return "IPv4 addr"
	case IP6Addr:
		return "IPv6 addr"
	case DomAddr:
		return "domain name addr"
	default:
		return "addr type no" + strconv.Itoa(int(a))
	}
}

type Addr struct {
	Type AddrType
	Host []byte
	Port uint16
	Net  string // tcp | udp ; not tcp4 | udp6 | etc; Default net is "tcp"
}

// TODO: Test
func AddrFromNetAddr(addr net.Addr) Addr {
	host, port := SplitHostPort(addr.Network(), addr.String(), 0)

	network := addr.Network()
	if strings.HasSuffix(network, "4") {
		network = strings.TrimRight(network, "4")
	} else if strings.HasSuffix(network, "6") {
		network = strings.TrimRight(network, "6")
	}

	ip := net.ParseIP(host)
	if ip != nil {
		return AddrFromIP(ip, port, addr.Network())
	}

	return AddrFromDom(host, port, addr.Network())
}

func AddrFromIP(ip net.IP, port uint16, net string) Addr {
	if ip4 := ip.To4(); ip != nil {
		return Addr{
			Type: IP4Addr,
			Host: append([]byte{}, []byte(ip4)...),
			Port: port,
			Net:  net,
		}
	}
	ip6 := ip.To16()
	return Addr{
		Type: IP6Addr,
		Host: append([]byte{}, []byte(ip6)...),
		Port: port,
		Net:  net,
	}
}

// If dom already contains port (e.g. "example.com:80") it will be used instead of port arg.
func AddrFromDom(dom string, port uint16, net string) Addr {
	dom, port = SplitHostPort(net, dom, port)
	return Addr{
		Type: DomAddr,
		Host: []byte(dom),
		Port: port,
		Net:  net,
	}
}

func (a Addr) IsUnspecified() bool {
	if a.Type == IP4Addr || a.Type == IP6Addr {
		return net.IP(a.Host).IsUnspecified()
	}
	return false
}

func (a Addr) ToIP() net.IP {
	switch a.Type {
	case IP4Addr:
		return net.IP(a.Host)
	case IP6Addr:
		return net.IP(a.Host)
	}
	return nil
}

func (a Addr) ToFQDN() string {
	if a.Type == DomAddr {
		return string(a.Host)
	}
	return ""
}

func (a Addr) Network() string {
	net := a.Net
	if net == "" {
		net = "tcp"
	}
	switch a.Type {
	case IP4Addr:
		return net + "4"
	case IP6Addr:
		return net + "6"
	}
	return net
}

func (a Addr) HostString() string {
	switch a.Type {
	case IP4Addr:
		return net.IP(a.Host).String()
	case IP6Addr:
		return net.IP(a.Host).String()
	case DomAddr:
		return string(a.Host)
	}
	return a.Type.String()
}

func (a Addr) String() string {
	return net.JoinHostPort(a.HostString(), strconv.Itoa(int(a.Port)))
}

type ReplyStatus uint8

func (r ReplyStatus) String() string {
	switch r {
	case SuccReply:
		return "succeeded"
	case FailReply:
		return "general SOCKS server failure"
	case DisallowReply:
		return "connection not allowed by ruleset"
	case NetUnreachReply:
		return "hetwork unreachable"
	case HostUnreachReply:
		return "host unreachable"
	case ConnRefusedReply:
		return "connection refused"
	case TTLExpiredReply:
		return "TTL expired"
	case CmdNotSuppReply:
		return "command not supported"
	case AddrNotSuppReply:
		return "address type not supported"
	case TorDescNotFound:
		return "onion service descriptor can not be found"
	case TorDescInvalid:
		return "onion service descriptor is invalid"
	case TorIntroFail:
		return "onion service introduction failed"
	case TorRendFailed:
		return "onion service rendezvous failed"
	case TorMissAuth:
		return "onion service missing client authorization"
	case TorWrongAuth:
		return "onion service wrong client authorization"
	case TorInvalidAddr:
		return "onion service invalid address"
	case TorIntroTimeOut:
		return "onion service introduction timed out"
	default:
		return "reply code no" + strconv.Itoa(int(r))
	}
}

type AuthMethod uint8

func (a AuthMethod) String() string {
	if a >= 0x3 && a <= 0x7f {
		return "IANA assiged auth"
	}
	if a >= 0x80 && a <= 0xfe {
		return "private auth method"
	}
	switch a {
	case NoAuth:
		return "no auth required"
	case GSSAuth:
		return "GSS auth"
	case PassAuth:
		return "user-pass auth"
	case NoAccAuth:
		return "no acceptable auth methods"
	default:
		return "auth method no" + strconv.Itoa(int(a))
	}
}

type Cmd uint8

func (cmd Cmd) String() string {
	switch cmd {
	case CmdConnect:
		return "cmd connect"
	case CmdBind:
		return "cmd bind"
	case CmdUDPAssoc:
		return "cmd UDP associate"
	case CmdTorResolve:
		return "cmd tor resolve"
	case CmdTorResolvePtr:
		return "cmd tor resolve_ptr"
	default:
		return "cmd no" + strconv.Itoa(int(cmd))
	}
}

type CmdResp4 uint8

func (cmd CmdResp4) String() string {
	switch cmd {
	case Cmdr4Granted:
		return "request granted"
	case Cmdr4Rejected:
		return "request rejected or failed"
	case Cmdr4IdentFailed:
		return "request rejected becasue socks server cannot connect to identd on the client"
	case Cmdr4IdentRequired:
		return "request rejected because the client program and identd report different user-ids"
	default:
		return "socks response cmd no" + strconv.Itoa(int(cmd))
	}
}

type BufferPool interface {
	GetBuffer(length int) []byte
	PutBuffer(buf []byte)
}

func LookupPortOffline(network, service string) (port int, err error) {
	// A bit dirty hack to prevent Resolver for sending DNS requests
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
// TODO: Test
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
