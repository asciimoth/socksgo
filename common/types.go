package common

import (
	"context"
	"net"
	"strconv"
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

const (
	V4 = 0x04
	V5 = 0x05

	V4Name  = "socks4"
	V4aName = "socks4a"
	V5aName = "socks5"

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

	IP4Addr AddrType = 0x01
	IP6Addr AddrType = 0x04
	DomAddr AddrType = 0x03

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
