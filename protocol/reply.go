package protocol

import "strconv"

const (
	// Socks5
	SuccReply        ReplyStatus = 0x0
	FailReply        ReplyStatus = 0x1
	DisallowReply    ReplyStatus = 0x2
	NetUnreachReply  ReplyStatus = 0x3
	HostUnreachReply ReplyStatus = 0x4
	ConnRefusedReply ReplyStatus = 0x5
	TTLExpiredReply  ReplyStatus = 0x6
	CmdNotSuppReply  ReplyStatus = 0x7
	AddrNotSuppReply ReplyStatus = 0x80

	// Socks4
	Granted       ReplyStatus = 90
	Rejected      ReplyStatus = 91
	IdentRequired ReplyStatus = 92
	IdentFailed   ReplyStatus = 93

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
	// socks4
	case Granted:
		return "request granted"
	case Rejected:
		return "request rejected or failed"
	case IdentFailed:
		return "request rejected becasue socks server cannot connect to identd on the client"
	case IdentRequired:
		return "request rejected because the client program and identd report different user-ids"

	// socks5
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

// Convert all socks5 specific status codes to corresponding socks4 ones
func (r ReplyStatus) To5() ReplyStatus {
	switch r {
	case Granted:
		return SuccReply
	case Rejected:
		return FailReply
	case IdentFailed:
		return FailReply
	case IdentRequired:
		return FailReply
	}
	return r
}

// Convert all socks4 specific status codes to corresponding socks4 ones
func (r ReplyStatus) To4() ReplyStatus {
	switch r {
	case SuccReply:
		return Granted
	case FailReply:
		return Rejected
	case DisallowReply:
		return Rejected
	case NetUnreachReply:
		return Rejected
	case HostUnreachReply:
		return Rejected
	case ConnRefusedReply:
		return Rejected
	case TTLExpiredReply:
		return Rejected
	case CmdNotSuppReply:
		return Rejected
	case AddrNotSuppReply:
		return Rejected
	case TorDescNotFound:
		return Rejected
	case TorDescInvalid:
		return Rejected
	case TorIntroFail:
		return Rejected
	case TorRendFailed:
		return Rejected
	case TorMissAuth:
		return Rejected
	case TorWrongAuth:
		return Rejected
	case TorInvalidAddr:
		return Rejected
	case TorIntroTimeOut:
		return Rejected
	}
	return r
}
