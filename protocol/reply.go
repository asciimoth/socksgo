package protocol

import "strconv"

// SOCKS5 reply status codes.
//
// These constants define the response status values in SOCKS5 replies
// as specified in RFC 1928.
const (
	// SuccReply indicates the request succeeded.
	// Wire value: 0x0
	SuccReply ReplyStatus = 0x0

	// FailReply indicates a general SOCKS server failure.
	// Wire value: 0x1
	FailReply ReplyStatus = 0x1

	// DisallowReply indicates the connection was not allowed by ruleset.
	// Typically used when address filters reject the request.
	// Wire value: 0x2
	DisallowReply ReplyStatus = 0x2

	// NetUnreachReply indicates the network is unreachable.
	// Wire value: 0x3
	NetUnreachReply ReplyStatus = 0x3

	// HostUnreachReply indicates the host is unreachable.
	// Typically used when dialing the target fails.
	// Wire value: 0x4
	HostUnreachReply ReplyStatus = 0x4

	// ConnRefusedReply indicates the connection was refused by the target.
	// Wire value: 0x5
	ConnRefusedReply ReplyStatus = 0x5

	// TTLExpiredReply indicates the TTL expired (used in UDP assoc).
	// Wire value: 0x6
	TTLExpiredReply ReplyStatus = 0x6

	// CmdNotSuppReply indicates the command is not supported.
	// Wire value: 0x7
	CmdNotSuppReply ReplyStatus = 0x7

	// AddrNotSuppReply indicates the address type is not supported.
	// Wire value: 0x8
	AddrNotSuppReply ReplyStatus = 0x80
)

// SOCKS4 reply status codes.
//
// SOCKS4 uses a different reply code scheme than SOCKS5.
// See https://www.openssh.com/txt/socks4.protocol
const (
	// Granted indicates the request was granted.
	// Wire value: 90
	Granted ReplyStatus = 90

	// Rejected indicates the request was rejected or failed.
	// Wire value: 91
	Rejected ReplyStatus = 91

	// IdentRequired indicates the client program and identd report
	// different user-ids.
	// Wire value: 92
	IdentRequired ReplyStatus = 92

	// IdentFailed indicates the socks server cannot connect to identd
	// on the client.
	// Wire value: 93
	IdentFailed ReplyStatus = 93
)

// Tor SOCKS extension reply codes.
//
// These status codes are defined in the Tor SOCKS extensions specification:
// https://spec.torproject.org/socks-extensions.html
const (
	// TorDescNotFound indicates the onion service descriptor cannot be found.
	// Wire value: 0xf0
	TorDescNotFound ReplyStatus = 0xf0

	// TorDescInvalid indicates the onion service descriptor is invalid.
	// Wire value: 0xf1
	TorDescInvalid ReplyStatus = 0xf1

	// TorIntroFail indicates the onion service introduction failed.
	// Wire value: 0xf2
	TorIntroFail ReplyStatus = 0xf2

	// TorRendFailed indicates the onion service rendezvous failed.
	// Wire value: 0xf3
	TorRendFailed ReplyStatus = 0xf3

	// TorMissAuth indicates the onion service is missing client authorization.
	// Wire value: 0xf4
	TorMissAuth ReplyStatus = 0xf4

	// TorWrongAuth indicates the onion service has wrong client authorization.
	// Wire value: 0xf5
	TorWrongAuth ReplyStatus = 0xf5

	// TorInvalidAddr indicates an invalid onion service address.
	// Wire value: 0xf6
	TorInvalidAddr ReplyStatus = 0xf6

	// TorIntroTimeOut indicates the onion service introduction timed out.
	// Wire value: 0xf7
	TorIntroTimeOut ReplyStatus = 0xf7
)

// ReplyStatus represents a SOCKS reply status code.
//
// ReplyStatus is used in SOCKS replies to indicate the result of a request.
// SOCKS4 and SOCKS5 use different status code ranges, and this type provides
// methods to convert between them (To4, To5).
//
// # Examples
//
//	// Check if request succeeded
//	if status.Ok() {
//	    // Request granted
//	}
//
//	// Convert to SOCKS4 status
//	status4 := status.To4()
//
//	// String representation
//	status.String() // Returns "succeeded", "host unreachable", etc.
type ReplyStatus uint8

// Ok reports whether the status indicates success.
//
// Returns true for:
//   - SuccReply (SOCKS5 success)
//   - Granted (SOCKS4 success)
//
// All other status codes return false.
func (r ReplyStatus) Ok() bool {
	return r == Granted || r == SuccReply
}

// String returns a human-readable description of the status code.
//
// Returns descriptive strings for all known SOCKS4, SOCKS5, and Tor
// extension status codes. For unknown values, returns "reply code noX"
// where X is the numeric value.
//
// # Examples
//
//	protocol.SuccReply.String()        // "succeeded"
//	protocol.HostUnreachReply.String() // "host unreachable"
//	protocol.Granted.String()          // "request granted"
func (r ReplyStatus) String() string {
	switch r {
	// socks4
	case Granted:
		return "request granted"
	case Rejected:
		return "request rejected or failed"
	case IdentFailed:
		return "request rejected because socks server cannot connect to identd on the client"
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
		return "network unreachable"
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

// To5 converts a ReplyStatus to its SOCKS5 equivalent.
//
// SOCKS4-specific codes are mapped to SOCKS5 equivalents:
//   - Granted -> SuccReply
//   - Rejected, IdentFailed, IdentRequired -> FailReply
//
// SOCKS5 and Tor extension codes are returned unchanged.
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
	case SuccReply:
		return r
	case FailReply:
		return r
	case DisallowReply:
		return r
	case NetUnreachReply:
		return r
	case HostUnreachReply:
		return r
	case ConnRefusedReply:
		return r
	case TTLExpiredReply:
		return r
	case CmdNotSuppReply:
		return r
	case AddrNotSuppReply:
		return r
	case TorDescNotFound:
		return r
	case TorDescInvalid:
		return r
	case TorIntroFail:
		return r
	case TorRendFailed:
		return r
	case TorMissAuth:
		return r
	case TorWrongAuth:
		return r
	case TorInvalidAddr:
		return r
	case TorIntroTimeOut:
		return r
	}
	return r
}

// To4 converts a ReplyStatus to its SOCKS4 equivalent.
//
// SOCKS5-specific codes are mapped to SOCKS4 equivalents:
//   - SuccReply -> Granted
//   - All other SOCKS5 codes -> Rejected
//
// SOCKS4 codes are returned unchanged.
//
// Note: SOCKS4 has limited status code granularity compared to SOCKS5,
// so most error conditions map to the generic Rejected code.
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
	case Granted:
		return r
	case Rejected:
		return r
	case IdentRequired:
		return r
	case IdentFailed:
		return r
	}
	return r
}
