package protocol

import (
	"errors"
	"fmt"
)

// Protocol-level error values.
//
// These errors are returned when protocol encoding/decoding fails
// or when protocol constraints are violated.
var (
	// ErrNoAcceptableAuthMethods is returned when the server doesn't
	// support any of the client's advertised authentication methods.
	ErrNoAcceptableAuthMethods = errors.New("no acceptable socks auth methods")

	// ErrTooLongUser is returned when a username exceeds the maximum
	// allowed length (MAX_HEADER_STR_LENGTH = 255 bytes).
	ErrTooLongUser = errors.New("socks user name is too long")

	// ErrTooLongHost is returned when a hostname/FQDN exceeds the
	// maximum allowed length (MAX_HEADER_STR_LENGTH = 255 bytes).
	ErrTooLongHost = errors.New("socks host name is too long")

	// ErrUDPAssocTimeout is returned when a UDP association times out
	// due to inactivity.
	ErrUDPAssocTimeout = errors.New("socks udp assoc timeout")
)

// UnknownAuthVerError is returned when an unknown authentication version
// is received during SOCKS5 auth negotiation.
type UnknownAuthVerError struct {
	Version int
}

func (e UnknownAuthVerError) Error() string {
	return fmt.Sprintf("unknown socks auth version %d", e.Version)
}

// UnsupportedAuthMethodError is returned when the server selects an
// authentication method that the client doesn't support.
type UnsupportedAuthMethodError struct {
	Method AuthMethodCode
}

func (e UnsupportedAuthMethodError) Error() string {
	return fmt.Sprintf(
		"socks server select unsupported auth method %d",
		e.Method,
	)
}

// UnknownAddrTypeError is returned when an unknown address type is
// encountered in a SOCKS request or reply.
type UnknownAddrTypeError struct {
	Type AddrType
}

func (e UnknownAddrTypeError) Error() string {
	return fmt.Sprintf("unknown socks addr type: %s", e.Type)
}

// Wrong4ReplyVerError is returned when a SOCKS4 reply has an unexpected
// version byte.
//
// SOCKS4 replies should always have version byte 0.
type Wrong4ReplyVerError struct {
	Version int
}

func (e Wrong4ReplyVerError) Error() string {
	return fmt.Sprintf("wrong socks4 reply version %d, should be 0", e.Version)
}

// WrongProtocolVerError is returned when a SOCKS request or reply has
// an unexpected protocol version.
type WrongProtocolVerError struct {
	Version int
}

func (e WrongProtocolVerError) Error() string {
	return fmt.Sprintf("wrong socks protocol version %d", e.Version)
}
