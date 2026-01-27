package protocol

import (
	"errors"
	"fmt"
)

var (
	ErrNoAcceptableAuthMethods = errors.New("no acceptable socks auth methods")
	ErrTooLongUser             = errors.New("socks user name is too long")
	ErrTooLongHost             = errors.New("socks host name is too long")
	ErrUDPAssocTimeout         = errors.New("socks udp assoc timeout")
)

type UnknownAuthVerError struct {
	Version int
}

func (e UnknownAuthVerError) Error() string {
	return fmt.Sprintf("unknown socks auth version %d", e.Version)
}

type UnsupportedAuthMethod struct {
	Method AuthMethodCode
}

func (e UnsupportedAuthMethod) Error() string {
	return fmt.Sprintf("socks server select unsupported auth method %d", e.Method)
}

type UnknownAddrTypeError struct {
	Type AddrType
}

func (e UnknownAddrTypeError) Error() string {
	return fmt.Sprintf("unknown socks addr type: %s", e.Type)
}

type Wrong4ReplyVerError struct {
	Version int
}

func (e Wrong4ReplyVerError) Error() string {
	return fmt.Sprintf("wrong socks4 reply version %d, should be 0", e.Version)
}

type WrongProtocolVerError struct {
	Version int
}

func (e WrongProtocolVerError) Error() string {
	return fmt.Sprintf("wrong socks protocol version %d", e.Version)
}
