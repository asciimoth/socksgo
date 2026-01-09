package socks

import (
	"errors"
	"fmt"
	"net"

	"github.com/asciimoth/socks/protocol"
)

var (
	ErrUDPDisallowed             = errors.New("plaintext UDP is disallowed for tls/wss proxies")
	ErrResolveDisabled           = errors.New("tor resolve extension for socks is disabled")
	ErrWrongAddrInLookupResponse = errors.New("wrong addr type in lookup response")
)

type WrongNetworkError struct {
	SocksVersion string // "4" | "4a" | "5"
	Network      string
}

func (e WrongNetworkError) Error() string {
	return fmt.Sprintf(
		"socks%s %s",
		e.SocksVersion,
		e.Unwrap(),
	)
}

func (e WrongNetworkError) Unwrap() error {
	return net.UnknownNetworkError(e.Network)
}

type UnsupportedAddrError struct {
	SocksVersion string // "4" | "4a" | "5"
	Addr         string
}

func (e UnsupportedAddrError) Error() string {
	return fmt.Sprintf(
		"addr %s is unsupported by socks%s",
		e.Addr,
		e.SocksVersion,
	)
}

type UnknownSocksVersionError struct {
	Version string
}

func (e UnknownSocksVersionError) Error() string {
	return fmt.Sprintf("unknown socks version %s", e.Version)
}

type RejectdError struct {
	Status protocol.ReplyStatus
}

func (e RejectdError) Error() string {
	return fmt.Sprintf(
		"socks request rejected with code %d %s",
		int(e.Status),
		e.Status,
	)
}
