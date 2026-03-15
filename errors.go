// Package socksgo implements SOCKS proxy client and server (SOCKS4, SOCKS4a, SOCKS5)
// with extensions for Gost and Tor compatibility.
package socksgo

import (
	"errors"
	"fmt"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

// Client-side error variables.
var (
	// ErrUDPDisallowed is returned when attempting plaintext UDP over TLS/WSS
	// proxies without the insecureudp option enabled.
	ErrUDPDisallowed = errors.New(
		"plaintext UDP is disallowed for tls/wss proxies",
	)
	// ErrResolveDisabled is returned when Tor lookup extension is requested
	// but not enabled on the client.
	ErrResolveDisabled = errors.New(
		"tor resolve extension for socks is disabled",
	)
	// ErrWrongAddrInLookupResponse is returned when a Tor resolve response
	// contains an unexpected address type.
	ErrWrongAddrInLookupResponse = errors.New(
		"wrong addr type in lookup response",
	)
	// ErrClientAuthFailed is returned when client authentication fails.
	ErrClientAuthFailed = errors.New("client auth failed")
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

// UnsupportedAddrError is returned when an address type is not supported
// by the specified SOCKS version (e.g., FQDN with SOCKS4).
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

// UnknownSocksVersionError is returned when an unrecognized SOCKS version
// is specified.
type UnknownSocksVersionError struct {
	Version string
}

func (e UnknownSocksVersionError) Error() string {
	return fmt.Sprintf("unknown socks version %s", e.Version)
}

// RejectdError wraps a server rejection response with the reply status code.
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

// UnsupportedCommandError is returned when a command is not supported
// by the specified SOCKS version.
type UnsupportedCommandError struct {
	SocksVersion string // "4" | "4a" | "5"
	Cmd          protocol.Cmd
}

func (e UnsupportedCommandError) Error() string {
	return fmt.Sprintf(
		"socks%s client requested unsupported command %d (%s)",
		e.SocksVersion,
		int(e.Cmd),
		e.Cmd.String(),
	)
}

// NilHandlerError is returned when a command handler is not registered
// for the requested command.
type NilHandlerError struct {
	Cmd protocol.Cmd
}

func (e NilHandlerError) Error() string {
	return fmt.Sprintf(
		"attempt to run nil handler for cmd %d (%s)",
		int(e.Cmd),
		e.Cmd.String(),
	)
}

// AddrDisallowedError is returned when an address is blocked by a filter.
type AddrDisallowedError struct {
	Addr       *protocol.Addr
	FilterName string
}

func (e AddrDisallowedError) Error() string {
	return fmt.Sprintf(
		"address %s is disallowed by %s filter",
		e.Addr.String(),
		e.FilterName,
	)
}
