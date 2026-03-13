//go:build !testhooks

package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

// Default no-op hooks for production builds.
// These are used when the "testhooks" build tag is NOT set.

var testLookupIPHook = func(addr protocol.Addr) protocol.Addr {
	return addr
}

var testLookupAddrHook = func(addr protocol.Addr) protocol.Addr {
	return addr
}

var testListenSmuxHook = func() error {
	return nil
}

var testListenCloseHook = func(conn net.Conn) {
	_ = conn.Close()
}

var testRequestHook = func(
	ctx context.Context,
	cmd protocol.Cmd,
	address protocol.Addr,
) (net.Conn, protocol.Addr, bool) {
	return nil, protocol.Addr{}, false
}

// Stub functions for production builds (no-op)
func SetTestLookupIPHook(hook func(protocol.Addr) protocol.Addr) {
	// No-op in production
}

func SetTestLookupAddrHook(hook func(protocol.Addr) protocol.Addr) {
	// No-op in production
}

func SetTestListenSmuxHook(hook func() error) {
	// No-op in production
}

func SetTestListenCloseHook(hook func(net.Conn)) {
	// No-op in production
}

func GetTestLookupIPHook() func(protocol.Addr) protocol.Addr {
	return testLookupIPHook
}

func GetTestLookupAddrHook() func(protocol.Addr) protocol.Addr {
	return testLookupAddrHook
}

func GetTestListenSmuxHook() func() error {
	return testListenSmuxHook
}

func GetTestListenCloseHook() func(net.Conn) {
	return testListenCloseHook
}

func SetTestRequestHook(
	hook func(context.Context, protocol.Cmd, protocol.Addr) (net.Conn, protocol.Addr, bool),
) {
	// No-op in production
}

func GetTestRequestHook() func(context.Context, protocol.Cmd, protocol.Addr) (net.Conn, protocol.Addr, bool) {
	return testRequestHook
}

func ResetTestHooks() {
	// No-op in production
}

func TestAddrFromFQDN(fqdn string, port uint16, network string) protocol.Addr {
	return protocol.AddrFromFQDN(fqdn, port, network)
}

func TestAddrFromIP(ip net.IP, port uint16, network string) protocol.Addr {
	return protocol.AddrFromIP(ip, port, network)
}

func resetTestHooks() {
	// No-op in production
}

// Default implementations that just call the original logic
func (c *Client) lookupIPWithHook(
	ctx context.Context,
	network, address string,
	addr protocol.Addr,
) ([]net.IP, error) {
	ip := addr.ToIP()
	if ip == nil {
		return nil, ErrWrongAddrInLookupResponse
	}
	return []net.IP{ip}, nil
}

func (c *Client) lookupAddrWithHook(
	ctx context.Context,
	addr protocol.Addr,
) ([]string, error) {
	return []string{addr.ToFQDN()}, nil
}

func (c *Client) listenSmuxWithHook(
	conn net.Conn,
	addr protocol.Addr,
) (*clientListener5mux, error) {
	if err := testListenSmuxHook(); err != nil {
		testListenCloseHook(conn)
		return nil, err
	}
	session, err := smux.Server(conn, c.Smux)
	if err != nil {
		testListenCloseHook(conn)
		return nil, err
	}
	return &clientListener5mux{
		session: session,
		addr:    addr,
		conn:    conn,
	}, nil
}
