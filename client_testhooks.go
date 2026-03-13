//go:build testhooks

package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

// Test hooks for improving test coverage.
// These hooks are only compiled when the "testhooks" build tag is used.
//
// Usage in tests:
//
//	// Set up hook before test
//	oldHook := testLookupIPHook
//	testLookupIPHook = func(addr protocol.Addr) protocol.Addr {
//	    // Return modified address to trigger specific code paths
//	    return protocol.AddrFromFQDN("example.com", 0, "tcp")
//	}
//	defer func() { testLookupIPHook = oldHook }()
//
//	// Run test that uses LookupIP
//
// Note: These hooks are intentionally not exported and only available
// within the socksgo package for testing purposes.

// testLookupIPHook is called after Request returns in LookupIP.
// It can modify the returned address to test error paths.
// Default: returns addr unchanged.
var testLookupIPHook = func(addr protocol.Addr) protocol.Addr {
	return addr
}

// testLookupAddrHook is called after Request returns in LookupAddr.
// It can modify the returned address to test error paths.
// Default: returns addr unchanged.
var testLookupAddrHook = func(addr protocol.Addr) protocol.Addr {
	return addr
}

// testListenSmuxHook is called after smux.Server succeeds in Listen.
// It can return an error to test the error handling path.
// Default: returns nil (no error).
var testListenSmuxHook = func() error {
	return nil
}

// testListenCloseHook is called instead of conn.Close() in error paths.
// It can be used to verify the close is called.
// Default: does nothing.
var testListenCloseHook = func(conn net.Conn) {
	_ = conn.Close()
}

// testRequestHook is called at the start of request().
// It can return a custom connection and address to test error paths.
// If ok is true, the returned values are used and normal flow is skipped.
// Default: returns nil, nil, false (continue with normal flow).
var testRequestHook = func(
	ctx context.Context,
	cmd protocol.Cmd,
	address protocol.Addr,
) (net.Conn, protocol.Addr, bool) {
	return nil, protocol.Addr{}, false
}

// SetTestLookupIPHook sets the hook for LookupIP.
// This function is only available with the "testhooks" build tag.
func SetTestLookupIPHook(hook func(protocol.Addr) protocol.Addr) {
	testLookupIPHook = hook
}

// GetTestLookupIPHook returns the current LookupIP hook.
// This function is only available with the "testhooks" build tag.
func GetTestLookupIPHook() func(protocol.Addr) protocol.Addr {
	return testLookupIPHook
}

// SetTestLookupAddrHook sets the hook for LookupAddr.
// This function is only available with the "testhooks" build tag.
func SetTestLookupAddrHook(hook func(protocol.Addr) protocol.Addr) {
	testLookupAddrHook = hook
}

// GetTestLookupAddrHook returns the current LookupAddr hook.
// This function is only available with the "testhooks" build tag.
func GetTestLookupAddrHook() func(protocol.Addr) protocol.Addr {
	return testLookupAddrHook
}

// SetTestListenSmuxHook sets the hook for Listen smux error path.
// This function is only available with the "testhooks" build tag.
func SetTestListenSmuxHook(hook func() error) {
	testListenSmuxHook = hook
}

// GetTestListenSmuxHook returns the current Listen smux hook.
// This function is only available with the "testhooks" build tag.
func GetTestListenSmuxHook() func() error {
	return testListenSmuxHook
}

// SetTestListenCloseHook sets the hook for Listen connection close.
// This function is only available with the "testhooks" build tag.
func SetTestListenCloseHook(hook func(net.Conn)) {
	testListenCloseHook = hook
}

// GetTestListenCloseHook returns the current Listen close hook.
// This function is only available with the "testhooks" build tag.
func GetTestListenCloseHook() func(net.Conn) {
	return testListenCloseHook
}

// SetTestRequestHook sets the hook for request().
// This function is only available with the "testhooks" build tag.
func SetTestRequestHook(
	hook func(context.Context, protocol.Cmd, protocol.Addr) (net.Conn, protocol.Addr, bool),
) {
	testRequestHook = hook
}

// GetTestRequestHook returns the current request hook.
// This function is only available with the "testhooks" build tag.
func GetTestRequestHook() func(context.Context, protocol.Cmd, protocol.Addr) (net.Conn, protocol.Addr, bool) {
	return testRequestHook
}

// Helper functions for creating test addresses

// TestAddrFromFQDN creates an FQDN address for testing.
// This function is only available with the "testhooks" build tag.
func TestAddrFromFQDN(fqdn string, port uint16, network string) protocol.Addr {
	return protocol.AddrFromFQDN(fqdn, port, network)
}

// TestAddrFromIP creates an IP address for testing.
// This function is only available with the "testhooks" build tag.
func TestAddrFromIP(ip net.IP, port uint16, network string) protocol.Addr {
	return protocol.AddrFromIP(ip, port, network)
}

// resetTestHooks resets all hooks to their default values.
// This function is only available with the "testhooks" build tag.
func resetTestHooks() {
	testLookupIPHook = func(addr protocol.Addr) protocol.Addr {
		return addr
	}
	testLookupAddrHook = func(addr protocol.Addr) protocol.Addr {
		return addr
	}
	testListenSmuxHook = func() error {
		return nil
	}
	testListenCloseHook = func(conn net.Conn) {
		_ = conn.Close()
	}
	testRequestHook = func(
		ctx context.Context,
		cmd protocol.Cmd,
		address protocol.Addr,
	) (net.Conn, protocol.Addr, bool) {
		return nil, protocol.Addr{}, false
	}
}

// ResetTestHooks resets all hooks to their default values.
// This function is only available with the "testhooks" build tag.
func ResetTestHooks() {
	resetTestHooks()
}

// The following are the modified methods in client.go that use the hooks.
// These are compile-time replacements when testhooks tag is enabled.

// lookupIPWithHook is a testable wrapper for the LookupIP logic.
func (c *Client) lookupIPWithHook(
	ctx context.Context,
	network, address string,
	addr protocol.Addr,
) ([]net.IP, error) {
	ip := testLookupIPHook(addr).ToIP()
	if ip == nil {
		return nil, ErrWrongAddrInLookupResponse
	}
	return []net.IP{ip}, nil
}

// lookupAddrWithHook is a testable wrapper for the LookupAddr logic.
func (c *Client) lookupAddrWithHook(
	ctx context.Context,
	addr protocol.Addr,
) ([]string, error) {
	return []string{testLookupAddrHook(addr).ToFQDN()}, nil
}

// listenSmuxWithHook is a testable wrapper for the Listen smux logic.
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
