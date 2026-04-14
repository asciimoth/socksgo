//go:build testhooks

package socksgo

import (
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

// TestResolveUnspecifiedAddr exposes resolveUnspecifiedAddr for testing.
// This function is only available with the "testhooks" build tag.
func TestResolveUnspecifiedAddr(
	proxy net.Conn,
	naddr protocol.Addr,
) protocol.Addr {
	return resolveUnspecifiedAddr(proxy, naddr)
}

// TestClientListener5 is an exported version of clientListener5 for testing.
// This is only available with the "testhooks" build tag.
type TestClientListener5 = clientListener5
