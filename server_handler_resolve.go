package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

// DefaultResolveHandler handles the Tor forward DNS lookup command.
//
// DefaultResolveHandler performs DNS forward lookup (A/AAAA records)
// through the server's configured resolver and returns the resolved
// IP address to the client.
//
// # Protocol Support
//
//   - SOCKS4: Yes (with Tor extension)
//   - SOCKS4a: Yes (with Tor extension)
//   - SOCKS5: Yes (with Tor extension)
//   - TLS: Yes
//
// # Behavior
//
// 1. Validates remote address (hostname) against RaddrFilter
// 2. Performs DNS lookup using server's Resolver
// 3. If DoNotPreferIP4 is false (default):
//   - Prefers IPv4 address if both IPv4 and IPv6 found
//
// 4. Sends success reply with resolved IP address
//
// # IPv4 Preference
//
// By default (DoNotPreferIP4 = false), if the DNS lookup returns
// both IPv4 and IPv6 addresses, the first IPv4 address is returned.
// This provides better compatibility with clients that expect IPv4.
//
// # Reply
//
// Sends success reply (0x00) with the resolved IP address.
// The port in the reply is set to 0.
//
// # Errors
//
// Returns error and sends appropriate reply status:
//   - DisallowReply (0x02): Address filtered
//   - HostUnreachReply (0x04): DNS lookup failed or no results
//
// # Examples
//
//	// Enable on client
//	client.TorLookup = true
//	ips, err := client.LookupIP(ctx, "ip4", "example.com")
//
//	// Server handles automatically with DefaultCommandHandlers
//	server := &socksgo.Server{
//	    Handlers: socksgo.DefaultCommandHandlers,
//	}
//
// # See Also
//
//   - server_handler_resolveptr.go: Reverse DNS lookup
//   - client.go#LookupIP: Client-side forward lookup
var DefaultResolveHandler = CommandHandler{
	Socks4:    true,
	Socks5:    true,
	TLSCompat: true,
	Handler: func(
		ctx context.Context,
		server *Server,
		conn net.Conn,
		ver string,
		info protocol.AuthInfo,
		cmd protocol.Cmd,
		addr protocol.Addr) error {
		pool := server.GetPool()
		err := server.CheckRaddr(&addr)
		if err != nil {
			protocol.Reject(ver, conn, protocol.DisallowReply, pool)
			return err
		}
		ips, err := server.GetResolver().
			LookupIP(ctx, addr.IpNetwork(), addr.ToFQDN())
		if err != nil {
			protocol.Reject(ver, conn, protocol.HostUnreachReply, pool)
			return err
		}
		if len(ips) < 1 {
			protocol.Reject(ver, conn, protocol.HostUnreachReply, pool)
			return &net.DNSError{
				Err:        "zero IPs found",
				Name:       addr.ToFQDN(),
				IsNotFound: true,
			}
		}
		ip := ips[0]
		if server.IsPreferIPv4() {
			for _, elem := range ips {
				if ip4 := elem.To4(); ip4 != nil {
					ip = ip4
					break
				}
			}
		}
		err = protocol.Reply(
			ver,
			conn,
			protocol.SuccReply,
			protocol.AddrFromIP(ip, 0, ""),
			pool,
		)
		return err
	},
}
