package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

// DefaultResolvePtrHandler handles the Tor reverse DNS lookup command.
//
// DefaultResolvePtrHandler performs DNS reverse lookup (PTR records)
// through the server's configured resolver and returns the resolved
// hostname to the client.
//
// # Protocol Support
//
//   - SOCKS4: No
//   - SOCKS4a: No
//   - SOCKS5: Yes (with Tor extension)
//   - TLS: Yes
//
// # Behavior
//
//  1. Validates remote address (IP) against RaddrFilter
//  2. Performs reverse DNS lookup using server's Resolver
//  3. Sends success reply with resolved hostname
//
// # Reply
//
// Sends success reply (0x00) with the resolved hostname.
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
//	names, err := client.LookupAddr(ctx, "8.8.8.8")
//
//	// Server handles automatically with DefaultCommandHandlers
//	server := &socksgo.Server{
//	    Handlers: socksgo.DefaultCommandHandlers,
//	}
//
// # See Also
//
//   - server_handler_resolve.go: Forward DNS lookup
//   - client.go#LookupAddr: Client-side reverse lookup
var DefaultResolvePtrHandler = CommandHandler{
	Socks4:    false,
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
		names, err := server.GetResolver().LookupAddr(ctx, addr.ToIP().String())
		if err != nil {
			protocol.Reject(ver, conn, protocol.HostUnreachReply, pool)
			return err
		}
		if len(names) < 1 {
			protocol.Reject(ver, conn, protocol.HostUnreachReply, pool)
			return &net.DNSError{
				Err:        "zero addrs found",
				Name:       addr.ToFQDN(),
				IsNotFound: true,
			}
		}
		err = protocol.Reply(
			ver,
			conn,
			protocol.SuccReply,
			protocol.AddrFromFQDNNoDot(names[0], 0, ""),
			pool,
		)
		return err
	},
}
