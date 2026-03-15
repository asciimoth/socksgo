package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

// DefaultBindHandler handles the BIND command.
//
// DefaultBindHandler creates a TCP listener on the proxy server
// that forwards incoming connections to the client.
//
// # Protocol Support
//
//   - SOCKS4: Yes
//   - SOCKS4a: Yes
//   - SOCKS5: Yes
//   - TLS: Yes
//
// # Behavior
//
//  1. Applies default listen host if address is unspecified
//  2. Validates local address against LaddrFilter
//  3. Creates TCP listener on requested address
//  4. Sends first reply with bound address (listener.Addr())
//  5. Waits for single incoming connection
//  6. Sends second reply with remote address (incoming client)
//  7. Pipes data bidirectionally
//
// # Two-Reply Protocol
//
// BIND uses a two-reply protocol:
//
//  1. First reply: Contains the address where the client should
//     direct the peer to connect (listener address)
//  2. Second reply: Contains the address of the incoming
//     connection (after Accept returns)
//
// # Use Cases
//
// BIND is used for protocols that require reverse connections:
//   - FTP passive mode
//   - Remote debugging
//   - Any protocol requiring server-to-client connections
//
// # Reply
//
// Sends success reply (0x00) with:
//   - First reply: Listener address
//   - Second reply: Incoming connection's remote address
//
// # Errors
//
// Returns error and sends appropriate reply status:
//   - DisallowReply (0x02): Address filtered
//   - FailReply (0x01): Listen failed
//
// # Examples
//
//	// Default handler is used automatically
//	server := &socksgo.Server{
//	    Handlers: socksgo.DefaultCommandHandlers,
//	}
//
// # See Also
//
//   - RFC 1928: SOCKS5 Protocol (Section 4)
//   - protocol.PipeConn: Connection piping implementation
//   - server_handler_mbind.go: Gost multiplexed BIND
var DefaultBindHandler = CommandHandler{
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
		addr = addr.WithDefaultHost(server.GetDefaultListenHost())
		err := server.CheckLaddr(&addr)
		if err != nil {
			protocol.Reject(ver, conn, protocol.DisallowReply, pool)
			return err
		}
		tcp := "tcp"
		if ver == "4" || ver == "4a" {
			tcp = "tcp4"
		}
		listener, err := server.GetListener()(ctx, tcp, addr.ToHostPort())
		if err != nil {
			protocol.Reject(ver, conn, errorToReplyStatus(err), pool)
			return err
		}
		defer func() { _ = listener.Close() }()
		// Send first reply with laddr
		err = protocol.Reply(
			ver,
			conn,
			protocol.SuccReply,
			protocol.AddrFromNetAddr(listener.Addr()),
			pool,
		)
		if err != nil {
			return err
		}
		proxy, err := listener.Accept()
		if err != nil {
			return err
		}
		// Send second reply with raddr
		err = protocol.Reply(
			ver,
			conn,
			protocol.SuccReply,
			protocol.AddrFromNetAddr(proxy.RemoteAddr()),
			pool,
		)
		if err != nil {
			return err
		}
		return protocol.PipeConn(conn, proxy)
	},
}
