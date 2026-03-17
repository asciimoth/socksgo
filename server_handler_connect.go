package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

// DefaultConnectHandler handles the CONNECT command.
//
// DefaultConnectHandler establishes a TCP connection to the target
// address and pipes data between the client and target.
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
//  1. Validates remote address against RaddrFilter
//  2. Dials target address using server's Dialer
//  3. Sends success reply with bound address
//  4. Pipes data bidirectionally until EOF or error
//
// # Reply
//
// Sends success reply (0x00) with the target's address.
//
// # Errors
//
// Returns error and sends appropriate reply status:
//   - DisallowReply (0x02): Address filtered
//   - HostUnreachReply (0x04): Dial failed
//   - FailReply (0x01): Other errors
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
var DefaultConnectHandler = CommandHandler{
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
		conn2, err := server.GetDialer()(ctx, addr.Network(), addr.String())
		if err != nil {
			protocol.Reject(ver, conn, errorToReplyStatus(err), pool)
			return err
		}
		defer func() { _ = conn2.Close() }()
		err = protocol.Reply(
			ver,
			conn,
			protocol.SuccReply,
			protocol.AddrFromNetAddr(conn2.RemoteAddr()),
			pool,
		)
		if err != nil {
			return err
		}
		return protocol.PipeConn(conn, conn2)
	},
}
