package socksgo

import (
	"context"
	"net"
	"sync"

	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

// DefaultGostMBindHandler handles the Gost multiplexed BIND command.
//
// DefaultGostMBindHandler creates a TCP listener and uses smux to
// multiplex multiple incoming connections over a single TCP connection
// to the client.
//
// # Protocol Support
//
//   - SOCKS4: Yes (Gost extension)
//   - SOCKS5: Yes (Gost extension)
//   - TLS: Yes
//
// # Behavior
//
//  1. Applies default listen host if address is unspecified
//
//  2. Validates local address against LaddrFilter
//
//  3. Creates TCP listener on requested address
//
//  4. Sends success reply with bound address
//
//  5. Upgrades connection to smux session
//
//  6. Spawns goroutine to accept smux streams (and discard)
//
//  7. Accepts incoming connections on listener
//
//  8. For each incoming connection:
//     - Opens new smux stream
//     - Pipes data between listener connection and stream
//
//  9. Continues until listener or session closes
//
// # Multiplexing
//
// MBIND uses smux (stream multiplexing) to carry multiple independent
// connections over a single TCP connection.
//
// # Reply
//
// Sends success reply (0x00) with the listener address.
//
// # Errors
//
// Returns error and sends appropriate reply status:
//   - DisallowReply (0x02): Address filtered
//   - FailReply (0x01): Listen failed
//
// # Examples
//
//	// Enable on server
//	server := &socksgo.Server{
//	    Handlers: socksgo.DefaultCommandHandlers,
//	    Smux: &smux.Config{
//	        MaxFrameSize:     65535,
//	        MaxReceiveBuffer: 4194304,
//	    },
//	}
//
// # See Also
//
//   - github.com/xtaci/smux: Stream multiplexing library
//   - server_handler_bind.go: Standard BIND handler
//   - protocol.PipeConn: Connection piping implementation
var DefaultGostMBindHandler = CommandHandler{
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
		listener, err := server.GetListener()(ctx, "tcp", addr.ToHostPort())
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

		session, err := smux.Client(conn, server.GetSmux())
		if err != nil {
			_ = conn.Close()
			return err
		}
		defer func() {
			_ = conn.Close()
			_ = session.Close()
		}()

		var wg sync.WaitGroup
		wg.Go(func() {
			for {
				rw, err := session.Accept()
				if err != nil {
					_ = session.Close()
					_ = listener.Close()
					return
				}
				_ = rw.Close()
			}
		})
		for {
			var inc net.Conn
			inc, err = listener.Accept()
			if err != nil {
				break
			}
			stream, err := session.OpenStream()
			if err != nil {
				break
			}
			wg.Go(func() {
				_ = protocol.PipeConn(inc, stream)
			})
		}
		wg.Wait()

		return internal.ClosedNetworkErrToNil(err)
	},
}
