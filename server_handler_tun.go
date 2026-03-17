package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

// DefaultGostUDPTUNHandler handles the Gost UDP Tunnel command.
//
// DefaultGostUDPTUNHandler creates a UDP tunnel over TCP,
// encapsulating UDP packets in a custom TCP framing format.
//
// # Protocol Support
//
//   - SOCKS4: No (Gost extension)
//   - SOCKS5: Yes (Gost extension)
//   - TLS: No (UDP over TLS is problematic)
//
// # Behavior
//
//  1. Sets address network type to "udp"
//
//  2. If address is unspecified (0.0.0.0:0):
//     - Creates UDP listener (server mode)
//     - Validates against LaddrFilter
//
//  3. If address is specified:
//     - Creates UDP connection to target (client mode)
//     - Validates against RaddrFilter
//
//  4. Sends success reply with proxy's UDP address
//
//  5. Proxies UDP packets with Gost framing over TCP
//
// # Reply
//
// Sends success reply (0x00) with the proxy's UDP address.
//
// # Errors
//
// Returns error and sends appropriate reply status:
//   - DisallowReply (0x02): Address filtered
//   - FailReply (0x01): Listen/dial failed
//
// # Examples
//
//	// Enable on client
//	client.GostUDPTun = true
//
//	// Server handles automatically with DefaultCommandHandlers
//	server := &socksgo.Server{
//	    Handlers: socksgo.DefaultCommandHandlers,
//	}
//
// # See Also
//
//   - server_handler_assoc.go: Standard UDP ASSOC handler
//   - protocol.ProxySocks5UDPTun: UDP tunnel proxy implementation
var DefaultGostUDPTUNHandler = CommandHandler{
	Socks4:    false,
	Socks5:    true,
	TLSCompat: false,
	Handler: func(
		ctx context.Context,
		server *Server,
		tun net.Conn,
		ver string,
		info protocol.AuthInfo,
		cmd protocol.Cmd,
		addr protocol.Addr) (err error) {
		addr.NetTyp = "udp"
		pool := server.GetPool()

		var proxy PacketConn

		binded := false
		if addr.IsUnspecified() {
			// UDP socket should not be binded to any specific raddr
			// aka UDP server
			laddr := addr.WithDefaultHost(server.GetDefaultListenHost())
			err = server.CheckLaddr(&addr)
			if err == nil {
				proxy, err = server.GetPacketListener()(
					ctx, laddr.Network(), laddr.ToHostPort(),
				)
			}
		} else {
			err = server.CheckRaddr(&addr)
			if err == nil {
				binded = true
				proxy, err = server.GetPacketDialer()(
					ctx,
					addr.Network(),
					addr.ToHostPort(),
				)
			}
		}
		if err != nil {
			protocol.Reject(ver, tun, errorToReplyStatus(err), pool)
			return err

		}

		err = protocol.Reply(
			ver,
			tun,
			protocol.SuccReply,
			protocol.AddrFromNetAddr(proxy.LocalAddr()),
			pool,
		)
		if err != nil {
			return err
		}

		return protocol.ProxySocks5UDPTun(
			tun, proxy, binded, nil, pool, server.GetUDPBufferSize(),
		)
	},
}
