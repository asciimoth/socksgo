package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo/protocol"
)

// DefaultUDPAssocHandler handles the UDP ASSOCIATE command.
//
// DefaultUDPAssocHandler creates a UDP association that proxies
// packets between the client and target using standard SOCKS5
// UDP encapsulation.
//
// # Protocol Support
//
//   - SOCKS4: No
//   - SOCKS5: Yes
//   - TLS: No
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
//  4. Creates UDP association listener
//
//  5. Sends success reply with association address
//
//  6. Proxies UDP packets with SOCKS5 UDP headers
//
// # UDP Encapsulation
//
// SOCKS5 UDP packets include a header:
//
//		+----+------+------+----------+----------+----------+
//		|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//		+----+------+------+----------+----------+----------+
//		| 2  |  1   |  1   | Variable |    2     | Variable |
//		+----+------+------+----------+----------+----------+
//
//	  - RSV: Reserved (0x0000)
//	  - FRAG: Fragment number (0x00 = no fragmentation)
//	  - ATYP: Address type (IP4=0x01, IP6=0x04, FQDN=0x03)
//	  - DST.ADDR: Destination address
//	  - DST.PORT: Destination port
//	  - DATA: UDP payload
//
// # Association Lifecycle
//
// The UDP association remains active until:
//   - UDPTimeout expires (default: 3 minutes)
//   - Control TCP connection closes
//   - Error occurs during proxying
//
// # Reply
//
// Sends success reply (0x00) with the UDP association address.
//
// # Errors
//
// Returns error and sends appropriate reply status:
//   - DisallowReply (0x02): Address filtered
//   - FailReply (0x01): Listen/dial failed
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
//   - RFC 1928: SOCKS5 Protocol (Section 7)
//   - protocol.ProxySocks5UDPAssoc: UDP proxy implementation
//   - server_handler_tun.go: Gost UDP tunnel (UDP over TCP)
var DefaultUDPAssocHandler = CommandHandler{
	Socks4:    false,
	Socks5:    true,
	TLSCompat: false,
	Handler: func(
		ctx context.Context,
		server *Server,
		ctrl net.Conn,
		ver string,
		info protocol.AuthInfo,
		cmd protocol.Cmd,
		addr protocol.Addr) (err error) {
		addr.NetTyp = "udp"
		pool := server.GetPool()

		var proxy gonnect.PacketConn

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
			protocol.Reject(ver, ctrl, errorToReplyStatus(err), pool)
			return err
		}

		assoc, err := server.ListenForAssoc(ctx, ctrl)
		if err != nil {
			protocol.Reject(ver, ctrl, errorToReplyStatus(err), pool)
			return err
		}

		err = protocol.Reply(
			ver,
			ctrl,
			protocol.SuccReply,
			protocol.AddrFromNetAddr(assoc.LocalAddr()),
			pool,
		)
		if err != nil {
			return err
		}

		return protocol.ProxySocks5UDPAssoc(
			assoc, proxy, ctrl, binded, nil, pool,
			server.GetUDPBufferSize(), server.GetUDPTimeout(),
		)
	},
}
