package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

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

		var proxy net.PacketConn

		if addr.IsUnspecified() {
			// UDP socket should not be binded to any specific raddr
			// aka UDP server
			laddr := addr.WithDefaultHost(server.GetDefaultListenHost())
			proxy, err = server.GetPacketListener()(
				ctx, laddr.Network(), laddr.ToHostPort(),
			)
		} else {
			proxy, err = server.GetPacketDialer()(ctx, addr.Network(), addr.ToHostPort())
		}
		if err != nil {
			// TODO: What ReplyCode should we return here?
			protocol.Reject(ver, ctrl, protocol.FailReply, pool)
			return err

		}

		assoc, err := server.ListenForAssoc(ctx, ctrl)
		if err != nil {
			// TODO: What ReplyCode should we return here?
			protocol.Reject(ver, ctrl, protocol.FailReply, pool)
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
			assoc, proxy, ctrl, nil, pool,
			server.GetUDPBufferSize(), server.GetUDPTimeout(),
		)
	},
}
