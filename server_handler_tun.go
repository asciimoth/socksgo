package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

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
			proxy, err = server.GetPacketListener()(
				ctx, laddr.Network(), laddr.ToHostPort(),
			)
		} else {
			binded = true
			proxy, err = server.GetPacketDialer()(
				ctx,
				addr.Network(),
				addr.ToHostPort(),
			)
		}
		if err != nil {
			// TODO: What ReplyCode should we return here?
			protocol.Reject(ver, tun, protocol.FailReply, pool)
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
