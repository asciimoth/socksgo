package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
)

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
			// TODO: Select reply code depending on err type
			protocol.Reject(ver, conn, protocol.HostUnreachReply, pool)
			return err
		}
		defer conn2.Close()
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
		return internal.PipeConn(conn, conn2)
	},
}
