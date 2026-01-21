package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
)

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
		listener, err := net.Listen("tcp", addr.ToHostPort())
		if err != nil {
			// TODO: What ReplyCode should we return here?
			protocol.Reject(ver, conn, protocol.FailReply, pool)
			return err
		}
		defer listener.Close()
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
		conn2, err := listener.Accept()
		if err != nil {
			return err
		}
		// Send second reply with raddr
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
