package socksgo

import (
	"context"
	"net"
	"sync"

	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

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
			// TODO: What ReplyCode should we return here?
			protocol.Reject(ver, conn, protocol.FailReply, pool)
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
