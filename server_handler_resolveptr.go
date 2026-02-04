package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

var DefaultResolvePtrHandler = CommandHandler{
	Socks4:    false,
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
		names, err := server.GetResolver().LookupAddr(ctx, addr.ToIP().String())
		if err != nil {
			protocol.Reject(ver, conn, protocol.HostUnreachReply, pool)
			return err
		}
		if len(names) < 1 {
			protocol.Reject(ver, conn, protocol.HostUnreachReply, pool)
			return &net.DNSError{
				Err:        "zero addrs found",
				Name:       addr.ToFQDN(),
				IsNotFound: true,
			}
		}
		err = protocol.Reply(
			ver,
			conn,
			protocol.SuccReply,
			protocol.AddrFromFQDNNoDot(names[0], 0, ""),
			pool,
		)
		return err
	},
}
