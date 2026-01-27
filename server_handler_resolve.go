package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

var DefaultResolveHandler = CommandHandler{
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
		ips, err := server.GetResolver().
			LookupIP(ctx, addr.IpNetwork(), addr.ToFQDN())
		if err != nil {
			protocol.Reject(ver, conn, protocol.HostUnreachReply, pool)
			return err
		}
		if len(ips) < 1 {
			protocol.Reject(ver, conn, protocol.HostUnreachReply, pool)
			return &net.DNSError{
				Err:        "zero IPs found",
				Name:       addr.ToFQDN(),
				IsNotFound: true,
			}
		}
		ip := ips[0]
		if server.IsPreferIPv4() {
			for _, elem := range ips {
				if ip4 := elem.To4(); ip4 != nil {
					ip = ip4
					break
				}
			}
		}
		err = protocol.Reply(
			ver,
			conn,
			protocol.SuccReply,
			protocol.AddrFromIP(ip, 0, ""),
			pool,
		)
		return err
	},
}
