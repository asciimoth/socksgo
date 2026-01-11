package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
)

var DefaultCommandHandlers = map[protocol.Cmd]CommandHandler{
	protocol.CmdConnect: {
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
	},
	protocol.CmdTorResolve: {
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
			ips, err := server.GetResolver().LookupIP(ctx, addr.IpNetwork(), addr.ToFQDN())
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
	},
	protocol.CmdTorResolvePtr: {
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
			names, err := server.GetResolver().LookupAddr(ctx, addr.ToIP().String())
			if err != nil {
				protocol.Reject(ver, conn, protocol.HostUnreachReply, pool)
				return err
			}
			if len(names) < 1 {
				protocol.Reject(ver, conn, protocol.HostUnreachReply, pool)
				return &net.DNSError{
					Err:        "zero IPs found",
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
	},
	protocol.CmdBind: {
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
	},
}

type CommandHandler struct {
	Socks4    bool
	Socks5    bool
	TLSCompat bool

	// If rejecting - raise err with reason
	// Run addr.WithDefaultHosr before checking laddr filter
	Handler func(
		ctx context.Context,
		server *Server,
		conn net.Conn,
		ver string, // "4" | "5"
		info protocol.AuthInfo,
		cmd protocol.Cmd,
		addr protocol.Addr,
	) error
}

func (h *CommandHandler) Run(
	ctx context.Context,
	server *Server,
	conn net.Conn,
	ver string, // "4" | "5"
	info protocol.AuthInfo,
	cmd protocol.Cmd,
	addr protocol.Addr,
) error {
	if h == nil || h.Handler == nil {
		return NilHandlerError{cmd}
	}
	return h.Handler(ctx, server, conn, ver, info, cmd, addr)
}

func (h *CommandHandler) Allowed(ver string, isTLS bool) bool {
	if h == nil {
		return false
	}
	if isTLS && !h.TLSCompat {
		return false
	}
	if ver == "4" && h.Socks4 {
		return true
	}
	if ver == "5" && h.Socks5 {
		return true
	}
	return false
}
