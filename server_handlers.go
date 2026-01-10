package socksgo

import (
	"bytes"
	"context"
	"io"
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
			conn2, err := server.GetDialer()(ctx, addr.Network(), addr.String())
			if err != nil {
				// TODO: Select reply depending on err type
				server.reject5(conn, protocol.HostUnreachReply)
				return err
			}
			reply, err := protocol.BuildSocks5TCPReply(
				protocol.SuccReply,
				protocol.AddrFromNetAddr(conn2.RemoteAddr()),
				server.GetPool(),
			)
			if err != nil {
				return err
			}
			_, err = io.Copy(conn, bytes.NewReader(reply))
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
	Handler   func(
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
