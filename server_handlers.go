package socksgo

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

var DefaultCommandHandlers = map[protocol.Cmd]CommandHandler{
	protocol.CmdConnect:  DefaultConnectHandler,
	protocol.CmdBind:     DefaultBindHandler,
	protocol.CmdUDPAssoc: DefaultUDPAssocHandler,

	protocol.CmdTorResolve:    DefaultResolveHandler,
	protocol.CmdTorResolvePtr: DefaultResolvePtrHandler,

	protocol.CmdGostUDPTun:  DefaultGostUDPTUNHandler,
	protocol.CmdGostMuxBind: DefaultGostMBindHandler,
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
