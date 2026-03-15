package socksgo

// Default command handlers and CommandHandler type.
//
// This file defines the CommandHandler type and the default
// implementation for all supported SOCKS commands.

import (
	"context"
	"net"

	"github.com/asciimoth/socksgo/protocol"
)

// DefaultCommandHandlers is the default map of command handlers.
//
// DefaultCommandHandlers provides standard implementations for all
// supported SOCKS commands:
//
//   - CmdConnect: Forward TCP connections
//   - CmdBind: Listen for incoming connections (BIND)
//   - CmdUDPAssoc: UDP association (standard SOCKS5)
//   - CmdTorResolve: Forward DNS lookup (Tor extension)
//   - CmdTorResolvePtr: Reverse DNS lookup (Tor extension)
//   - CmdGostUDPTun: UDP tunnel over TCP (Gost extension)
//   - CmdGostMuxBind: Multiplexed BIND (Gost extension)
//
// # Usage
//
// Use as-is for standard SOCKS server, or copy and modify for
// custom behavior:
//
//	handlers := make(map[protocol.Cmd]CommandHandler)
//	for k, v := range socksgo.DefaultCommandHandlers {
//	    handlers[k] = v
//	}
//	handlers[protocol.CmdConnect] = myCustomHandler
//	server.Handlers = handlers
//
// # See Also
//
//   - server_handler_connect.go: CONNECT handler implementation
//   - server_handler_bind.go: BIND handler implementation
//   - server_handler_assoc.go: UDP ASSOC handler implementation
//   - server_handler_resolve.go: Tor resolve handler implementation
//   - server_handler_mbind.go: Gost MBIND handler implementation
//   - server_handler_tun.go: Gost UDP tunnel handler implementation
var DefaultCommandHandlers = map[protocol.Cmd]CommandHandler{
	protocol.CmdConnect:  DefaultConnectHandler,
	protocol.CmdBind:     DefaultBindHandler,
	protocol.CmdUDPAssoc: DefaultUDPAssocHandler,

	protocol.CmdTorResolve:    DefaultResolveHandler,
	protocol.CmdTorResolvePtr: DefaultResolvePtrHandler,

	protocol.CmdGostUDPTun:  DefaultGostUDPTUNHandler,
	protocol.CmdGostMuxBind: DefaultGostMBindHandler,
}

// CommandHandler defines a handler for a SOCKS command.
//
// CommandHandler encapsulates the implementation of a SOCKS command
// along with metadata about which protocol versions and transport
// modes it supports.
//
// # Fields
//
//   - Socks4: true if handler supports SOCKS4/4a
//   - Socks5: true if handler supports SOCKS5
//   - TLSCompat: true if handler works over TLS connections
//   - Handler: The actual handler function
//
// # Handler Function
//
// The Handler function is called after:
// 1. Authentication succeeds
// 2. Command is validated
// 3. PreCmd hook passes
// 4. Address filters pass
//
// The handler is responsible for:
//   - call address filters suitable for its purpose
//   - Sending the appropriate reply to the client
//   - Executing the command (dialing, listening, etc.)
//   - Proxying data between client and target
//   - Returning errors (which close the connection)
//
// # Examples
//
//	// Custom CONNECT handler with logging
//	customHandler := CommandHandler{
//	    Socks4:    true,
//	    Socks5:    true,
//	    TLSCompat: true,
//	    Handler: func(ctx context.Context, server *Server,
//	        conn net.Conn, ver string, info protocol.AuthInfo,
//	        cmd protocol.Cmd, addr protocol.Addr) error {
//	        log.Printf("CONNECT to %s", addr)
//	        // Call default handler
//	        return socksgo.DefaultConnectHandler.Handler(
//	            ctx, server, conn, ver, info, cmd, addr)
//	    },
//	}
//
// # See Also
//
//   - DefaultCommandHandlers: Built-in handlers
//   - server_handler_*.go: Individual handler implementations
type CommandHandler struct {
	Socks4    bool
	Socks5    bool
	TLSCompat bool

	// Handler is the function that executes the command.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - server: Server instance (for accessing config, dialers, etc.)
	//   - conn: Client connection
	//   - ver: SOCKS version ("4", "4a", "5")
	//   - info: Authentication information from handshake
	//   - cmd: Command code being executed
	//   - addr: Target address from client request
	//
	// Returns:
	//   - error: Non-nil error closes the connection
	//
	// The handler is responsible for sending the appropriate reply
	// to the client before proxying data. Use protocol.Reply()
	// for standard replies or protocol.Reject() for errors.
	//
	// # See Also
	//
	//   - protocol.Reply: Send success reply
	//   - protocol.Reject: Send error reply
	//   - protocol.PipeConn: Proxy data between connections
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

// Run executes the command handler.
//
// Run calls the Handler function if it is set, otherwise returns
// a NilHandlerError.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - server: Server instance
//   - conn: Client connection
//   - ver: SOCKS version ("4", "4a", "5")
//   - info: Authentication information
//   - cmd: Command code
//   - addr: Target address
//
// # Returns
//
// Error from handler, or NilHandlerError if handler is nil.
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

// Allowed reports whether the handler supports the given version and TLS mode.
//
// Allowed checks if the handler can handle requests for the specified
// SOCKS version and TLS configuration.
//
// # Parameters
//
//   - ver: SOCKS version ("4", "4a", "5", "5h")
//   - isTLS: true if connection is encrypted
//
// # Returns
//
//   - true: Handler supports this version/TLS combination
//   - false: Handler does not support this combination
//
// # Behavior
//
// Returns false if:
//   - Handler is nil
//   - isTLS is true but TLSCompat is false
//   - ver is "4" or "4a" but Socks4 is false
//   - ver is "5" or "5h" but Socks5 is false
func (h *CommandHandler) Allowed(ver string, isTLS bool) bool {
	if h == nil {
		return false
	}
	if isTLS && !h.TLSCompat {
		return false
	}
	if (ver == "4" || ver == "4a") && h.Socks4 {
		return true
	}
	if (ver == "5" || ver == "5h") && h.Socks5 {
		return true
	}
	return false
}
