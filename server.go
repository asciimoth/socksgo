package socksgo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/ident"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

// Server is a SOCKS proxy server.
//
// Server accepts incoming SOCKS4, SOCKS4a, and SOCKS5 connections,
// performs authentication negotiation, and dispatches commands to
// appropriate handlers.
//
// # Quick Start
//
//	// Create server with default handlers
//	server := &socksgo.Server{
//	    Auth:     authHandlers,
//	    Handlers: socksgo.DefaultCommandHandlers,
//	}
//
//	// Accept connections
//	listener, _ := net.Listen("tcp", "127.0.0.1:1080")
//	for {
//	    conn, _ := listener.Accept()
//	    go server.Accept(ctx, conn, false)
//	}
//
// # Thread Safety
//
// Server is safe for concurrent use. Multiple goroutines can call
// Accept simultaneously, and handlers execute independently.
//
// # See Also
//
//   - Accept: Main entry point for TCP connections
//   - AcceptWS: Entry point for WebSocket connections
//   - server_handlers.go: CommandHandler type and default handlers
type Server struct {
	// Pool is a buffer pool for memory-efficient operations.
	//
	// If nil, buffers are allocated without pooling.
	//
	// Using a shared pool can reduce memory allocations and GC pressure.
	Pool bufpool.Pool

	// Auth contains server-side authentication handlers.
	//
	// Multiple auth methods can be registered; the server selects
	// one during SOCKS5 authentication negotiation.
	//
	// Examples:
	//
	//	server.Auth = (&protocol.AuthHandlers{}).
	//	    Add(&protocol.NoAuthHandler{}).
	//	    Add(&protocol.PassAuthHandler{Verify: verifyFunc})
	Auth *protocol.AuthHandlers

	// Smux configures connection multiplexing for Gost MBIND.
	//
	// Only used when handling CmdGostMuxBind commands.
	//
	// Example:
	//
	//	server.Smux = &smux.Config{
	//	    MaxFrameSize:     65535,
	//	    MaxReceiveBuffer: 4194304,
	//	}
	Smux *smux.Config

	// UDPBufferSize is the buffer size for UDP packet forwarding.
	//
	// Default: 8192 bytes
	//
	// Used by UDP ASSOC and Gost UDPTun handlers.
	UDPBufferSize int

	// UDPTimeout is the timeout for UDP associations.
	//
	// Default: 2 minutes (120 seconds)
	//
	// UDP associations are closed after this duration of inactivity.
	UDPTimeout time.Duration

	// HandshakeTimeout specifies the timeout for SOCKS handshake
	// (authentication and command request).
	//
	// Default: 0 (no timeout)
	//
	// If set, the connection deadline is set to time.Now() + timeout
	// during handshake, then cleared after successful handshake.
	HandshakeTimeout time.Duration

	// DoNotPreferIP4 controls IPv4 preference for Tor resolve replies.
	//
	// When false (default), if both IPv4 and IPv6 addresses are returned
	// from a DNS lookup, IPv4 is preferred in the reply.
	//
	// When true, the first returned address is used regardless of type.
	DoNotPreferIP4 bool

	// DefaultListenHost is the default host for BIND/MBIND/UDPAssoc commands.
	//
	// If set, this host is used instead of "0.0.0.0" or "::" when the
	// client requests an unspecified address.
	//
	// Default: "" (use system default)
	DefaultListenHost string

	// UseIDENT determines whether IDENT lookup is performed for SOCKS4.
	//
	// If non-nil, called with (username, clientAddr) to determine if
	// IDENT verification should be attempted.
	//
	// IDENT (RFC 1413) verifies the username by querying port 113 on
	// the client's IP address.
	//
	// Default: nil (no IDENT verification)
	UseIDENT func(user string, clientAddr net.Addr) bool

	// LaddrFilter filters local addresses for listening commands
	// (BIND, MBIND, UDPAssoc, UDPTun).
	//
	// Return true to allow, false to reject.
	//
	// If nil, all addresses are allowed.
	//
	// Examples:
	//
	//	// Reject unspecified addresses
	//	server.LaddrFilter = func(addr *protocol.Addr) bool {
	//	    return !addr.IsUnspecified()
	//	}
	LaddrFilter func(laddr *protocol.Addr) bool

	// RaddrFilter filters remote addresses for outgoing commands
	// (CONNECT, Tor Resolve, etc.).
	//
	// Return true to allow, false to reject.
	//
	// If nil, all addresses are allowed.
	//
	// Examples:
	//
	//	// Use client Filter for server-side filtering
	//	server.RaddrFilter = func(addr *protocol.Addr) bool {
	//	    return socksgo.BuildFilter("localhost,192.168.0.0/16")(
	//	        "", addr.ToHostPort())
	//	}
	RaddrFilter func(raddr *protocol.Addr) bool

	// PreCmd is a hook called before executing any command.
	//
	// Parameters:
	//   - ctx: Context for the connection
	//   - conn: Client connection
	//   - ver: SOCKS version ("4", "4a", "5")
	//   - info: Authentication information
	//   - cmd: Requested command
	//   - addr: Target address
	//
	// Returns:
	//   - protocol.ReplyStatus: Status to send if rejecting
	//   - error: Error to return (connection closed)
	//
	// If non-nil error or non-Ok status is returned, the request is
	// rejected. For nil error with non-Ok status, Rejected(91) is used.
	//
	// Examples:
	//
	//	server.PreCmd = func(ctx context.Context, conn net.Conn,
	//	    ver string, info protocol.AuthInfo, cmd protocol.Cmd,
	//	    addr protocol.Addr) (protocol.ReplyStatus, error) {
	//	    log.Printf("Command %s to %s", cmd, addr)
	//	    return 0, nil // Allow
	//	}
	PreCmd func(
		ctx context.Context,
		conn net.Conn,
		ver string, // "4" | "5"
		info protocol.AuthInfo,
		cmd protocol.Cmd,
		addr protocol.Addr,
	) (protocol.ReplyStatus, error)

	// Handlers maps commands to their handlers.
	//
	// If nil, DefaultCommandHandlers is used.
	//
	// To customize handlers, copy DefaultCommandHandlers and modify:
	//
	//	handlers := make(map[protocol.Cmd]CommandHandler)
	//	for k, v := range socksgo.DefaultCommandHandlers {
	//	    handlers[k] = v
	//	}
	//	handlers[protocol.CmdConnect] = myCustomHandler
	//	server.Handlers = handlers
	Handlers map[protocol.Cmd]CommandHandler

	// Dialer is used to establish outgoing TCP connections for
	// CONNECT and other commands requiring TCP dialing.
	//
	// Default: net.Dialer.DialContext
	Dialer gonnect.Dial

	// PacketDialer is used to establish outgoing UDP connections for
	// UDP ASSOC and Gost UDPTun commands.
	//
	// Default: net.DialUDP
	PacketDialer gonnect.PacketDial

	// Listener is used to create TCP listeners for BIND and MBIND commands.
	//
	// Default: net.ListenConfig.Listen
	Listener gonnect.Listen

	// PacketListener is used to create UDP listeners for UDP ASSOC
	// and Gost UDPTun commands.
	//
	// Default: net.ListenUDP
	PacketListener gonnect.PacketListen

	// AssocListener creates UDP listeners for UDP ASSOC commands.
	//
	// If nil, a UDP listener is created based on the control connection's
	// local address.
	//
	// This allows custom UDP association handling, such as using a
	// specific port range or interface.
	AssocListener func(ctx context.Context, ctrl net.Conn) (assoc gonnect.PacketConn, err error)

	// Resolver is used for DNS lookups in Tor Resolve commands.
	//
	// Default: net.DefaultResolver
	Resolver gonnect.Resolver

	// DanglingConnections disable closing of used connections after handler
	// returns.
	DanglingConnections bool
}

// AcceptWS accepts a SOCKS connection over WebSocket.
//
// AcceptWS wraps the WebSocket connection and delegates to Accept.
// It handles the WebSocket framing layer for SOCKS over WS/WSS.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - conn: WebSocket connection from gorilla/websocket
//   - isTLS: true if connection is encrypted (WSS)
//
// # Thread Safety
//
// AcceptWS is safe for concurrent use.
//
// # Examples
//
//	// WebSocket server
//	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
//	    conn, _ := websocket.Upgrade(w, r, nil, 1024, 1024)
//	    go server.AcceptWS(r.Context(), conn, r.TLS != nil)
//	})
//
// # See Also
//
//   - Accept: Accept TCP connections
//   - wsConn: WebSocket connection wrapper
func (s *Server) AcceptWS(
	ctx context.Context,
	conn *websocket.Conn,
	isTLS bool,
) error {
	return s.Accept(ctx, &wsConn{
		Conn: conn,
	}, isTLS)
}

// Accept accepts and handles a SOCKS connection.
//
// Accept is the main entry point for handling incoming SOCKS connections.
// It reads the protocol version, routes to the appropriate handler (accept4
// or accept5), and manages the authentication and command dispatch flow.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - conn: TCP connection from client
//   - isTLS: true if connection is encrypted (TLS)
//
// # Behavior
//
// 1. Reads version byte from connection
// 2. Routes to accept4 (SOCKS4/4a) or accept5 (SOCKS5)
// 3. Connection is closed on return (deferred)
//
// # Thread Safety
//
// Accept is safe for concurrent use. Each connection is handled
// independently.
//
// # Examples
//
//	// TCP server
//	listener, _ := net.Listen("tcp", "127.0.0.1:1080")
//	for {
//	    conn, err := listener.Accept()
//	    if err != nil {
//	        continue
//	    }
//	    go server.Accept(ctx, conn, false)
//	}
//
//	// TLS server
//	tlsListener := tls.Listen(listener, tlsConfig)
//	for {
//	    conn, err := tlsListener.Accept()
//	    if err != nil {
//	        continue
//	    }
//	    go server.Accept(ctx, conn, true)
//	}
//
// # Errors
//
// Returns error if:
//   - Version byte cannot be read
//   - Unknown SOCKS version (not 4 or 5)
//   - Authentication fails
//   - Handler execution fails
//
// # See Also
//
//   - AcceptWS: Accept WebSocket connections
func (s *Server) Accept(
	ctx context.Context,
	conn net.Conn,
	isTLS bool,
) (err error) {
	defer func() {
		s.closeConn(conn, err)
	}()

	// Read version
	var ver [1]byte
	_, err = io.ReadFull(conn, ver[:])
	if err != nil {
		return
	}
	if ver[0] == 4 { //nolint
		err = s.accept4(ctx, conn, isTLS)
		return
	}
	if ver[0] == 5 { //nolint
		err = s.accept5(ctx, conn, isTLS)
		return
	}
	err = UnknownSocksVersionError{
		Version: strconv.Itoa(int(ver[0])), //nolint
	}
	return
}

// accept4 handles SOCKS4 and SOCKS4a connections.
//
// accept4 processes the SOCKS4/4a protocol flow:
// 1. Read request (CMD, DSTPORT, DSTIP, USERID)
// 2. Optional IDENT verification (if UseIDENT is set)
// 3. Check PreCmd hook
// 4. Validate command is allowed
// 5. Execute command handler
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - conn: Client connection
//   - isTLS: true if connection is encrypted
//
// # IDENT Verification
//
// If UseIDENT is set and returns true, connects to port 113 on the
// client's IP address to verify the USERID. If IDENT fails or returns
// a different user, the connection is rejected with IdentRequired or
// IdentFailed status.
//
// # Errors
//
// Returns error if:
//   - Request cannot be read
//   - User is rejected by auth check
//   - Command is not allowed
//   - PreCmd hook rejects
//   - Handler execution fails
//
// # See Also
//
//   - Accept: Main entry point
//   - UseIDENT: IDENT verification configuration
//   - protocol.ReadSocks4TCPRequest: Request parsing
func (s *Server) accept4(ctx context.Context, conn net.Conn, isTLS bool) error {
	pool := s.GetPool()

	timeout := s.GetHandshakeTimeout()
	if timeout != 0 {
		err := conn.SetDeadline(time.Now().Add(timeout))
		if err != nil {
			return err
		}
	}

	cmd, addr, user, err := protocol.ReadSocks4TCPRequest(conn, pool)
	if err != nil {
		return errors.Join(
			ErrClientAuthFailed,
			err,
		)
	}

	if !s.GetAuth().CheckSocks4User(user) {
		// Reject
		protocol.Reject("4", conn, protocol.Rejected, pool)
		return errors.Join(
			ErrClientAuthFailed,
			errors.New("provided socks4 user rejected"),
		)
	}

	handler := s.GetHandler(cmd)
	if handler == nil || !handler.Allowed("4", isTLS) {
		protocol.Reject("4", conn, protocol.CmdNotSuppReply, pool)
		return UnsupportedCommandError{
			SocksVersion: "4",
			Cmd:          cmd,
		}
	}

	info := protocol.AuthInfo{
		Code: protocol.PassAuthCode,
		Info: map[string]any{
			"user": user,
			"pass": "",
		},
	}

	if s.CheckUseIDENT(user, conn.RemoteAddr()) {
		err = s.checkIDENT(ctx, user, conn, pool)
		if err != nil {
			return err
		}
		info.Info["ident"] = true
	}

	stat, err := s.runPreCmd(ctx, conn, "4", info, cmd, addr)
	if err != nil || !stat.Ok() {
		if stat.Ok() {
			stat = protocol.Rejected
		}
		protocol.Reject("4", conn, stat, pool)
		return err
	}

	if timeout != 0 {
		err = conn.SetDeadline(time.Time{})
		if err != nil {
			return err
		}
	}

	return handler.Run(ctx, s, conn, "4", info, cmd, addr)
}

// accept5 handles SOCKS5 connections.
//
// accept5 processes the SOCKS5 protocol flow:
// 1. Authentication negotiation (HandleAuth)
// 2. Read request (VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT)
// 3. Check PreCmd hook
// 4. Validate command is allowed
// 5. Execute command handler
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - conn: Client connection
//   - isTLS: true if connection is encrypted
//
// # Authentication
//
// Authentication is negotiated via protocol.HandleAuth which:
//   - Reads supported methods from client
//   - Selects a compatible method from server's Auth
//   - Executes the authentication handshake
//
// Supported methods depend on Auth configuration:
//   - No Auth (0x00)
//   - Username/Password (0x02)
//   - GSS-API (0x01) - stub implementation
//
// # Errors
//
// Returns error if:
//   - Authentication fails
//   - Request cannot be read
//   - Command is not allowed
//   - PreCmd hook rejects
//   - Handler execution fails
//
// # See Also
//
//   - Accept: Main entry point
//   - protocol.HandleAuth: Authentication negotiation
//   - protocol.ReadSocks5TCPRequest: Request parsing
func (s *Server) accept5(ctx context.Context, conn net.Conn, isTLS bool) error {
	pool := s.GetPool()

	timeout := s.GetHandshakeTimeout()
	if timeout != 0 {
		err := conn.SetDeadline(time.Now().Add(timeout))
		if err != nil {
			return err
		}
	}

	conn, info, err := protocol.HandleAuth(conn, pool, s.GetAuth())
	if err != nil {
		return errors.Join(
			ErrClientAuthFailed,
			err,
		)
	}

	cmd, addr, err := protocol.ReadSocks5TCPRequest(conn, pool)
	if err != nil {
		return err
	}

	handler := s.GetHandler(cmd)
	if handler == nil || !handler.Allowed("5", isTLS) {
		protocol.Reject("5", conn, protocol.CmdNotSuppReply, pool)
		return UnsupportedCommandError{
			SocksVersion: "5",
			Cmd:          cmd,
		}
	}

	stat, err := s.runPreCmd(ctx, conn, "5", info, cmd, addr)
	if err != nil || !stat.Ok() {
		protocol.Reject("5", conn, stat, pool)
		return err
	}

	if timeout == 0 {
		return handler.Run(ctx, s, conn, "5", info, cmd, addr)
	}

	err = conn.SetDeadline(time.Time{})
	if err != nil {
		return err
	}
	return handler.Run(ctx, s, conn, "5", info, cmd, addr)
}

// checkIDENT performs IDENT (RFC 1413) verification for SOCKS4.
//
// checkIDENT connects to port 113 on the client's IP address to verify
// the username provided in the SOCKS4 request.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - user: Username from SOCKS4 request
//   - conn: Client connection (for remote address)
//   - pool: Buffer pool for temporary allocations
//
// # Behavior
//
// 1. Connects to IDENT server (port 113) on client's IP
// 2. Queries with (local-port, remote-port)
// 3. Compares returned username with request username
//
// # Errors
//
// Returns error if:
//   - Cannot connect to IDENT server
//   - IDENT query fails
//   - Username mismatch
//
// On error, sends IdentRequired or IdentFailed reply and closes connection.
//
// # See Also
//
//   - UseIDENT: Configuration for enabling IDENT
//   - github.com/asciimoth/ident: IDENT client library
//   - RFC 1413: Identification Protocol
func (s *Server) checkIDENT(
	ctx context.Context, user string, conn net.Conn, pool bufpool.Pool,
) error {
	srcAddr := protocol.AddrFromNetAddr(conn.RemoteAddr())
	dstAddr := protocol.AddrFromNetAddr(conn.LocalAddr())
	identAddr := srcAddr.Copy()
	identAddr.Port = 113 // Standard IDENT port (RFC 1413)
	identConn, err := s.GetDialer()(
		ctx,
		identAddr.Network(),
		identAddr.ToHostPort(),
	)
	if err != nil {
		protocol.Reject("4", conn, protocol.IdentRequired, pool)
		return errors.Join(
			ErrClientAuthFailed,
			errors.New("IDENT server connection"),
			err,
		)
	}
	iresp, err := ident.QueryWithConn(
		srcAddr.PortStr(),
		dstAddr.PortStr(),
		identConn,
	)
	if err != nil {
		protocol.Reject("4", conn, protocol.IdentRequired, pool)
		return errors.Join(
			ErrClientAuthFailed,
			errors.New("IDENT response"),
			err,
		)
	}
	if iresp.ID == user {
		return nil
	}
	protocol.Reject("4", conn, protocol.IdentFailed, pool)
	return errors.Join(
		ErrClientAuthFailed,
		errors.New("IDENT user mismatch"),
		fmt.Errorf("IDENT user mismatch '%s' vs '%s'", user, iresp.ID),
	)
}

// runPreCmd executes the PreCmd hook if configured.
//
// runPreCmd calls the PreCmd function before executing any command.
// This allows for logging, rate limiting, or custom validation.
//
// # Parameters
//
//   - ctx: Context for the connection
//   - conn: Client connection
//   - ver: SOCKS version ("4", "4a", "5")
//   - info: Authentication information
//   - cmd: Requested command
//   - addr: Target address
//
// # Returns
//
//   - protocol.ReplyStatus: Status to send if rejecting (0 = no reply)
//   - error: Error to return (connection closed)
//
// # Behavior
//
// If PreCmd is nil, returns (0, nil) to allow the command.
//
// # See Also
//
//   - PreCmd: Hook configuration
func (s *Server) runPreCmd(
	ctx context.Context,
	conn net.Conn,
	ver string,
	info protocol.AuthInfo,
	cmd protocol.Cmd,
	addr protocol.Addr,
) (protocol.ReplyStatus, error) {
	if s == nil || s.PreCmd == nil {
		return 0, nil
	}
	return s.PreCmd(ctx, conn, ver, info, cmd, addr)
}
