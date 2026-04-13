package socksgo

// Server configuration helpers.
//
// This file contains helper methods for Server configuration access
// and validation. These methods provide safe defaults and handle nil
// receiver cases.

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

// GetHandler returns the handler for a command.
//
// GetHandler looks up the command handler from the Handlers map.
// If Handlers is nil or the command is not found, returns the
// corresponding handler from DefaultCommandHandlers.
//
// # Parameters
//
//   - cmd: Command code to look up
//
// # Returns
//
// Pointer to CommandHandler, or nil if not found.
//
// # See Also
//
//   - Handlers: Server command handler map
//   - DefaultCommandHandlers: Built-in handlers
func (s *Server) GetHandler(cmd protocol.Cmd) *CommandHandler {
	handlers := DefaultCommandHandlers
	if s != nil && s.Handlers != nil {
		handlers = s.Handlers
	}
	handler, ok := handlers[cmd]
	if !ok {
		return nil
	}
	return &handler
}

// IsPreferIPv4 reports whether IPv4 addresses are preferred for Tor resolve.
//
// Returns true by default (including when s is nil).
//
// # Returns
//
//   - true: Prefer IPv4 when both IPv4 and IPv6 are available
//   - false: Use first returned address regardless of type
//
// # See Also
//
//   - DoNotPreferIP4: Server configuration field
func (s *Server) IsPreferIPv4() bool {
	if s == nil {
		return true
	}
	return !s.DoNotPreferIP4
}

// CheckLaddr validates a local address against LaddrFilter.
//
// CheckLaddr is used for listening commands (BIND, MBIND, UDPAssoc, UDPTun)
// to ensure the requested bind address is allowed.
//
// # Parameters
//
//   - laddr: Local address to validate
//
// # Returns
//
//   - nil: Address is allowed (or filter is nil)
//   - AddrDisallowedError: Address was rejected by filter
//
// # See Also
//
//   - LaddrFilter: Server configuration field
//   - CheckRaddr: Validate remote address
func (s *Server) CheckLaddr(laddr *protocol.Addr) error {
	if s != nil && s.LaddrFilter != nil && !s.LaddrFilter(laddr) {
		return AddrDisallowedError{
			Addr:       laddr,
			FilterName: "server laddr",
		}
	}
	return nil
}

// CheckRaddr validates a remote address against RaddrFilter.
//
// CheckRaddr is used for outgoing commands (CONNECT, Tor Resolve)
// to ensure the target address is allowed.
//
// # Parameters
//
//   - raddr: Remote address to validate
//
// # Returns
//
//   - nil: Address is allowed (or filter is nil)
//   - AddrDisallowedError: Address was rejected by filter
//
// # See Also
//
//   - RaddrFilter: Server configuration field
//   - CheckLaddr: Validate local address
func (s *Server) CheckRaddr(raddr *protocol.Addr) error {
	if s != nil && s.RaddrFilter != nil && !s.RaddrFilter(raddr) {
		return AddrDisallowedError{
			Addr:       raddr,
			FilterName: "server raddr",
		}
	}
	return nil
}

// CheckBothAddr validates both local and remote addresses.
//
// CheckBothAddr calls CheckLaddr and CheckRaddr to validate
// both addresses. Returns the first error encountered.
//
// # Parameters
//
//   - laddr: Local address to validate
//   - raddr: Remote address to validate
//
// # Returns
//
//   - nil: Both addresses are allowed
//   - AddrDisallowedError: One address was rejected
//
// # See Also
//
//   - CheckLaddr: Validate local address
//   - CheckRaddr: Validate remote address
func (s *Server) CheckBothAddr(laddr, raddr *protocol.Addr) error {
	if err := s.CheckLaddr(laddr); err != nil {
		return err
	}
	if err := s.CheckRaddr(raddr); err != nil {
		return err
	}
	return nil
}

// CheckUseIDENT reports whether IDENT verification should be performed.
//
// CheckUseIDENT calls the UseIDENT function if set, otherwise returns false.
//
// # Parameters
//
//   - user: Username from SOCKS4 request
//   - clientAddr: Client's network address
//
// # Returns
//
//   - true: Perform IDENT verification
//   - false: Skip IDENT verification
//
// # See Also
//
//   - UseIDENT: Server configuration field
//   - checkIDENT: IDENT verification implementation
func (s *Server) CheckUseIDENT(user string, clientAddr net.Addr) bool {
	if s == nil || s.UseIDENT == nil {
		return false
	}
	return s.UseIDENT(user, clientAddr)
}

// GetUDPBufferSize returns the configured UDP buffer size.
//
// # Returns
//
// UDPBufferSize if set, otherwise 8192 bytes.
func (s *Server) GetUDPBufferSize() int {
	if s == nil || s.UDPBufferSize == 0 {
		return 8192
	}
	return s.UDPBufferSize
}

// GetUDPTimeout returns the configured UDP timeout.
//
// # Returns
//
// UDPTimeout if set, otherwise 180 seconds (3 minutes).
func (s *Server) GetUDPTimeout() time.Duration {
	if s == nil || s.UDPTimeout == 0 {
		return time.Second * 180
	}
	return s.UDPTimeout
}

// GetHandshakeTimeout returns the configured handshake timeout.
//
// # Returns
//
// HandshakeTimeout if set, otherwise 0 (no timeout).
func (s *Server) GetHandshakeTimeout() time.Duration {
	if s == nil {
		return 0
	}
	return s.HandshakeTimeout
}

// GetDefaultListenHost returns the default host for listening commands.
//
// # Returns
//
// DefaultListenHost if set, otherwise "" (system default).
func (s *Server) GetDefaultListenHost() string {
	if s == nil {
		return ""
	}
	return s.DefaultListenHost
}

// GetAuth returns the server's authentication handlers.
//
// # Returns
//
// Auth if set, otherwise nil (no authentication required).
func (s *Server) GetAuth() *protocol.AuthHandlers {
	if s == nil {
		return nil
	}
	return s.Auth
}

// GetPool returns the server's buffer pool.
//
// # Returns
//
// Pool if set, otherwise nil (no pooling).
func (s *Server) GetPool() bufpool.Pool {
	if s == nil {
		return nil
	}
	return s.Pool
}

// GetSmux returns the server's smux configuration.
//
// # Returns
//
// Smux if set, otherwise nil (default smux settings).
func (s *Server) GetSmux() *smux.Config {
	if s == nil {
		return nil
	}
	return s.Smux
}

// GetListener returns the TCP listener for server operations.
//
// # Returns
//
// Listener if set, otherwise net.ListenConfig.Listen.
//
// # See Also
//
//   - Listener: Server configuration field
func (s *Server) GetListener() gonnect.Listen {
	if s == nil || s.Listener == nil {
		return (&net.ListenConfig{}).Listen
	}
	return s.Listener
}

// GetPacketListener returns the UDP packet listener for server operations.
//
// # Returns
//
// PacketListener if set, otherwise net.ListenUDP.
//
// # See Also
//
//   - PacketListener: Server configuration field
func (s *Server) GetPacketListener() gonnect.PacketListen {
	if s == nil || s.PacketListener == nil {
		return func(ctx context.Context, network, laddr string) (gonnect.PacketConn, error) {
			addr := protocol.AddrFromHostPort(laddr, network)
			udpAddr := addr.ToUDP()
			return net.ListenUDP(network, udpAddr)
		}
	}
	return s.PacketListener
}

// GetDialer returns the TCP dialer for server operations.
//
// # Returns
//
// Dialer if set, otherwise net.Dialer.DialContext.
//
// # See Also
//
//   - Dialer: Server configuration field
func (s *Server) GetDialer() gonnect.Dial {
	if s == nil || s.Dialer == nil {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	return s.Dialer
}

// GetPacketDialer returns the UDP packet dialer for server operations.
//
// # Returns
//
// PacketDialer if set, otherwise net.DialUDP.
//
// # See Also
//
//   - PacketDialer: Server configuration field
func (s *Server) GetPacketDialer() gonnect.PacketDial {
	if s == nil || s.Dialer == nil {
		return func(ctx context.Context, network, raddr string) (gonnect.PacketConn, error) {
			udpAddr := protocol.AddrFromHostPort(raddr, network).ToUDP()
			return net.DialUDP(network, nil, udpAddr)
		}
	}
	return s.PacketDialer
}

// GetResolver returns the DNS resolver for server operations.
//
// # Returns
//
// Resolver if set, otherwise net.DefaultResolver.
//
// # See Also
//
//   - Resolver: Server configuration field
func (s *Server) GetResolver() gonnect.Resolver {
	if s == nil || s.Resolver == nil {
		return net.DefaultResolver
	}
	return s.Resolver
}

// ListenForAssoc creates a UDP listener for UDP ASSOC commands.
//
// ListenForAssoc calls AssocListener if set, otherwise creates a UDP
// listener based on the control connection's local address.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - ctrl: Control TCP connection from client
//
// # Returns
//
// PacketConn for UDP association or error.
//
// # Behavior
//
// If AssocListener is nil:
//
//  1. Gets local address from control connection
//  2. Extracts host from address
//  3. Creates UDP listener on host:0 (any port)
//
// # See Also
//
//   - AssocListener: Server configuration field
//   - DefaultUDPAssocHandler: Handler that calls this function
func (s *Server) ListenForAssoc(
	ctx context.Context,
	ctrl net.Conn,
) (assoc gonnect.PacketConn, err error) {
	if s != nil && s.AssocListener != nil {
		return s.AssocListener(ctx, ctrl)
	}
	la := ctrl.LocalAddr()
	if la == nil {
		err = fmt.Errorf(
			"failed to guess default local addr for incoming UDP assoc connections",
		)
		return
	}
	host := la.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return s.GetPacketListener()(ctx, "udp", net.JoinHostPort(host, "0"))
}

func (s *Server) closeConn(c net.Conn, err error) {
	if err != nil || !s.DanglingConnections {
		_ = c.Close()
	}
}
