package socksgo

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

func (s *Server) getHandler(cmd protocol.Cmd) *CommandHandler {
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

// true by default (for s == nil)
func (s *Server) IsPreferIPv4() bool {
	if s == nil {
		return true
	}
	return !s.DoNotPreferIP4
}

func (s *Server) CheckLaddr(laddr *protocol.Addr) error {
	if s != nil && s.LaddrFilter != nil && !s.LaddrFilter(laddr) {
		return AddrDisallowedError{
			Addr:       laddr,
			FilterName: "server laddr",
		}
	}
	return nil
}

func (s *Server) CheckRaddr(raddr *protocol.Addr) error {
	if s != nil && s.RaddrFilter != nil && !s.RaddrFilter(raddr) {
		return AddrDisallowedError{
			Addr:       raddr,
			FilterName: "server raddr",
		}
	}
	return nil
}

func (s *Server) CheckBothAddr(laddr, raddr *protocol.Addr) error {
	if err := s.CheckLaddr(laddr); err != nil {
		return err
	}
	if err := s.CheckRaddr(raddr); err != nil {
		return err
	}
	return nil
}

func (s *Server) CheckUseIDENT(user string, clientAddr net.Addr) bool {
	if s == nil || s.UseIDENT == nil {
		return false
	}
	return s.UseIDENT(user, clientAddr)
}

func (s *Server) GetUDPBufferSize() int {
	if s.UDPBufferSize == 0 {
		return 8192
	}
	return s.UDPBufferSize
}

func (s *Server) GetUDPTimeout() time.Duration {
	if s.UDPTimeout == 0 {
		return time.Second * 180
	}
	return s.UDPTimeout
}

func (s *Server) GetDefaultListenHost() string {
	if s == nil {
		return ""
	}
	return s.DefaultListenHost
}

func (s *Server) GetAuth() *protocol.AuthHandlers {
	if s == nil {
		return nil
	}
	return s.Auth
}

func (s *Server) GetPool() protocol.BufferPool {
	if s == nil {
		return nil
	}
	return s.Pool
}

func (s *Server) GetSmux() *smux.Config {
	if s == nil {
		return nil
	}
	return s.Smux
}

// Return s.Listener or default net listener.
func (s *Server) GetListener() Listener {
	if s.Listener == nil {
		return (&net.ListenConfig{}).Listen
	}
	return s.Listener
}

// Return s.PacketListener or default net UDP listener.
func (s *Server) GetPacketListener() PacketListener {
	if s.PacketListener == nil {
		return func(ctx context.Context, network, laddr string) (PacketConn, error) {
			addr := protocol.AddrFromHostPort(laddr, network)
			udpAddr := addr.ToUDP()
			return net.ListenUDP(network, udpAddr)
		}
	}
	return s.PacketListener
}

// Return s.Dialer or default net dialer.
func (s *Server) GetDialer() Dialer {
	if s.Dialer == nil {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	return s.Dialer
}

// Return s.PacketDialer or default net udp dialer.
func (s *Server) GetPacketDialer() PacketDialer {
	if s.Dialer == nil {
		return func(ctx context.Context, network, raddr string) (PacketConn, error) {
			udpAddr := protocol.AddrFromHostPort(raddr, network).ToUDP()
			return net.DialUDP(network, nil, udpAddr)
		}
	}
	return s.PacketDialer
}

// Return s.Resolver4 or net.DefaultResolver
func (s *Server) GetResolver() Resolver {
	if s.Resolver == nil {
		return net.DefaultResolver
	}
	return s.Resolver
}

func (s *Server) ListenForAssoc(ctx context.Context, ctrl net.Conn) (assoc PacketConn, err error) {
	if s != nil && s.AssocListener != nil {
		return s.AssocListener(ctx, ctrl)
	}
	la := ctrl.LocalAddr()
	if la == nil {
		err = fmt.Errorf("failed to guess default local addr for incoming UDP assoc connections")
		return
	}
	host := la.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return s.GetPacketListener()(ctx, "udp", net.JoinHostPort(host, "0"))
}
