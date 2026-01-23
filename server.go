package socksgo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
)

type Server struct {
	Pool protocol.BufferPool
	Auth *protocol.AuthHandlers

	UDPBufferSize int // 8192 default

	// Should IPv4 addrs be preferred if both IPv4 and IPv6 addr are available
	// when replying to CmdTorResolve
	DoNotPreferIP4 bool

	// Default host that will be used in Bind/Mbind/UDPAssoc/UDPTun requests
	// as local addr instead of "0.0.0.0"/"::"/"" if provided
	DefaultListenHost string

	// Local addr filter. For listening commands (bind, mbind, etc)
	// true means allow, false means reject
	// If nil (default) any laddr is allowed
	LaddrFilter func(laddr *protocol.Addr) bool

	// Remote addr filter. For connect/lookup commands (connect, raddr, etc)
	// true means allow, false means reject
	// If nil (default) any raddr is allowed
	RaddrFilter func(raddr *protocol.Addr) bool

	// TODO: Add option to use IDENT for socks4 instead of Auth

	// If non nil error or non Ok status will be reutrned, request
	// will be rejected.
	// For non nil error but Ok status, Rejected(91) will be used.
	// Status will be automaticlaly translated to relevant socks version.
	PreCmd func(
		ctx context.Context,
		conn net.Conn,
		ver string, // "4" | "5"
		info protocol.AuthInfo,
		cmd protocol.Cmd,
		addr protocol.Addr,
	) (error, protocol.ReplyStatus)

	// If nil, DefaultCommandHandlers will be used
	Handlers map[protocol.Cmd]CommandHandler

	Dialer         Dialer
	PacketDialer   PacketDialer
	Listener       Listener
	PacketListener PacketListener
	AssocListener  func(ctx context.Context, ctrl net.Conn) (assoc PacketConn, err error)
	Resolver       Resolver
}

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

func (s *Server) GetUDPBufferSize() int {
	if s.UDPBufferSize == 0 {
		return 8192
	}
	return s.UDPBufferSize
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
	// if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
	// 	oip, err := internal.GetOutboundIP()
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	host = oip.String()
	// }
	return s.GetPacketListener()(ctx, "udp", net.JoinHostPort(host, "0"))
}

func (s *Server) runPreCmd(
	ctx context.Context,
	conn net.Conn,
	ver string,
	info protocol.AuthInfo,
	cmd protocol.Cmd,
	addr protocol.Addr,
) (error, protocol.ReplyStatus) {
	if s == nil || s.PreCmd == nil {
		return nil, 0
	}
	return s.PreCmd(ctx, conn, ver, info, cmd, addr)
}

// Thread-safe
// TODO: AcceptWS
func (s *Server) Accept(ctx context.Context, conn net.Conn, isTLS bool) error {
	defer conn.Close()

	// Read version
	var ver [1]byte
	_, err := io.ReadFull(conn, ver[:])
	if err != nil {
		return err
	}
	if ver[0] == 4 {
		return s.accept4(ctx, conn, isTLS)
	}
	if ver[0] == 5 {
		return s.accept5(ctx, conn, isTLS)
	}
	return UnknownSocksVersionError{
		Version: strconv.Itoa(int(ver[0])),
	}
}

func (s *Server) accept4(ctx context.Context, conn net.Conn, isTLS bool) error {
	pool := s.GetPool()
	cmd, addr, user, err := protocol.ReadSocks4TCPRequest(conn, pool)
	if err != nil {
		return errors.Join(
			ErrClientAuthFailed,
			err,
		)
	}

	if !s.GetAuth().CheckSocks4User(user) {
		// Reject
		reply := protocol.BuildSocks4TCPReply(
			protocol.Rejected.To4(),
			protocol.Addr{},
			pool,
		)
		defer internal.PutBuffer(pool, reply)
		io.Copy(conn, bytes.NewReader(reply))
		return errors.Join(
			ErrClientAuthFailed,
			errors.New("provided socks4 user rejected"),
		)
	}

	handler := s.getHandler(cmd)
	if handler == nil || !handler.Allowed("4", isTLS) {
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

	err, stat := s.runPreCmd(ctx, conn, "4", info, cmd, addr)
	if err != nil || !stat.Ok() {
		if stat.Ok() {
			stat = protocol.Rejected
		}
		protocol.Reject("4", conn, stat, pool)
		return err
	}

	return handler.Run(ctx, s, conn, "4", info, cmd, addr)
}

func (s *Server) accept5(ctx context.Context, conn net.Conn, isTLS bool) error {
	pool := s.GetPool()
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

	handler := s.getHandler(cmd)
	if handler == nil || !handler.Allowed("5", isTLS) {
		protocol.Reject("5", conn, protocol.CmdNotSuppReply, pool)
		return UnsupportedCommandError{
			SocksVersion: "5",
			Cmd:          cmd,
		}
	}

	err, stat := s.runPreCmd(ctx, conn, "5", info, cmd, addr)
	if err != nil || !stat.Ok() {
		protocol.Reject("5", conn, stat, pool)
		return err
	}
	return handler.Run(ctx, s, conn, "5", info, cmd, addr)
}
