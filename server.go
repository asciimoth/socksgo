package socksgo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/asciimoth/ident"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

type Server struct {
	Pool protocol.BufferPool
	Auth *protocol.AuthHandlers

	Smux *smux.Config

	UDPBufferSize int           // 8192 default
	UDPTimeout    time.Duration // 2m default

	// Should IPv4 addrs be preferred if both IPv4 and IPv6 addr are available
	// when replying to CmdTorResolve
	DoNotPreferIP4 bool

	// Default host that will be used in Bind/Mbind/UDPAssoc/UDPTun requests
	// as local addr instead of "0.0.0.0"/"::"/"" if provided
	DefaultListenHost string

	// false by default
	UseIDENT func(user string, clientAddr net.Addr) bool

	// Local addr filter. For listening commands (bind, mbind, etc)
	// true means allow, false means reject
	// If nil (default) any laddr is allowed
	LaddrFilter func(laddr *protocol.Addr) bool

	// Remote addr filter. For connect/lookup commands (connect, raddr, etc)
	// true means allow, false means reject
	// If nil (default) any raddr is allowed
	RaddrFilter func(raddr *protocol.Addr) bool

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
		protocol.Reject("4", conn, protocol.Rejected, pool)
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

	if s.CheckUseIDENT(user, conn.RemoteAddr()) {
		err = s.checkIDENT(ctx, user, conn, pool)
		if err != nil {
			return err
		}
		info.Info["ident"] = true
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

func (s *Server) checkIDENT(
	ctx context.Context, user string, conn net.Conn, pool protocol.BufferPool,
) error {
	srcAddr := protocol.AddrFromNetAddr(conn.RemoteAddr())
	dstAddr := protocol.AddrFromNetAddr(conn.LocalAddr())
	identAddr := srcAddr.Copy()
	identAddr.Port = 113 // Standard IDENT port (RFC 1413)
	identConn, err := s.GetDialer()(ctx, identAddr.Network(), identAddr.ToHostPort())
	if err != nil {
		protocol.Reject("4", conn, protocol.IdentRequired, pool)
		return errors.Join(
			ErrClientAuthFailed,
			errors.New("IDENT server connection"),
			err,
		)
	}
	iresp, err := ident.QueryWithConn(srcAddr.PortStr(), dstAddr.PortStr(), identConn)
	if err != nil {
		protocol.Reject("4", conn, protocol.IdentRequired, pool)
		return errors.Join(
			ErrClientAuthFailed,
			errors.New("IDENT response"),
			err,
		)
	}
	if iresp.ID != user {
		protocol.Reject("4", conn, protocol.IdentFailed, pool)
		return errors.Join(
			ErrClientAuthFailed,
			errors.New("IDENT user mismatch"),
			fmt.Errorf("IDENT user mismatch '%s' vs '%s'", user, iresp.ID),
		)
	}
	return nil
}
