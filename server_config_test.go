package socksgo_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

// dummyConn implements net.Conn and returns nil for LocalAddr to test the error path.
type dummyConn struct{}

func (d *dummyConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (d *dummyConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (d *dummyConn) Close() error                       { return nil }
func (d *dummyConn) LocalAddr() net.Addr                { return nil }
func (d *dummyConn) RemoteAddr() net.Addr               { return nil }
func (d *dummyConn) SetDeadline(t time.Time) error      { return nil }
func (d *dummyConn) SetReadDeadline(t time.Time) error  { return nil }
func (d *dummyConn) SetWriteDeadline(t time.Time) error { return nil }

func TestGetHandler_DefaultAndCustom(t *testing.T) {
	// default handler should exist for CmdConnect
	s := &socksgo.Server{}
	h := s.GetHandler(protocol.CmdConnect)
	if h == nil {
		t.Fatalf("expected handler for CmdConnect, got nil")
	}

	// unknown command -> nil
	if s.GetHandler(protocol.Cmd(0xFF)) != nil {
		t.Fatalf("expected nil for unknown command")
	}

	// custom handlers override default
	customCalled := false
	s2 := &socksgo.Server{
		Handlers: map[protocol.Cmd]socksgo.CommandHandler{
			protocol.CmdConnect: {
				Handler: func(
					ctx context.Context,
					server *socksgo.Server,
					conn net.Conn,
					ver string,
					info protocol.AuthInfo,
					cmd protocol.Cmd,
					addr protocol.Addr,
				) error {
					customCalled = true
					return nil
				},
			},
		},
	}
	h2 := s2.GetHandler(protocol.CmdConnect)
	if h2 == nil {
		t.Fatalf("expected custom handler, got nil")
	}
	// call it to ensure it's our handler
	if err := h2.Handler(
		context.Background(),
		s2,
		nil,
		"5",
		protocol.AuthInfo{},
		protocol.CmdConnect,
		protocol.Addr{},
	); err != nil {
		t.Fatalf("custom handler returned error: %v", err)
	}
	if !customCalled {
		t.Fatalf("custom handler didn't run")
	}
}

func TestIsPreferIPv4(t *testing.T) {
	var nilS *socksgo.Server
	// nil receiver: true by default
	if !nilS.IsPreferIPv4() {
		t.Fatalf("nil server should prefer IPv4 (true)")
	}

	s := &socksgo.Server{DoNotPreferIP4: true}
	if s.IsPreferIPv4() {
		t.Fatalf("server with DoNotPreferIP4=true should not prefer IPv4")
	}

	s2 := &socksgo.Server{DoNotPreferIP4: false}
	if !s2.IsPreferIPv4() {
		t.Fatalf("server with DoNotPreferIP4=false should prefer IPv4")
	}
}

func TestCheckLaddrRaddrBothAndUseIDENT(t *testing.T) {
	laddr := protocol.AddrFromHostPort("127.0.0.1:1", "tcp")
	raddr := protocol.AddrFromHostPort("127.0.0.1:2", "tcp")

	// Test LaddrFilter denies
	s1 := &socksgo.Server{
		LaddrFilter: func(a *protocol.Addr) bool { return false },
	}
	if err := s1.CheckLaddr(&laddr); err == nil {
		t.Fatalf("expected CheckLaddr to return error when LaddrFilter denies")
	} else {
		var ade socksgo.AddrDisallowedError
		if !errors.As(err, &ade) {
			t.Fatalf("expected AddrDisallowedError, got: %T %v", err, err)
		}
	}

	// Test RaddrFilter denies
	s2 := &socksgo.Server{
		RaddrFilter: func(a *protocol.Addr) bool { return false },
	}
	if err := s2.CheckRaddr(&raddr); err == nil {
		t.Fatalf("expected CheckRaddr to return error when RaddrFilter denies")
	} else {
		var ade socksgo.AddrDisallowedError
		if !errors.As(err, &ade) {
			t.Fatalf("expected AddrDisallowedError, got: %T %v", err, err)
		}
	}

	// Test CheckBothAddr returns first encountered (Laddr)
	s3 := &socksgo.Server{
		LaddrFilter: func(a *protocol.Addr) bool { return false },
		RaddrFilter: func(a *protocol.Addr) bool { return false },
	}
	if err := s3.CheckBothAddr(&laddr, &raddr); err == nil {
		t.Fatalf("expected CheckBothAddr to return error")
	} else {
		var ade socksgo.AddrDisallowedError
		if !errors.As(err, &ade) {
			t.Fatalf("expected AddrDisallowedError, got: %T %v", err, err)
		}
		// FilterName for Laddr should be "server laddr"
		if ade.FilterName != "server laddr" {
			t.Fatalf(
				"expected FilterName 'server laddr', got %q",
				ade.FilterName,
			)
		}
	}

	// Test CheckUseIDENT nil and custom
	var nilS *socksgo.Server
	if nilS.CheckUseIDENT("u", nil) {
		t.Fatalf("nil server should return false for CheckUseIDENT")
	}
	s4 := &socksgo.Server{
		UseIDENT: func(user string, clientAddr net.Addr) bool { return user == "yes" },
	}
	if !s4.CheckUseIDENT("yes", nil) {
		t.Fatalf("UseIDENT should return true for 'yes'")
	}
	if s4.CheckUseIDENT("no", nil) {
		t.Fatalf("UseIDENT should return false for 'no'")
	}
}

func TestGetters_DefaultsAndSetValues(t *testing.T) {
	var nilS *socksgo.Server

	// UDP buffer default on zero / nil
	if got := nilS.GetUDPBufferSize(); got != 8192 {
		t.Fatalf("expected default UDPBufferSize 8192, got %d", got)
	}
	s := &socksgo.Server{UDPBufferSize: 1234}
	if s.GetUDPBufferSize() != 1234 {
		t.Fatalf("expected UDPBufferSize 1234, got %d", s.GetUDPBufferSize())
	}

	// UDP timeout default
	if got := nilS.GetUDPTimeout(); got != time.Second*180 {
		t.Fatalf("expected default UDPTimeout 180s, got %v", got)
	}
	s.UDPTimeout = time.Second * 5
	if s.GetUDPTimeout() != time.Second*5 {
		t.Fatalf("expected UDPTimeout 5s, got %v", s.GetUDPTimeout())
	}

	// Handshake timeout
	if nilS.GetHandshakeTimeout() != 0 {
		t.Fatalf("nil server GetHandshakeTimeout should be 0")
	}
	s.HandshakeTimeout = time.Second * 11
	if s.GetHandshakeTimeout() != time.Second*11 {
		t.Fatalf(
			"expected handshake timeout 11s, got %v",
			s.GetHandshakeTimeout(),
		)
	}

	// Default listen host
	if nilS.GetDefaultListenHost() != "" {
		t.Fatalf("nil server default listen host should be empty")
	}
	s.DefaultListenHost = "127.0.0.1"
	if s.GetDefaultListenHost() != "127.0.0.1" {
		t.Fatalf(
			"expected default listen host '127.0.0.1', got %q",
			s.GetDefaultListenHost(),
		)
	}

	// Auth / Pool / Smux nil behavior and set behavior
	if nilS.GetAuth() != nil || nilS.GetPool() != nil || nilS.GetSmux() != nil {
		t.Fatalf("nil server GetAuth/GetPool/GetSmux should be nil")
	}
	a := &protocol.AuthHandlers{}
	s.Auth = a
	if s.GetAuth() != a {
		t.Fatalf("GetAuth mismatch")
	}
	p := bufpool.NewTestDebugPool(t)
	s.Pool = p
	if s.GetPool() != p {
		t.Fatalf("GetPool mismatch")
	}
	cfg := &smux.Config{}
	s.Smux = cfg
	if s.GetSmux() != cfg {
		t.Fatalf("GetSmux mismatch")
	}
}

// Test GetListener default and custom
func TestGetListener(t *testing.T) {
	s := &socksgo.Server{}
	lnFn := s.GetListener()
	ln, err := lnFn(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("default GetListener failed: %v", err)
	}
	if ln == nil {
		t.Fatalf("expected a listener")
	}
	addr := ln.Addr().String()
	ln.Close() //nolint

	// ensure address had a port
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("unexpected addr format: %v", err)
	}
	if p, err := strconv.Atoi(portStr); err != nil || p == 0 {
		t.Fatalf("expected non-zero port, got %q (err=%v)", portStr, err)
	}

	// custom listener function
	s2 := &socksgo.Server{
		Listener: func(ctx context.Context, network, laddr string) (net.Listener, error) {
			return nil, errors.New("custom-listen-error")
		},
	}
	lnFn2 := s2.GetListener()
	_, err = lnFn2(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil || err.Error() != "custom-listen-error" {
		t.Fatalf("expected custom-listen-error, got %v", err)
	}
}

func TestGetPacketListener_Default(t *testing.T) {
	s := &socksgo.Server{}
	pl := s.GetPacketListener()
	pc, err := pl(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("GetPacketListener default failed: %v", err)
	}
	if pc.LocalAddr() == nil {
		t.Fatalf("expected PacketConn LocalAddr not nil")
	}
	pc.Close() //nolint
}

func TestGetDialerAndPacketDialer_DefaultAndCustom(t *testing.T) {
	// Test default dialer by creating a tcp server to connect to
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint
	if err != nil {
		t.Fatalf("tcp listen failed: %v", err)
	}
	defer ln.Close() //nolint
	addr := ln.Addr().String()

	// accept a single conn in background
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		c, _ := ln.Accept()
		if c != nil {
			c.Close() //nolint
		}
	}()

	s := &socksgo.Server{}
	dialFn := s.GetDialer()
	ctx := context.Background()
	conn, err := dialFn(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("default dialer failed to connect: %v", err)
	}
	conn.Close() //nolint
	<-acceptDone

	// custom dialer is used when provided
	markerErr := errors.New("marker")
	s2 := &socksgo.Server{
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, markerErr
		},
	}
	_, err = s2.GetDialer()(ctx, "tcp", "127.0.0.1:1")
	if !errors.Is(err, markerErr) {
		t.Fatalf("expected markerErr from custom dialer, got %v", err)
	}

	// PacketDialer default: start UDP server and dial to it
	udpLn, err := net.ListenUDP(
		"udp",
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0},
	)
	if err != nil {
		t.Fatalf("udp listen failed: %v", err)
	}
	defer udpLn.Close() //nolint
	udpAddr := udpLn.LocalAddr().String()

	pdFn := (&socksgo.Server{}).GetPacketDialer() // both Dialer and PacketDialer nil -> default
	pconn, err := pdFn(ctx, "udp", udpAddr)
	if err != nil {
		t.Fatalf("default packet dialer failed: %v", err)
	}
	pconn.Close() //nolint

	// custom PacketDialer is returned only if s.Dialer != nil (see implementation)
	sCustom := &socksgo.Server{
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, nil //nolint
		},
		PacketDialer: func(ctx context.Context, network, raddr string) (socksgo.PacketConn, error) {
			return nil, markerErr
		},
	}
	_, err = sCustom.GetPacketDialer()(ctx, "udp", udpAddr)
	if !errors.Is(err, markerErr) {
		t.Fatalf("expected markerErr from custom PacketDialer, got %v", err)
	}
}

func TestGetResolver(t *testing.T) {
	var nilS *socksgo.Server
	if nilS.GetResolver() != net.DefaultResolver {
		t.Fatalf("nil server GetResolver should return net.DefaultResolver")
	}

	custom := &net.Resolver{}
	s := &socksgo.Server{Resolver: custom}
	if s.GetResolver() != custom {
		t.Fatalf("GetResolver should return custom resolver")
	}
}

func TestListenForAssoc_Behaviors(t *testing.T) {
	// 1) If AssocListener is provided it should be called
	sErr := errors.New("assoc marker")
	s1 := &socksgo.Server{
		AssocListener: func(ctx context.Context, ctrl net.Conn) (socksgo.PacketConn, error) {
			return nil, sErr
		},
	}
	// create a real tcp connection for ctrl
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint
	if err != nil {
		t.Fatalf("tcp listen failed: %v", err)
	}
	defer ln.Close() //nolint

	// dial to get a connection pair
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, _ := ln.Accept()
		if c != nil {
			// call ListenForAssoc using server-side accepted connection
			_, err := s1.ListenForAssoc(context.Background(), c)
			if !errors.Is(err, sErr) {
				t.Errorf("expected assoc marker error, got %v", err)
			}
			c.Close() //nolint
		}
	}()
	// dial client side to trigger accept
	clientConn, err := net.Dial("tcp", ln.Addr().String()) //nolint
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	clientConn.Close() //nolint
	<-done

	// 2) default path: AssocListener nil -> create PacketListener using ctrl.LocalAddr()
	s2 := &socksgo.Server{}
	ln2, err := net.Listen("tcp", "127.0.0.1:0") //nolint
	if err != nil {
		t.Fatalf("tcp listen failed: %v", err)
	}
	defer ln2.Close() //nolint

	// accept in background and run ListenForAssoc on server-side conn
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		srvConn, _ := ln2.Accept()
		pc, err := s2.ListenForAssoc(context.Background(), srvConn)
		if err != nil {
			t.Errorf("ListenForAssoc default failed: %v", err)
			return
		}
		if pc.LocalAddr() == nil {
			t.Errorf("expected PacketConn LocalAddr not nil")
		}
		pc.Close()      //nolint
		srvConn.Close() //nolint
	}()

	cliConn, err := net.Dial("tcp", ln2.Addr().String()) //nolint
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	cliConn.Close() //nolint
	<-done2

	// 3) If ctrl.LocalAddr() is nil -> error path
	s3 := &socksgo.Server{}
	_, err = s3.ListenForAssoc(context.Background(), &dummyConn{})
	if err == nil {
		t.Fatalf("expected error when ctrl.LocalAddr is nil")
	}
}

func TestCheckAddr_NilServer(t *testing.T) {
	var s *socksgo.Server

	addr := protocol.AddrFromHostPort("127.0.0.1:1234", "tcp")

	if err := s.CheckLaddr(&addr); err != nil {
		t.Fatalf("CheckLaddr with nil server returned error: %v", err)
	}

	if err := s.CheckRaddr(&addr); err != nil {
		t.Fatalf("CheckRaddr with nil server returned error: %v", err)
	}
}

func TestCheckBothAddr_LaddrOK_RaddrFails(t *testing.T) {
	laddr := protocol.AddrFromHostPort("127.0.0.1:1", "tcp")
	raddr := protocol.AddrFromHostPort("127.0.0.1:2", "tcp")

	s := &socksgo.Server{
		LaddrFilter: func(a *protocol.Addr) bool { return true },
		RaddrFilter: func(a *protocol.Addr) bool { return false },
	}

	err := s.CheckBothAddr(&laddr, &raddr)
	if err == nil {
		t.Fatalf("expected error from CheckBothAddr")
	}

	var ade socksgo.AddrDisallowedError
	if !errors.As(err, &ade) {
		t.Fatalf("expected AddrDisallowedError, got %T: %v", err, err)
	}

	if ade.FilterName != "server raddr" {
		t.Fatalf("expected FilterName 'server raddr', got %q", ade.FilterName)
	}
}

func TestCheckBothAddr_LaddrOK_RaddrOk(t *testing.T) {
	laddr := protocol.AddrFromHostPort("127.0.0.1:1", "tcp")
	raddr := protocol.AddrFromHostPort("127.0.0.1:2", "tcp")

	s := &socksgo.Server{
		LaddrFilter: func(a *protocol.Addr) bool { return true },
		RaddrFilter: func(a *protocol.Addr) bool { return true },
	}

	err := s.CheckBothAddr(&laddr, &raddr)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetPacketListener_Custom(t *testing.T) {
	markerErr := errors.New("custom packet listener")

	s := &socksgo.Server{
		PacketListener: func(ctx context.Context, network, laddr string) (socksgo.PacketConn, error) {
			return nil, markerErr
		},
	}

	pl := s.GetPacketListener()
	_, err := pl(context.Background(), "udp", "127.0.0.1:0")
	if !errors.Is(err, markerErr) {
		t.Fatalf("expected markerErr, got %v", err)
	}
}
