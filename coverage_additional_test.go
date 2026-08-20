package socksgo //nolint:testpackage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo/protocol"
)

type coverageResolver struct{}

func (coverageResolver) LookupIP(
	context.Context,
	string,
	string,
) ([]net.IP, error) {
	return []net.IP{net.IPv4(192, 0, 2, 1)}, nil
}

func (coverageResolver) LookupAddr(context.Context, string) ([]string, error) {
	return []string{"ptr.example."}, nil
}

func (coverageResolver) LookupIPAddr(
	context.Context,
	string,
) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.IPv4(192, 0, 2, 2)}}, nil
}

func (coverageResolver) LookupNetIP(
	context.Context,
	string,
	string,
) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.3")}, nil
}

func (coverageResolver) LookupHost(context.Context, string) ([]string, error) {
	return []string{"192.0.2.4"}, nil
}

func (coverageResolver) LookupCNAME(context.Context, string) (string, error) {
	return "cname.example.", nil
}

func (coverageResolver) LookupPort(
	context.Context,
	string,
	string,
) (int, error) {
	return 12345, nil
}

func (coverageResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return []*net.NS{{Host: "ns.example."}}, nil
}

func (coverageResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	return []*net.MX{{Host: "mx.example.", Pref: 10}}, nil
}

func (coverageResolver) LookupSRV(
	context.Context,
	string,
	string,
	string,
) (string, []*net.SRV, error) {
	return "target.example.", []*net.SRV{{Target: "srv.example."}}, nil
}

func (coverageResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{"txt"}, nil
}

type invalidIPResolver struct {
	coverageResolver
}

func (invalidIPResolver) LookupIP(
	context.Context,
	string,
	string,
) ([]net.IP, error) {
	return []net.IP{{1, 2, 3}, net.IPv4(192, 0, 2, 5)}, nil
}

func TestClientConstructorsAndEnvFallbacks(t *testing.T) {
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	t.Setenv("SOCKS5_PROXY", "")
	t.Setenv("socks5_proxy", "")

	noProxy, err := ClientFromENVSafe("socks5")
	if err != nil {
		t.Fatalf("ClientFromENVSafe empty env: %v", err)
	}
	if !noProxy.IsNoProxy() || !noProxy.IsNative() {
		t.Fatalf("empty env did not return a native client")
	}

	t.Setenv("ALL_PROXY", "socks5://user:pass@127.0.0.1:1080?pass")
	fromEnv, err := ClientFromENV("socks5")
	if err != nil {
		t.Fatalf("ClientFromENV: %v", err)
	}
	if fromEnv.ProxyAddr != "127.0.0.1:1080" || fromEnv.Auth == nil {
		t.Fatalf("ClientFromENV did not parse proxy and auth")
	}

	if _, err := ClientFromURLSafe("://bad-url"); err == nil {
		t.Fatal("ClientFromURLSafe accepted an invalid URL")
	}
	if _, err := ClientFromURL("://bad-url"); err == nil {
		t.Fatal("ClientFromURL accepted an invalid URL")
	}
	if got := ClientFromURLObjSafe(nil); got == nil || !got.IsNoProxy() {
		t.Fatal("ClientFromURLObjSafe(nil) did not return an empty client")
	}
	if got := ClientFromURLObj(nil); got == nil || !got.IsNoProxy() {
		t.Fatal("ClientFromURLObj(nil) did not return an empty client")
	}
}

func TestClientDNSWrappersDirectAndProxied(t *testing.T) {
	ctx := context.Background()
	direct := &Client{Resolver: coverageResolver{}}

	cname, err := direct.LookupCNAME(ctx, "example.com")
	if err != nil || cname != "cname.example." {
		t.Fatalf("LookupCNAME direct = %q, %v", cname, err)
	}
	port, err := direct.LookupPort(ctx, "tcp", "service")
	if err != nil || port != 12345 {
		t.Fatalf("LookupPort direct = %d, %v", port, err)
	}
	if ns, err := direct.LookupNS(
		ctx,
		"example.com",
	); err != nil ||
		len(ns) != 1 {
		t.Fatalf("LookupNS direct length = %d, %v", len(ns), err)
	}
	if mx, err := direct.LookupMX(
		ctx,
		"example.com",
	); err != nil ||
		len(mx) != 1 {
		t.Fatalf("LookupMX direct length = %d, %v", len(mx), err)
	}
	target, srv, err := direct.LookupSRV(ctx, "svc", "tcp", "example.com")
	if err != nil || target != "target.example." || len(srv) != 1 {
		t.Fatalf("LookupSRV direct = %q, %d, %v", target, len(srv), err)
	}
	if txt, err := direct.LookupTXT(
		ctx,
		"example.com",
	); err != nil ||
		len(txt) != 1 {
		t.Fatalf("LookupTXT direct length = %d, %v", len(txt), err)
	}

	torDirect := &Client{
		TorLookup: true,
		Filter:    gonnect.TrueFilter,
		Resolver:  coverageResolver{},
	}
	if addrs, err := torDirect.LookupIPAddr(ctx, "example.com"); err != nil ||
		len(addrs) != 1 {
		t.Fatalf("LookupIPAddr direct length = %d, %v", len(addrs), err)
	}
	if hosts, err := torDirect.LookupHost(ctx, "example.com"); err != nil ||
		len(hosts) != 1 {
		t.Fatalf("LookupHost direct length = %d, %v", len(hosts), err)
	}

	torDirect.Resolver = invalidIPResolver{}
	netIPs, err := torDirect.LookupNetIP(ctx, "ip", "example.com")
	if err != nil {
		t.Fatalf("LookupNetIP direct: %v", err)
	}
	if len(netIPs) != 1 ||
		netIPs[0] != netip.MustParseAddr("::ffff:192.0.2.5") {
		t.Fatalf("LookupNetIP direct = %v", netIPs)
	}

	disabled := &Client{}
	if _, err := disabled.LookupIPAddr(ctx, "example.com"); err == nil {
		t.Fatal("LookupIPAddr unexpectedly succeeded with Tor lookup disabled")
	}
	if _, err := disabled.LookupNetIP(ctx, "ip", "example.com"); err == nil {
		t.Fatal("LookupNetIP unexpectedly succeeded with Tor lookup disabled")
	}
	if _, err := disabled.LookupHost(ctx, "example.com"); err == nil {
		t.Fatal("LookupHost unexpectedly succeeded with Tor lookup disabled")
	}

	proxied := &Client{ProxyAddr: "127.0.0.1:1080"}
	for name, fn := range map[string]func() error{
		"LookupCNAME": func() error {
			_, err := proxied.LookupCNAME(ctx, "example.com")
			return err
		},
		"LookupNS": func() error {
			_, err := proxied.LookupNS(ctx, "example.com")
			return err
		},
		"LookupMX": func() error {
			_, err := proxied.LookupMX(ctx, "example.com")
			return err
		},
		"LookupSRV": func() error {
			_, _, err := proxied.LookupSRV(ctx, "svc", "tcp", "example.com")
			return err
		},
		"LookupTXT": func() error {
			_, err := proxied.LookupTXT(ctx, "example.com")
			return err
		},
	} {
		if err := fn(); err == nil {
			t.Fatalf("%s proxied unexpectedly succeeded", name)
		}
	}

	if port, err := proxied.LookupPort(
		ctx,
		"tcp",
		"http",
	); err != nil ||
		port != 80 {
		t.Fatalf("LookupPort proxied offline = %d, %v", port, err)
	}
}

func TestClientNetworkAndListenWrappers(t *testing.T) {
	ctx := context.Background()
	client := &Client{}

	if ifaces, err := client.Interfaces(); err != nil || len(ifaces) != 0 {
		t.Fatalf("Interfaces = %d, %v", len(ifaces), err)
	}
	if addrs, err := client.InterfaceAddrs(); err != nil || len(addrs) != 0 {
		t.Fatalf("InterfaceAddrs = %d, %v", len(addrs), err)
	}
	if addrs, err := client.InterfaceMulticastAddrs(); err != nil ||
		len(addrs) != 0 {
		t.Fatalf("InterfaceMulticastAddrs = %d, %v", len(addrs), err)
	}
	if _, err := client.InterfacesByIndex(1); err == nil {
		t.Fatal("InterfacesByIndex unexpectedly succeeded")
	}
	if _, err := client.InterfacesByName("lo"); err == nil {
		t.Fatal("InterfacesByName unexpectedly succeeded")
	}
	if _, err := client.ListenMulticastUDP(
		ctx,
		"udp",
		"224.0.0.1:1",
		gonnect.MulticastOptions{},
	); !errors.Is(err, gonnect.ErrUnsupported) {
		t.Fatalf("ListenMulticastUDP error = %v", err)
	}

	conn, err := client.ListenUDPConfig(ctx, nil, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDPConfig direct: %v", err)
	}
	_ = conn.Close()
}

func TestClientDialAndListenConfigCustomPaths(t *testing.T) {
	ctx := context.Background()
	udpServer, err := net.ListenUDP(
		"udp",
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
	)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer func() { _ = udpServer.Close() }()

	client := &Client{
		Filter: gonnect.TrueFilter,
		PacketDialer: func(
			ctx context.Context,
			network, address string,
		) (gonnect.PacketConn, error) {
			raddr, err := net.ResolveUDPAddr(network, address)
			if err != nil {
				return nil, err
			}
			return net.DialUDP(network, nil, raddr)
		},
		DirectPacketListener: func(
			ctx context.Context,
			_ string,
			_ string,
		) (gonnect.PacketConn, error) {
			var listenConfig net.ListenConfig
			conn, err := listenConfig.ListenPacket(ctx, "udp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			udpConn, ok := conn.(*net.UDPConn)
			if !ok {
				_ = conn.Close()
				return nil, errors.New("packet listener did not return UDPConn")
			}
			return udpConn, nil
		},
	}

	packet, err := client.ListenPacketConfig(ctx, nil, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacketConfig: %v", err)
	}
	_ = packet.Close()

	listenUDP, err := client.ListenUDPConfig(ctx, nil, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenUDPConfig custom: %v", err)
	}
	_ = listenUDP.Close()

	udp, err := client.DialUDP(ctx, "udp", "", udpServer.LocalAddr().String())
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	_ = udp.Close()
}

func TestClientTCPWrapperMethods(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = right.Close() }()

	client := &Client{
		Filter: gonnect.TrueFilter,
		Dialer: func(context.Context, string, string) (net.Conn, error) {
			return left, nil
		},
	}
	tcpConn, err := client.DialTCP(context.Background(), "tcp", "", "pipe")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer func() { _ = tcpConn.Close() }()

	if err := tcpConn.SetKeepAlive(true); err != nil {
		t.Fatalf("SetKeepAlive: %v", err)
	}
	if err := tcpConn.SetKeepAliveConfig(net.KeepAliveConfig{}); err != nil {
		t.Fatalf("SetKeepAliveConfig: %v", err)
	}
	if err := tcpConn.SetKeepAlivePeriod(time.Second); err != nil {
		t.Fatalf("SetKeepAlivePeriod: %v", err)
	}
	if err := tcpConn.SetLinger(0); err != nil {
		t.Fatalf("SetLinger: %v", err)
	}
	if err := tcpConn.SetNoDelay(true); err != nil {
		t.Fatalf("SetNoDelay: %v", err)
	}

	readDone := make(chan error, 1)
	go func() {
		var dst bytes.Buffer
		_, err := tcpConn.WriteTo(&dst)
		if dst.String() != "hello" {
			err = errors.Join(err, errors.New("unexpected WriteTo data"))
		}
		readDone <- err
	}()
	if _, err := right.Write([]byte("hello")); err != nil {
		t.Fatalf("pipe write: %v", err)
	}
	_ = right.Close()
	if err := <-readDone; err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	wrapper := &tcpConnWrapper{Conn: &nopAddrConn{}}
	if n, err := wrapper.ReadFrom(
		bytes.NewBufferString("abc"),
	); err != nil ||
		n != 3 {
		t.Fatalf("ReadFrom = %d, %v", n, err)
	}

	closeReadLeft, closeReadRight := net.Pipe()
	_ = closeReadRight.Close()
	if err := (&tcpConnWrapper{Conn: closeReadLeft}).CloseRead(); err != nil {
		t.Fatalf("CloseRead fallback: %v", err)
	}
	closeWriteLeft, closeWriteRight := net.Pipe()
	_ = closeWriteRight.Close()
	if err := (&tcpConnWrapper{Conn: closeWriteLeft}).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite fallback: %v", err)
	}
}

func TestClientListenTCPNonTCPListener(t *testing.T) {
	client := &Client{
		Filter: gonnect.TrueFilter,
		DirectListener: func(
			context.Context,
			string,
			string,
		) (net.Listener, error) {
			return coverageListener{}, nil
		},
	}

	if _, err := client.ListenTCP(
		context.Background(),
		"tcp",
		"127.0.0.1:0",
	); err == nil {
		t.Fatal("ListenTCP unexpectedly accepted a non-TCP listener")
	}
}

type coverageListener struct{}

func (coverageListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (coverageListener) Close() error              { return nil }

func (coverageListener) Addr() net.Addr { return badAddr("listener") }

func TestBindAcceptedConnFallbacks(t *testing.T) {
	conn := &bindAcceptedConn{
		Conn:    &nopAddrConn{},
		onClose: func() {},
	}

	if n, err := conn.ReadFrom(
		bytes.NewBufferString("abc"),
	); err != nil ||
		n != 3 {
		t.Fatalf("bind ReadFrom fallback = %d, %v", n, err)
	}
	if err := conn.SetKeepAlive(true); err != nil {
		t.Fatalf("bind SetKeepAlive fallback: %v", err)
	}
	if err := conn.SetKeepAliveConfig(net.KeepAliveConfig{}); err != nil {
		t.Fatalf("bind SetKeepAliveConfig fallback: %v", err)
	}
	if err := conn.SetKeepAlivePeriod(time.Second); err != nil {
		t.Fatalf("bind SetKeepAlivePeriod fallback: %v", err)
	}
	if err := conn.SetLinger(0); err != nil {
		t.Fatalf("bind SetLinger fallback: %v", err)
	}
	if err := conn.SetNoDelay(true); err != nil {
		t.Fatalf("bind SetNoDelay fallback: %v", err)
	}
}

type nopAddrConn struct {
	bytes.Buffer
}

func (n nopAddrConn) Close() error                     { return nil }
func (n nopAddrConn) LocalAddr() net.Addr              { return nil }
func (n nopAddrConn) RemoteAddr() net.Addr             { return nil }
func (n nopAddrConn) SetDeadline(time.Time) error      { return nil }
func (n nopAddrConn) SetReadDeadline(time.Time) error  { return nil }
func (n nopAddrConn) SetWriteDeadline(time.Time) error { return nil }

func TestConfigAdaptersAndWsCoderConn(t *testing.T) {
	var wsConfig *WebSocketConfig
	if wsConfig.jar() != nil {
		t.Fatal("nil WebSocketConfig returned a non-nil jar")
	}
	if wsConfig.subprotocols() != nil {
		t.Fatal("nil WebSocketConfig returned subprotocols")
	}
	if wsConfig.enableCompression() {
		t.Fatal("nil WebSocketConfig enabled compression")
	}

	adapter := &wsBufferPoolAdapter{}
	if got := adapter.Get(); got != nil {
		t.Fatalf("nil pool Get = %v", got)
	}
	adapter.Put([]byte("ignored"))

	pool := bufpool.NewTestDebugPool(t)
	adapter = &wsBufferPoolAdapter{pool: pool}
	buf, ok := adapter.Get().([]byte)
	if !ok {
		t.Fatal("buffer pool adapter did not return []byte")
	}
	adapter.Put(buf)
	adapter.Put("ignored")

	left, right := net.Pipe()
	defer func() { _ = right.Close() }()
	laddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	raddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
	ws := &wsCoderConn{Conn: left, Laddr: laddr, Raddr: raddr}
	if ws.LocalAddr() != laddr || ws.RemoteAddr() != raddr {
		t.Fatal("wsCoderConn did not use configured addresses")
	}

	ws = &wsCoderConn{Conn: left}
	if ws.LocalAddr() == nil || ws.RemoteAddr() == nil {
		t.Fatal("wsCoderConn did not fall back to wrapped connection addresses")
	}
	_ = ws.Close()

	if err := wrapEOF(os.ErrNotExist); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrapEOF non-network error = %v", err)
	}
}

func TestGetSpawnerAndWithNetworkNil(t *testing.T) {
	var client *Client
	if client.GetSpawner() != nil {
		t.Fatal("nil client GetSpawner returned non-nil")
	}

	client = &Client{}
	client.WithNetwork(nil)
	if client.Dialer != nil ||
		client.DirectListener != nil ||
		client.PacketDialer != nil ||
		client.DirectPacketListener != nil {
		t.Fatal("WithNetwork(nil) modified client")
	}

	spawner := coverageSpawner{}
	client.Spawner = spawner
	if client.GetSpawner() == nil {
		t.Fatal("GetSpawner returned nil for configured spawner")
	}

	var server *Server
	if server.GetSpawner() != nil {
		t.Fatal("nil server GetSpawner returned non-nil")
	}
	server = &Server{Spawner: spawner}
	if server.GetSpawner() == nil {
		t.Fatal("server GetSpawner returned nil for configured spawner")
	}
}

func TestResolveUnspecifiedAddrParseFailure(t *testing.T) {
	addr := protocol.AddrFromHostPort("0.0.0.0:1234", "tcp")
	got := resolveUnspecifiedAddr(badRemoteAddrConn{}, addr)
	if got.String() != addr.String() {
		t.Fatalf("resolveUnspecifiedAddr changed addr to %s", got.String())
	}
}

type badRemoteAddrConn struct{}

func (badRemoteAddrConn) Read([]byte) (int, error) { return 0, io.EOF }

func (badRemoteAddrConn) Write(
	[]byte,
) (int, error) {
	return 0, io.ErrClosedPipe
}
func (badRemoteAddrConn) Close() error { return nil }

func (badRemoteAddrConn) LocalAddr() net.Addr { return badAddr("local") }

func (badRemoteAddrConn) RemoteAddr() net.Addr             { return badAddr("remote") }
func (badRemoteAddrConn) SetDeadline(time.Time) error      { return nil }
func (badRemoteAddrConn) SetReadDeadline(time.Time) error  { return nil }
func (badRemoteAddrConn) SetWriteDeadline(time.Time) error { return nil }

type badAddr string

func (b badAddr) Network() string { return "bad" }
func (b badAddr) String() string  { return string(b) }

type coverageSpawner struct{}

func (coverageSpawner) Spawn(worker func(), name string) (uint64, error) {
	go worker()
	return 1, nil
}

func (coverageSpawner) SpawnWg(
	worker func(),
	waitgroup *sync.WaitGroup,
	name string,
) (uint64, error) {
	waitgroup.Add(1)
	go func() {
		defer waitgroup.Done()
		worker()
	}()
	return 1, nil
}
