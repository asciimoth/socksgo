package socksgo_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
)

const fuzzOperationCount = 15

// FuzzUntrustedInput covers the public entry points that decode data from
// peers, configuration, and environment-like text. The first byte selects an
// entry point. This keeps one fuzzing session within one shared time budget.
func FuzzUntrustedInput(f *testing.F) {
	seeds := [][]byte{
		{0, 1, 0, 80, 127, 0, 0, 1, 0},
		{1, 0, 90, 0, 80, 127, 0, 0, 1},
		{2, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80},
		{3, 0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 'd', 'a', 't', 'a'},
		{4, 0, 4, 255, 1, 127, 0, 0, 1, 0, 53, 'd', 'a', 't', 'a'},
		{5, 1, 0},
		{6, 1, 1, 'u', 1, 'p'},
		{7, 1, 1, 0, 1, 'x'},
		{8, 5, 0},
		{9, 1, 0},
		{10, 1, 1, 0, 1, 'x'},
		{11, 5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80},
		[]byte("\fsocks5+tls://user:pass@example.com:1080?secure&gost"),
		[]byte("\rexample.com,127.0.0.1,10.0.0.0/8"),
		[]byte("\x0e[2001:db8::1]:443"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) == 0 || len(input) > 64*1024 {
			t.Skip()
		}

		operation := int(input[0]) % fuzzOperationCount
		data := input[1:]
		switch operation {
		case 0:
			fuzzSocks4Request(t, data)
		case 1:
			fuzzSocks4Reply(t, data)
		case 2:
			fuzzSocks5TCP(t, data)
		case 3:
			fuzzSocks5AssocUDP(t, data)
		case 4:
			fuzzSocks5TunUDP(t, data)
		case 5:
			fuzzAuthNegotiation(data)
		case 6:
			fuzzPasswordAuthHandler(data)
		case 7:
			fuzzGSSAuthHandler(data)
		case 8:
			fuzzAuthClient(data)
		case 9:
			fuzzPasswordAuthClient(data)
		case 10:
			fuzzGSSAuthClient(data)
		case 11:
			fuzzServer(data)
		case 12:
			fuzzClientURL(t, data)
		case 13:
			fuzzFilter(data)
		case 14:
			fuzzAddress(t, data)
		}
	})
}

func fuzzSocks4Request(t *testing.T, data []byte) {
	_, addr, _, err := protocol.ReadSocks4TCPRequest(bytes.NewReader(data), nil)
	if err == nil {
		checkParsedAddr(t, addr)
	}
}

func fuzzSocks4Reply(t *testing.T, data []byte) {
	status, addr, err := protocol.ReadSocks4TCPReply(bytes.NewReader(data))
	if err == nil && status.Ok() {
		checkParsedAddr(t, addr)
	}
}

func fuzzSocks5TCP(t *testing.T, data []byte) {
	_, addr, err := protocol.ReadSocks5TCPRequest(bytes.NewReader(data), nil)
	if err == nil {
		checkParsedAddr(t, addr)
	}
	_, addr, err = protocol.ReadSocks5TCPReply(bytes.NewReader(data), nil)
	if err == nil {
		checkParsedAddr(t, addr)
	}
}

func fuzzSocks5AssocUDP(t *testing.T, data []byte) {
	out := make([]byte, fuzzOutputSize(data))
	n, addr, _, err := protocol.ReadSocks5AssocUDPPacket(
		nil,
		&fuzzPacketConn{data: data},
		out,
		false,
		nil,
	)
	checkReadResult(t, n, out, err)
	if err == nil {
		checkParsedAddr(t, addr)
	}
}

func fuzzSocks5TunUDP(t *testing.T, data []byte) {
	out := make([]byte, fuzzOutputSize(data))
	n, addr, err := protocol.ReadSocks5TunUDPPacket(
		nil,
		newFuzzConn(data),
		out,
		false,
	)
	checkReadResult(t, n, out, err)
	if err == nil {
		checkParsedAddr(t, addr)
	}
}

func fuzzAuthNegotiation(data []byte) {
	handlers := (&protocol.AuthHandlers{}).Add(&protocol.PassAuthHandler{})
	_, _, _ = protocol.HandleAuth(newFuzzConn(data), nil, handlers)
}

func fuzzPasswordAuthHandler(data []byte) {
	handler := &protocol.PassAuthHandler{}
	_, _, _ = handler.HandleAuth(newFuzzConn(data), nil)
}

func fuzzGSSAuthHandler(data []byte) {
	handler := &protocol.GSSAuthHandler{Server: fuzzGSSServer{}}
	_, _, _ = handler.HandleAuth(newFuzzConn(data), nil)
}

func fuzzAuthClient(data []byte) {
	methods := (&protocol.AuthMethods{}).
		Add(&protocol.PassAuthMethod{User: "user", Pass: "pass"}).
		Add(&protocol.GSSAuthMethod{Client: &fuzzGSSClient{}})
	_, _, _ = protocol.RunAuth(newFuzzConn(data), nil, methods)
}

func fuzzPasswordAuthClient(data []byte) {
	method := &protocol.PassAuthMethod{User: "user", Pass: "pass"}
	_, _, _ = method.RunAuth(newFuzzConn(data), nil)
}

func fuzzGSSAuthClient(data []byte) {
	method := &protocol.GSSAuthMethod{Client: &fuzzGSSClient{}}
	_, _, _ = method.RunAuth(newFuzzConn(data), nil)
}

func fuzzServer(data []byte) {
	server := &socksgo.Server{
		Handlers: map[protocol.Cmd]socksgo.CommandHandler{},
	}
	_ = server.Accept(context.Background(), newFuzzConn(data), false)
}

func fuzzClientURL(t *testing.T, data []byte) {
	value := string(data)
	_, _, _ = internal.ParseScheme(value)
	_ = internal.GetProxyFromEnvVar(value)
	safeClient, err := socksgo.ClientFromURLSafe(value)
	if err == nil && safeClient.InsecureUDP {
		t.Fatal("safe URL parser enabled insecure UDP")
	}
	_, _ = socksgo.ClientFromURL(value)
}

func fuzzFilter(data []byte) {
	separator := bytes.IndexByte(data, 0)
	if separator < 0 {
		separator = len(data) / 2
	}
	filter := socksgo.BuildFilter(string(data[:separator]))
	_ = filter("tcp", string(data[separator:]))
}

func fuzzAddress(t *testing.T, data []byte) {
	separator := bytes.IndexByte(data, 0)
	if separator < 0 {
		separator = len(data) / 2
	}
	network := string(data[:separator])
	host := string(data[separator:])
	addresses := []protocol.Addr{
		protocol.AddrFromHostPort(host, network),
		protocol.AddrFromString(host, 1234, network),
		protocol.AddrFromFQDN(host, 1234, network),
		protocol.AddrFromFQDNNoDot(host, 1234, network),
	}
	for _, addr := range addresses {
		checkParsedAddr(t, addr)
		_ = addr.ToHostPort()
		_ = addr.String()
	}
}

func fuzzOutputSize(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	return int(data[0]) * 4
}

func checkReadResult(t *testing.T, n int, out []byte, _ error) {
	t.Helper()
	if n < 0 || n > len(out) {
		t.Fatalf(
			"read returned invalid length %d for %d-byte buffer",
			n,
			len(out),
		)
	}
}

func checkParsedAddr(t *testing.T, addr protocol.Addr) {
	t.Helper()
	switch addr.Type {
	case protocol.IP4Addr:
		if len(addr.Host) != net.IPv4len {
			t.Fatalf("IPv4 address has %d bytes", len(addr.Host))
		}
	case protocol.IP6Addr:
		if len(addr.Host) != net.IPv6len {
			t.Fatalf("IPv6 address has %d bytes", len(addr.Host))
		}
	case protocol.FQDNAddr:
		// Text constructors can accept names larger than the wire limit.
	default:
		t.Fatalf("parsed unknown address type %d", addr.Type)
	}
}

type fuzzConn struct {
	reader *bytes.Reader
	writes bytes.Buffer
}

func newFuzzConn(data []byte) *fuzzConn {
	return &fuzzConn{reader: bytes.NewReader(data)}
}

func (c *fuzzConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *fuzzConn) Write(p []byte) (int, error) {
	return c.writes.Write(p)
}

func (c *fuzzConn) Close() error { return nil }

func (c *fuzzConn) LocalAddr() net.Addr { return fuzzAddr("local") }

func (c *fuzzConn) RemoteAddr() net.Addr { return fuzzAddr("remote") }

func (c *fuzzConn) SetDeadline(time.Time) error { return nil }

func (c *fuzzConn) SetReadDeadline(time.Time) error { return nil }

func (c *fuzzConn) SetWriteDeadline(time.Time) error { return nil }

type fuzzPacketConn struct {
	data []byte
	done bool
}

func (c *fuzzPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.done {
		return 0, nil, io.EOF
	}
	c.done = true
	return copy(p, c.data), fuzzAddr("peer"), nil
}

func (c *fuzzPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}

func (c *fuzzPacketConn) Close() error { return nil }

func (c *fuzzPacketConn) LocalAddr() net.Addr { return fuzzAddr("local") }

func (c *fuzzPacketConn) SetDeadline(time.Time) error { return nil }

func (c *fuzzPacketConn) SetReadDeadline(time.Time) error { return nil }

func (c *fuzzPacketConn) SetWriteDeadline(time.Time) error { return nil }

type fuzzAddr string

func (a fuzzAddr) Network() string { return "fuzz" }
func (a fuzzAddr) String() string  { return string(a) }

type fuzzGSSServer struct{}

func (fuzzGSSServer) AcceptSecContext(
	[]byte,
) ([]byte, string, bool, error) {
	return nil, "fuzz", false, nil
}

func (fuzzGSSServer) DeleteSecContext() error { return nil }

type fuzzGSSClient struct {
	calls int
}

func (c *fuzzGSSClient) InitSecContext(
	string,
	[]byte,
) ([]byte, bool, error) {
	c.calls++
	return nil, c.calls == 1, nil
}

func (c *fuzzGSSClient) DeleteSecContext() error { return nil }
