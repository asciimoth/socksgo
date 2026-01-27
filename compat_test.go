package socksgo_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo"
)

type HostPort struct {
	Host string
	Port string
}

func (hp *HostPort) String() string {
	return net.JoinHostPort(hp.Host, hp.Port)
}

type NetAddr struct {
	Addr string
	Net  string
}

func (na NetAddr) String() string {
	return na.Addr
}

func (na NetAddr) Network() string {
	return na.Network()
}

type EnvConfig struct {
	Host     string
	Tor      string
	Pairs    []HostPort // example.com:http|google.com:http
	CurlURLs []string
}

func GetEnvConfig() EnvConfig {
	ret := EnvConfig{
		Host: "127.0.0.1",
		Tor:  "127.0.0.1:9050",
		Pairs: []HostPort{
			{"iana.org", "http"},
			{"ietf.org", "http"},
			{"example.com", "http"},
			{"google.com", "http"},
		},
		CurlURLs: []string{
			"https://iana.org",
			"https://ietf.org",
			"https://example.com",
			"https://google.com",
			"http://iana.org",
			"http://ietf.org",
			"http://example.com",
			"http://google.com",
		},
	}

	host := os.Getenv("SOCKS_TEST_HOST")
	if host != "" {
		ret.Host = host
	}

	tor := os.Getenv("SOCKS_TEST_TOR")
	if tor != "" {
		ret.Tor = tor
	}

	pairsStr := os.Getenv("SOCKS_TEST_PAIRS")
	if pairsStr != "" {
		pairs := []HostPort{}
		for pair := range strings.SplitSeq(pairsStr, "|") {
			host, port, err := net.SplitHostPort(strings.TrimSpace(pair))
			if err != nil {
				continue
			}
			pairs = append(pairs, HostPort{
				Host: host,
				Port: port,
			})
		}
		ret.Pairs = append(ret.Pairs, pairs...)
	}

	curlURLsStr := os.Getenv("SOCKS_TEST_CURL_URLS")
	if curlURLsStr != "" {
		ret.CurlURLs = append(ret.CurlURLs, strings.Split(curlURLsStr, "|")...)
	}

	return ret
}

func buildClient(url string, t *testing.T, pool bufpool.Pool) *socksgo.Client {
	c, err := socksgo.ClientFromURL(url)
	c.Pool = pool
	if err != nil {
		t.Fatalf("failed to create gost socks client: %s %v", url, err)
	}
	return c
}

func runUDPSTunSrv(t *testing.T) (io.Closer, net.Addr) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	})
	if err != nil {
		t.Fatalf("failed to start udp strun service: %v", err)
	}
	go func() {
		for {
			buf := make([]byte, 4098)
			_, addr, err := srv.ReadFrom(buf)
			if err != nil {
				break
			}
			t.Logf("stun request from %s", addr)
			reply := []byte("YOUR ADDR IS: " + addr.String())
			_, err = srv.WriteTo(reply, addr)
			if err != nil {
				break
			}
		}
	}()
	return srv, srv.LocalAddr()
}

func checkPacketConnLaddr(t *testing.T, conn net.PacketConn) (addr net.Addr) {
	stun_srv, stun := runUDPSTunSrv(t)
	defer stun_srv.Close()

	ready := make(chan any)
	defer func() { <-ready }()

	const ATTEMPTS = 100
	go func() {
		defer func() { ready <- nil }()
		for range ATTEMPTS {
			_, err := conn.WriteTo([]byte{0}, stun)
			if err != nil {
				return
			}
			time.Sleep(time.Millisecond * 10)
		}
	}()
	for range ATTEMPTS {
		buf := make([]byte, 4098)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("failed to get reply from stun: %v", err)
			return
		}
		reply := string(buf[:n])
		t.Logf("maybe stun reply %s", reply)
		if after, ok := strings.CutPrefix(string(buf[:n]), "YOUR ADDR IS: "); ok {
			addr = NetAddr{
				Addr: after,
				Net:  conn.LocalAddr().Network(),
			}
			return
		}
	}
	t.Fatalf("failed to get reply from stun: too much attempts")
	return
}

func testUDPListen(c *socksgo.Client, t *testing.T, times int, needStun bool) {
	serverConn, err := c.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to start udp server with client %T: %v", c, err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr()

	if needStun {
		serverAddr = checkPacketConnLaddr(t, serverConn)
	}

	t.Log(serverAddr)

	clientConn, err := net.Dial("udp4", serverAddr.String())
	if err != nil {
		t.Fatalf("failed to start udp client with client %T: %v", c, err)
	}
	defer clientConn.Close()

	// server goroutine: reply "pong N" for "ping N"
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, addr, err := serverConn.ReadFrom(buf)
			if err != nil {
				// connection closed or error -> exit goroutine
				return
			}
			msg := string(buf[:n])
			if !strings.HasPrefix(msg, "ping ") {
				// ignore unknown messages
				continue
			}
			parts := strings.SplitN(msg, " ", 2)
			if len(parts) != 2 {
				continue
			}
			reply := "pong " + parts[1]
			// best-effort write back; ignore errors (client may be gone)
			_, _ = serverConn.WriteTo([]byte(reply), addr)
		}
	}()

	// client: send ping i, wait for pong i with retries on timeout
	buf := make([]byte, 2048)
	timeout := 3 * time.Second
	maxAttempts := 10

	for i := 1; i <= times; i++ {
		want := fmt.Sprintf("pong %d", i)
		ping := fmt.Sprintf("ping %d", i)

		received := false
		for attempt := 1; attempt <= maxAttempts && !received; attempt++ {
			if _, err := clientConn.Write([]byte(ping)); err != nil {
				// writing to server address failed — fatal for test
				_ = serverConn.Close()
				t.Fatalf("client WriteTo (attempt %d) failed: %v", attempt, err)
			}

			if err := clientConn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
				_ = serverConn.Close()
				t.Fatalf("SetReadDeadline failed: %v", err)
			}

			n, err := clientConn.Read(buf)
			if err != nil {
				// timeout -> retry; other errors are fatal
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					// retry
					continue
				}
				_ = serverConn.Close()
				t.Fatalf("client ReadFrom failed: %v", err)
			}

			got := string(buf[:n])
			if got == want {
				received = true
				break
			}
			// if got something else, keep waiting/retrying until timeout
		}

		if !received {
			_ = serverConn.Close()
			t.Fatalf("did not receive %q after %d attempts", want, maxAttempts)
		}
	}

	// stop server goroutine and wait for it
	_ = serverConn.Close()
	_ = clientConn.Close()
	<-done
}

func testListen(c *socksgo.Client, t *testing.T, times int) {
	l, err := c.Listen(t.Context(), "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to start listener with client %T: %v", c, err)
	}
	defer l.Close()

	handler := func(conn net.Conn, i int) {
		defer conn.Close()

		_, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("error while reading request: %v", err)
		}

		text := fmt.Sprintf("response #%d\n", i)

		response := fmt.Sprintf(
			"HTTP/1.1 200 OK\r\n"+
				"Content-Type: text/plain; charset=utf-8\r\n"+
				"Content-Length: %d\r\n"+
				"Connection: close\r\n"+
				"\r\n%s",
			len(text), text,
		)

		_, err = conn.Write([]byte(response))
		if err != nil {
			t.Fatalf("error while responding: %v", err)
		}

		_, _ = io.ReadAll(conn)
	}

	go func() {
		i := 0
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			handler(conn, i)
			i += 1
		}
	}()

	for i := range times {
		func() {
			resp, err := http.Get("http://" + l.Addr().String())
			if err != nil {
				t.Fatalf("error while requesting: %v", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("fail to read response: %v", err)
			}

			expect := fmt.Sprintf("response #%d", i)
			got := strings.TrimSpace(string(body))

			if got != expect {
				t.Fatalf("got '%s' while expecting '%s'", got, expect)
			}
		}()
	}
}

func testUDPDial(c *socksgo.Client, t *testing.T, pairs ...HostPort) {
	resolver := net.Resolver{
		PreferGo: true,
		Dial:     c.Dial,
	}

	var err error
	for _, addr := range pairs {
		_, err = resolver.LookupHost(t.Context(), addr.Host)
		if err == nil {
			return
		}
	}

	if err != nil {
		t.Fatalf("failed to dial udp with client %T: %v", c, err)
	}
}

func testLookup(c *socksgo.Client, t *testing.T, lookupAddr bool, pairs ...HostPort) {
	var (
		err error
		ips []string = []string{
			"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
		}
	)

	for _, addr := range pairs {
		var resp []net.IP
		resp, err = c.LookupIP(t.Context(), "ip", addr.Host)
		if err == nil {
			for _, ip := range resp {
				ips = append(ips, ip.String())
			}
			break
		}
	}

	if err != nil {
		t.Fatalf("failed to lookup with client %T: %v", c, err)
	}

	if lookupAddr {
		for _, ip := range ips {
			_, err = c.LookupAddr(t.Context(), ip)
			if err == nil {
				break
			}
		}
	}

	if err != nil {
		t.Fatalf("failed to reverse lookup with client %T: %v", c, err)
	}
}

func testDial(c *socksgo.Client, t *testing.T, pairs ...HostPort) {
	var (
		conn net.Conn
		hp   HostPort
		err  error
	)
	for _, addr := range pairs {
		conn, err = c.Dial(context.Background(), "tcp", addr.String())
		if err == nil {
			hp = addr
			break
		}
	}
	if err != nil {
		t.Fatalf("failed to dial with client %T: %v", c, err)
	}

	// Create HTTP/1.1 request
	request := strings.Join([]string{
		"GET / HTTP/1.1",
		"Host: " + hp.Host,
		"User-Agent: go-test-http",
		"Accept: */*",
		"Connection: close",
		"", // Empty line to separate headers from body
		"", // Empty line indicating no body
	}, "\r\n")

	// Send request
	_, err = conn.Write([]byte(request))
	if err != nil {
		t.Fatalf("failed to send request with client %T: %v", c, err)
	}

	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("failed to read response with client %T: %v", c, err)
	}

	lower := strings.ToLower(string(response))

	if strings.Contains(lower, "ok") || strings.Contains(lower, "moved") {
		return
	}

	t.Fatalf("response from %s is not ok:\n%s", hp.String(), string(response))
}
