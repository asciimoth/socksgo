package client_test

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

	"github.com/asciimoth/socks/client"
)

type HostPort struct {
	Host string
	Port string
}

func (hp *HostPort) String() string {
	return net.JoinHostPort(hp.Host, hp.Port)
}

type EnvConfig struct {
	Addr5, Addr5Pass, Addr4, Addr4Pass string
	Tor                                string
	Pairs                              []HostPort // example.com:http|google.com:http
	RCTimeout                          int
}

func GetEnvConfig() EnvConfig {
	ret := EnvConfig{
		Addr5:     "127.0.0.1:1096",
		Addr5Pass: "127.0.0.1:1097",
		Addr4:     "127.0.0.1:1098",
		Addr4Pass: "127.0.0.1:1099",

		Tor: "127.0.0.1:9050",

		Pairs: []HostPort{
			{"example.com", "http"},
			{"google.com", "http"},
		},

		RCTimeout: 2000,
	}

	// TODO: Parse RCTimeout

	addr5 := os.Getenv("SOCKS_TEST_ADDR5")
	if addr5 != "" {
		ret.Addr5 = addr5
	}

	addr5pass := os.Getenv("SOCKS_TEST_ADDR5PASS")
	if addr5pass != "" {
		ret.Addr5Pass = addr5pass
	}

	addr4 := os.Getenv("SOCKS_TEST_ADDR4")
	if addr4 != "" {
		ret.Addr4 = addr4
	}

	addr4pass := os.Getenv("SOCKS_TEST_ADDR4PASS")
	if addr4pass != "" {
		ret.Addr4Pass = addr4pass
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
	}

	return ret
}

func buildClient(url string, t *testing.T) client.Client {
	c, err := client.ClientFomURL(url)
	if err != nil {
		t.Fatalf("failed to create gost socks5 client: %s %v", url, err)
	}
	return c
}

func testUDPListen(c client.Client, t *testing.T, times int) {
	serverConn, err := c.ListenPacket(context.Background(), "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to start udp server with client %T: %v", c, err)
	}
	defer serverConn.Close()

	t.Log(serverConn.LocalAddr())

	clientConn, err := net.Dial("udp4", serverConn.LocalAddr().String())
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

func testListen(c client.Client, t *testing.T, times int) {
	l, err := c.Listen(t.Context(), "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to start listener with client %T: %v", c, err)
	}
	defer l.Close()

	handler := func(conn net.Conn, i int) {
		defer conn.Close()

		_, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("error while reading reqest: %v", err)
		}

		text := fmt.Sprintf("responce #%d\n", i)

		responce := fmt.Sprintf(
			"HTTP/1.1 200 OK\r\n"+
				"Content-Type: text/plain; charset=utf-8\r\n"+
				"Content-Length: %d\r\n"+
				"Connection: close\r\n"+
				"\r\n%s",
			len(text), text,
		)

		_, err = conn.Write([]byte(responce))
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
		resp, err := http.Get("http://" + l.Addr().String())
		if err != nil {
			t.Fatalf("error while requesting: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("fail to read responce: %v", err)
		}

		expect := fmt.Sprintf("responce #%d", i)
		got := strings.TrimSpace(string(body))

		if got != expect {
			t.Fatalf("got '%s' while expecting '%s'", got, expect)
		}
	}
}

func testUDPDial(c client.Client, t *testing.T, pairs ...HostPort) {
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

func testLookup(c client.Client, t *testing.T, lookupAddr bool, pairs ...HostPort) {
	var (
		err error
		ips []string = []string{"8.8.8.8"}
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

func testDial(c client.Client, t *testing.T, pairs ...HostPort) {
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

	responce, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("failed to read responce with client %T: %v", c, err)
	}

	lower := strings.ToLower(string(responce))

	if strings.Contains(lower, "ok") || strings.Contains(lower, "moved") {
		return
	}

	t.Fatalf("responce from %s is not ok:\n%s", hp.String(), string(responce))
}
