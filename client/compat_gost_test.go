//go:build gost

package client_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/socks/client"
)

// runGost("socks5://user:pass@:1080")
func runGost(url string, ctx context.Context) (func(), error) {
	cmd := exec.CommandContext(ctx, "gost", "-L", url)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() {
		err := cmd.Process.Kill()
		if err != nil {
			panic(err)
		}
	}, nil
}

func runGostAll(t *testing.T, cfg EnvConfig) func() {

	killfuncs := []func(){}

	k, err := runGost(
		"socks5://"+cfg.Addr5+"?udp=true&udpBufferSize=4096&bind=true", t.Context(),
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	killfuncs = append(killfuncs, k)

	k, err = runGost(
		"socks5://user:pass@"+cfg.Addr5Pass+"?udp=true&udpBufferSize=4096&bind=true", t.Context(),
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	killfuncs = append(killfuncs, k)

	k, err = runGost(
		"socks4://"+cfg.Addr4+"?bind=true", t.Context(),
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	killfuncs = append(killfuncs, k)

	k, err = runGost(
		"socks4://user@"+cfg.Addr4Pass+"?bind=true", t.Context(),
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	killfuncs = append(killfuncs, k)

	kill := func() {
		for _, kf := range killfuncs {
			kf()
		}
	}

	// TODO: Aoid RC here
	time.Sleep(time.Millisecond * time.Duration(cfg.RCTimeout)) // Wait for all gost instances to start

	return kill
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

func TestIntegrationWithGost(t *testing.T) {
	cfg := GetEnvConfig()

	kill := runGostAll(t, cfg)
	defer kill()

	c5g := buildClient("socks5://"+cfg.Addr5+"?gost", t)
	c5gp := buildClient("socks5://user:pass@"+cfg.Addr5Pass+"?gost", t)
	c5 := buildClient("socks5://"+cfg.Addr5, t)
	c5p := buildClient("socks5://user:pass@"+cfg.Addr5Pass, t)

	c4 := buildClient("socks4://"+cfg.Addr4, t)
	c4p := buildClient("socks4://user@"+cfg.Addr4Pass, t)
	c4a := buildClient("socks4a://"+cfg.Addr4, t)
	c4ap := buildClient("socks4a://user@"+cfg.Addr4Pass, t)

	t.Run("HttpRequest", func(t *testing.T) {
		testDial(c5g, t, cfg.Pairs...)
		testDial(c5gp, t, cfg.Pairs...)
		testDial(c5, t, cfg.Pairs...)
		testDial(c5p, t, cfg.Pairs...)

		testDial(c4, t, cfg.Pairs...)
		testDial(c4p, t, cfg.Pairs...)
		testDial(c4a, t, cfg.Pairs...)
		testDial(c4ap, t, cfg.Pairs...)
	})

	t.Run("DNSRequest", func(t *testing.T) {
		testUDPDial(c5g, t, cfg.Pairs...)
		testUDPDial(c5gp, t, cfg.Pairs...)
		testUDPDial(c5, t, cfg.Pairs...)
		testUDPDial(c5p, t, cfg.Pairs...)
	})

	t.Run("Listen", func(t *testing.T) {
		testListen(c5g, t, 10)
		testListen(c5gp, t, 10)
		testListen(c5, t, 1)
		testListen(c5p, t, 1)
	})

	t.Run("ListenUDP", func(t *testing.T) {
		testUDPListen(c5g, t, 10)
		testUDPListen(c5gp, t, 10)
		// testUDPListen(c5, t, 1)
		// testUDPListen(c5p, t, 1)
	})
}
