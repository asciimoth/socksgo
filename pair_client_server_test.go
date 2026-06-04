package socksgo_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
	socksgo "github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

func runClientHttp(t *testing.T, srv string, urls []string) {
	socks, err := socksgo.ClientFromURL(srv)
	if err != nil {
		t.Fatal()
	}
	transport := &http.Transport{
		DialContext:         socks.Dial,
		MaxIdleConns:        100,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 60 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}
	for _, url := range urls {
		var req *http.Request
		req, err = http.NewRequest("GET", url, nil) //nolint
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

func buildSocksPostfix(tls, ws bool) string {
	postfix := ""
	if tls {
		if ws {
			postfix = "+wss"
		} else {
			postfix = "+tls"
		}
	} else {
		if ws {
			postfix = "+ws"
		}
	}
	return postfix
}

func runAssoc5UDP(
	t *testing.T,
	addr string,
	tls, ws bool,
	pairs []HostPort,
	pool bufpool.Pool,
) {
	postfix := buildSocksPostfix(tls, ws)
	t.Run("assoc", func(t *testing.T) {
		t.Run("dial socks5", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://"+addr, t, pool,
			)
			testUDPDial(client, t, pairs...)
		})
		t.Run("dial socks5 pass", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://user:pass@"+addr, t, pool,
			)
			testUDPDial(client, t, pairs...)
		})
		t.Run("dial socks5 gost", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://"+addr+"?gost", t, pool,
			)
			testUDPDial(client, t, pairs...)
		})
		t.Run("dial socks5 pass gost", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://user:pass@"+addr+"?gost", t, pool,
			)
			testUDPDial(client, t, pairs...)
		})

		t.Run("listen socks5", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://"+addr, t, pool,
			)
			testUDPListen(client, t, 10)
		})
		t.Run("listen socks5 pass", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://user:pass@"+addr, t, pool,
			)
			testUDPListen(client, t, 10)
		})
		t.Run("listen socks5 gost", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://"+addr+"?gost", t, pool,
			)
			testUDPListen(client, t, 10)
		})
		t.Run("lsiten socks5 pass gost", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://user:pass@"+addr+"?gost", t, pool,
			)
			testUDPListen(client, t, 10)
		})
	})
}

func runListen45Tcp(
	t *testing.T,
	addr string,
	tls, ws bool,
	pool bufpool.Pool,
) {
	postfix := buildSocksPostfix(tls, ws)
	t.Run("listen", func(t *testing.T) {
		t.Run("socks4", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks4"+postfix+"://"+addr, t, pool,
			)
			testListen(client, t, 1)
		})
		t.Run("socks4 user", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks4"+postfix+"://user@"+addr, t, pool,
			)
			testListen(client, t, 1)
		})
		t.Run("socks4a", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks4a"+postfix+"://"+addr, t, pool,
			)
			testListen(client, t, 1)
		})
		t.Run("socks4a user", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks4a"+postfix+"://user@"+addr, t, pool,
			)
			testListen(client, t, 1)
		})

		t.Run("socks5", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://"+addr, t, pool,
			)
			testListen(client, t, 1)
		})
		t.Run("socks5 pass", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://user:pass@"+addr, t, pool,
			)
			testListen(client, t, 1)
		})

		t.Run("socks5 gost", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://"+addr+"?gost", t, pool,
			)
			testListen(client, t, 10)
		})
		t.Run("socks5 pass gost", func(t *testing.T) {
			t.Parallel()
			client := buildClient(
				"socks5"+postfix+"://user:pass@"+addr+"?gost", t, pool,
			)
			testListen(client, t, 10)
		})
	})
}

func runClients45Http(
	t *testing.T, addr string, urls []string, tls, ws bool,
) {
	postfix := buildSocksPostfix(tls, ws)
	t.Run("group", func(t *testing.T) {
		t.Run("socks4", func(t *testing.T) {
			t.Parallel()
			runClientHttp(t, "socks4"+postfix+"://"+addr, urls)
		})
		t.Run("socks4 user", func(t *testing.T) {
			t.Parallel()
			runClientHttp(t, "socks4"+postfix+"://user@"+addr, urls)
		})
		t.Run("socks4a", func(t *testing.T) {
			t.Parallel()
			runClientHttp(t, "socks4a"+postfix+"://"+addr, urls)
		})
		t.Run("socks4a user", func(t *testing.T) {
			t.Parallel()
			runClientHttp(t, "socks4a"+postfix+"://user@"+addr, urls)
		})
		t.Run("socks5", func(t *testing.T) {
			t.Parallel()
			runClientHttp(t, "socks5"+postfix+"://"+addr, urls)
		})
		t.Run("socks5 pass", func(t *testing.T) {
			t.Parallel()
			runClientHttp(t, "socks5"+postfix+"://user:pass@"+addr, urls)
		})
	})
}

func TestClientServerConnect(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runTCPServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	runClients45Http(t, addr.String(), cfg.CurlURLs, false, false)
}

func TestClientServerTLSConnect(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runTLSServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	runClients45Http(t, addr.String(), cfg.CurlURLs, true, false)
}

func TestClientWSServerConnect(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runWSServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	runClients45Http(t, addr.String(), cfg.CurlURLs, false, true)
}

func TestClientWSSServerConnect(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runWSServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	runClients45Http(t, addr.String(), cfg.CurlURLs, true, true)
}

func TestClientServerBind(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runTCPServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	runListen45Tcp(t, addr.String(), false, false, pool)
}

func TestClientServerSocks5BindAcceptBlocksWhileIdle(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runTCPServer(&socksgo.Server{
		Pool: pool,
		Handlers: map[protocol.Cmd]socksgo.CommandHandler{
			protocol.CmdBind: socksgo.DefaultBindHandler,
		},
	}, cfg.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	client := buildClient("socks5://"+addr.String(), t, pool)
	ln, err := client.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	acceptDone := make(chan error, 1)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
		acceptDone <- err
	}()

	select {
	case err := <-acceptDone:
		t.Fatalf("BIND Accept returned while idle: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	peer, err := net.Dial("tcp", ln.Addr().String()) //nolint noctx
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()

	select {
	case err := <-acceptDone:
		if err != nil {
			t.Fatalf("BIND Accept failed after peer connected: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for BIND Accept after peer connected")
	}

	select {
	case conn := <-accepted:
		_ = conn.Close()
	default:
		t.Fatal("BIND Accept reported success without a connection")
	}
}

func TestClientServerBindHTTPServeWaitsForAcceptedConnClose(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runTCPServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	for _, version := range []string{"socks4", "socks5"} {
		t.Run(version, func(t *testing.T) {
			client := buildClient(version+"://"+addr.String(), t, pool)
			ln, err := client.Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}

			handlerEntered := make(chan struct{})
			releaseResponse := make(chan struct{})
			var releaseResponseOnce sync.Once
			release := func() {
				releaseResponseOnce.Do(func() { close(releaseResponse) })
			}
			defer release()
			handler := http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					close(handlerEntered)
					<-releaseResponse
					_, _ = io.WriteString(w, "ok")
				},
			)

			srv := &http.Server{Handler: handler} //nolint gosec
			defer func() { _ = srv.Close() }()

			serveDone := make(chan error, 1)
			go func() {
				serveDone <- srv.Serve(ln)
			}()

			conn, err := net.Dial("tcp", ln.Addr().String()) //nolint noctx
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()

			_, err = conn.Write([]byte(
				"GET / HTTP/1.1\r\n" +
					"Host: bind.test\r\n" +
					"Connection: close\r\n\r\n",
			))
			if err != nil {
				t.Fatal(err)
			}

			select {
			case <-handlerEntered:
			case err := <-serveDone:
				t.Fatalf(
					"http Serve returned while first request started: %v",
					err,
				)
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for http handler")
			}

			select {
			case err := <-serveDone:
				t.Fatalf(
					"http Serve returned before accepted conn closed: %v",
					err,
				)
			case <-time.After(200 * time.Millisecond):
			}

			release()

			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != "ok" {
				t.Fatalf("response body = %q, want %q", body, "ok")
			}

			select {
			case <-serveDone:
			case <-time.After(time.Second):
				t.Fatal("http Serve did not return after accepted conn closed")
			}
		})
	}
}

func TestClientServerTLSBind(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runTLSServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	runListen45Tcp(t, addr.String(), true, false, pool)
}

func TestClientWSServerBind(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runWSServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	runListen45Tcp(t, addr.String(), false, true, pool)
}

func TestClientWSSServerBind(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runWSServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	runListen45Tcp(t, addr.String(), true, true, pool)
}

func TestClientServerAssoc(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runTCPServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	runAssoc5UDP(t, addr.String(), false, false, cfg.Pairs, pool)
}

func TestClientWSServerAssoc(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runWSServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	runAssoc5UDP(t, addr.String(), false, true, cfg.Pairs, pool)
}

func TestClientServerResolve(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runTCPServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	c5 := buildClient("socks5://"+addr.String()+"?tor", t, pool)
	c4a := buildClient("socks4a://"+addr.String()+"?tor", t, pool)

	t.Run("Lookup", func(t *testing.T) {
		testLookup(c5, t, true, cfg.Pairs...)
		testLookup(c5, t, false, cfg.Pairs...)
		testLookup(c4a, t, false, cfg.Pairs...)
	})
}

func TestClientServerTLSResolve(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runTLSServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	c5 := buildClient("socks5+tls://"+addr.String()+"?tor", t, pool)
	c4a := buildClient("socks4a+tls://"+addr.String()+"?tor", t, pool)

	t.Run("Lookup", func(t *testing.T) {
		testLookup(c5, t, true, cfg.Pairs...)
		testLookup(c5, t, false, cfg.Pairs...)
		testLookup(c4a, t, false, cfg.Pairs...)
	})
}

func TestClientWSServerResolve(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runWSServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	c5 := buildClient("socks5+ws://"+addr.String()+"?tor", t, pool)
	c4a := buildClient("socks4a+ws://"+addr.String()+"?tor", t, pool)

	t.Run("Lookup", func(t *testing.T) {
		testLookup(c5, t, true, cfg.Pairs...)
		testLookup(c5, t, false, cfg.Pairs...)
		testLookup(c4a, t, false, cfg.Pairs...)
	})
}

func TestClientWSSServerResolve(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	cancel, addr, err := runWSServer(&socksgo.Server{
		Pool: pool,
	}, cfg.Host, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()

	c5 := buildClient("socks5+wss://"+addr.String()+"?tor", t, pool)
	c4a := buildClient("socks4a+wss://"+addr.String()+"?tor", t, pool)

	t.Run("Lookup", func(t *testing.T) {
		testLookup(c5, t, true, cfg.Pairs...)
		testLookup(c5, t, false, cfg.Pairs...)
		testLookup(c4a, t, false, cfg.Pairs...)
	})
}
