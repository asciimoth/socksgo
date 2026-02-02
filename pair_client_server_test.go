package socksgo_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
	socksgo "github.com/asciimoth/socksgo"
)

/*
 TODO:
- Bind
- Mbind
- UDP Assoc dial
- USP Assoc listen
- x2 for UDP Tun
- Resolve, ResolvePtr with custom resolver
*/

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

func runListen45Tcp(t *testing.T, addr string, tls, ws bool) {
	postfix := buildSocksPostfix(tls, ws)
	t.Run("group", func(t *testing.T) {
		t.Run("socks4", func(t *testing.T) {
			t.Parallel()
			client, err := socksgo.ClientFromURL(
				"socks4" + postfix + "://" + addr,
			)
			if err != nil {
				t.Fatal(err)
				return
			}
			testListen(client, t, 1)
		})
		t.Run("socks4 user", func(t *testing.T) {
			t.Parallel()
			client, err := socksgo.ClientFromURL(
				"socks4" + postfix + "://user@" + addr,
			)
			if err != nil {
				t.Fatal(err)
				return
			}
			testListen(client, t, 1)
		})
		t.Run("socks4a", func(t *testing.T) {
			t.Parallel()
			client, err := socksgo.ClientFromURL(
				"socks4a" + postfix + "://" + addr,
			)
			if err != nil {
				t.Fatal(err)
				return
			}
			testListen(client, t, 1)
		})
		t.Run("socks4a user", func(t *testing.T) {
			t.Parallel()
			client, err := socksgo.ClientFromURL(
				"socks4a" + postfix + "://user@" + addr,
			)
			if err != nil {
				t.Fatal(err)
				return
			}
			testListen(client, t, 1)
		})

		t.Run("socks5", func(t *testing.T) {
			t.Parallel()
			client, err := socksgo.ClientFromURL(
				"socks5" + postfix + "://" + addr,
			)
			if err != nil {
				t.Fatal(err)
				return
			}
			testListen(client, t, 1)
		})
		t.Run("socks5 pass", func(t *testing.T) {
			t.Parallel()
			client, err := socksgo.ClientFromURL(
				"socks5" + postfix + "://user:pass@" + addr,
			)
			if err != nil {
				t.Fatal(err)
				return
			}
			testListen(client, t, 1)
		})

		t.Run("socks5 gost", func(t *testing.T) {
			t.Parallel()
			client, err := socksgo.ClientFromURL(
				"socks5" + postfix + "://" + addr + "?gost",
			)
			if err != nil {
				t.Fatal(err)
				return
			}
			testListen(client, t, 10)
		})
		t.Run("socks5 pass gost", func(t *testing.T) {
			t.Parallel()
			client, err := socksgo.ClientFromURL(
				"socks5" + postfix + "://user:pass@" + addr + "?gost",
			)
			if err != nil {
				t.Fatal(err)
				return
			}
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

	runListen45Tcp(t, addr.String(), false, false)
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

	runListen45Tcp(t, addr.String(), true, false)
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

	runListen45Tcp(t, addr.String(), false, true)
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

	runListen45Tcp(t, addr.String(), true, true)
}
