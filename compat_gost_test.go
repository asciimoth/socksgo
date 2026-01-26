//// go:build gost

package socksgo_test

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/asciimoth/bufpool"
)

// runGost("socks5://user:pass@:1080")
func runGost(url string, t *testing.T) (func(), error) {
	t.Log("Launching gost for", url)
	ctx := t.Context()
	cmd := exec.CommandContext(ctx, "gost", "-L", url)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start gost: %w", err)
	}

	lines := make(chan string, 256) // buffered so scanners won't block the process quickly
	errc := make(chan error, 2)     // buffer to avoid goroutine leak on send
	var wg sync.WaitGroup

	// scanner goroutine for a reader
	scan := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			text := sc.Text()
			t.Log(text)
			select {
			case lines <- text:
				// delivered
			default:
				// channel full — drop line to avoid blocking (shouldn't happen in normal tests)
			}
		}
		if err := sc.Err(); err != nil {
			errc <- fmt.Errorf("scanner error: %w", err)
		}
	}

	wg.Add(2)
	go scan(stdout)
	go scan(stderr)

	// wait for process exit in background
	go func() {
		if err := cmd.Wait(); err != nil {
			errc <- fmt.Errorf("gost exited: %w", err)
		} else {
			errc <- fmt.Errorf("gost exited")
		}
	}()

	// watch lines / errors / ctx
	for {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			wg.Wait()
			return nil, ctx.Err()
		case e := <-errc:
			// process exited or reader error before we saw "listening on"
			wg.Wait()
			return nil, e
		case l := <-lines:
			// check for "listening on" (case-insensitive). This covers both JSON logs with msg and plain logs.
			if strings.Contains(strings.ToLower(l), "listening on") {
				cleanup := func() {
					// best-effort kill; ignore kill error here and wait for goroutines to finish
					_ = cmd.Process.Kill()
					wg.Wait()
				}
				return cleanup, nil
			}
		}
	}
}

func getSchemes(tls bool, ws bool) (socks5, socks4, socks4a string) {
	socks5 = "socks5"
	socks4 = "socks4"
	socks4a = "socks4a"
	if ws {
		socks5 = "socks5+ws"
		socks4 = "socks4+ws"
		socks4a = "socks4a+ws"
		if tls {
			socks5 = "socks5+wss"
			socks4 = "socks4+wss"
			socks4a = "socks4a+wss"
		}
	} else {
		if tls {
			socks5 = "socks5+tls"
			socks4 = "socks4+tls"
			socks4a = "socks4a+tls"
		}
	}
	return
}

func runGostAll(t *testing.T, cfg EnvConfig, tls bool, ws bool) func() {
	socks5, socks4, _ := getSchemes(tls, ws)

	killfuncs := []func(){}

	k, err := runGost(
		socks5+"://"+cfg.Addr5+"?udp=true&udpBufferSize=4096&bind=true", t,
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	killfuncs = append(killfuncs, k)

	k, err = runGost(
		socks5+"://user:pass@"+cfg.Addr5Pass+"?udp=true&udpBufferSize=4096&bind=true", t,
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	killfuncs = append(killfuncs, k)

	k, err = runGost(
		socks4+"://"+cfg.Addr4+"?bind=true", t,
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	killfuncs = append(killfuncs, k)

	k, err = runGost(
		socks4+"://user@"+cfg.Addr4Pass+"?bind=true", t,
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

	return kill
}

func testGostCompat(t *testing.T, tls bool, ws bool) {
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	cfg := GetEnvConfig()

	kill := runGostAll(t, cfg, tls, ws)
	defer kill()

	socks5, socks4, socks4a := getSchemes(tls, ws)

	c5g := buildClient(socks5+"://"+cfg.Addr5+"?gost", t, pool)
	c5gp := buildClient(socks5+"://user:pass@"+cfg.Addr5Pass+"?gost", t, pool)
	c5 := buildClient(socks5+"://"+cfg.Addr5, t, pool)
	c5p := buildClient(socks5+"://user:pass@"+cfg.Addr5Pass, t, pool)

	c4 := buildClient(socks4+"://"+cfg.Addr4, t, pool)
	c4p := buildClient(socks4+"://user@"+cfg.Addr4Pass, t, pool)
	c4a := buildClient(socks4a+"://"+cfg.Addr4, t, pool)
	c4ap := buildClient(socks4a+"://user@"+cfg.Addr4Pass, t, pool)

	t.Run("Http Request Socks5 gost", func(t *testing.T) {
		testDial(c5g, t, cfg.Pairs...)
	})
	t.Run("Http Request Socks5 gost pass", func(t *testing.T) {
		testDial(c5gp, t, cfg.Pairs...)
	})
	t.Run("Http Request Socks5", func(t *testing.T) {
		testDial(c5, t, cfg.Pairs...)
	})
	t.Run("Http Request Socks5 pass", func(t *testing.T) {
		testDial(c5p, t, cfg.Pairs...)
	})
	t.Run("Http Request Socks4", func(t *testing.T) {
		testDial(c4, t, cfg.Pairs...)
	})
	t.Run("Http Request Socks4 pass", func(t *testing.T) {
		testDial(c4p, t, cfg.Pairs...)
	})
	t.Run("Http Request Socks4a", func(t *testing.T) {
		testDial(c4a, t, cfg.Pairs...)
	})
	t.Run("Http Request Socks4a pass", func(t *testing.T) {
		testDial(c4ap, t, cfg.Pairs...)
	})

	if !tls {
		t.Run("DNS Request socks5 gost", func(t *testing.T) {
			testUDPDial(c5g, t, cfg.Pairs...)
		})
		t.Run("DNS Request socks5 gost pass", func(t *testing.T) {
			testUDPDial(c5gp, t, cfg.Pairs...)
		})
		t.Run("DNS Request socks5", func(t *testing.T) {
			testUDPDial(c5, t, cfg.Pairs...)
		})
		t.Run("DNS Request socks5 pass", func(t *testing.T) {
			testUDPDial(c5p, t, cfg.Pairs...)
		})
	}

	t.Run("Listen socks5 gost", func(t *testing.T) {
		testListen(c5g, t, 10)
	})
	t.Run("Listen socks5 gost pass", func(t *testing.T) {
		testListen(c5gp, t, 10)
	})
	t.Run("Listen socks5", func(t *testing.T) {
		testListen(c5, t, 1)
	})
	t.Run("Listen socks5 pass", func(t *testing.T) {
		testListen(c5p, t, 1)
	})

	if !tls {
		t.Run("Listen UDP socks5 gost", func(t *testing.T) {
			testUDPListen(c5g, t, 10, false)
		})
		t.Run("Listen UDP socks5 gost pass", func(t *testing.T) {
			testUDPListen(c5gp, t, 10, false)
		})
		t.Run("Listen UDP socks5", func(t *testing.T) {
			testUDPListen(c5, t, 10, true)
		})
		t.Run("Listen UDP socks5 pass", func(t *testing.T) {
			testUDPListen(c5p, t, 10, true)
		})
	}
}

func TestGostCompat(t *testing.T) {
	t.Run("notls+nows", func(t *testing.T) {
		testGostCompat(t, false, false)
	})
	t.Run("tls+nows", func(t *testing.T) {
		testGostCompat(t, true, false)
	})
	t.Run("notls+ws", func(t *testing.T) {
		testGostCompat(t, false, true)
	})
	t.Run("tls+ws", func(t *testing.T) {
		testGostCompat(t, true, true)
	})
}
