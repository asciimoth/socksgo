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

func testIntegrationWithGost(t *testing.T, tls bool, ws bool) {
	cfg := GetEnvConfig()

	kill := runGostAll(t, cfg, tls, ws)
	defer kill()

	socks5, socks4, socks4a := getSchemes(tls, ws)

	c5g := buildClient(socks5+"://"+cfg.Addr5+"?gost", t)
	c5gp := buildClient(socks5+"://user:pass@"+cfg.Addr5Pass+"?gost", t)
	c5 := buildClient(socks5+"://"+cfg.Addr5, t)
	c5p := buildClient(socks5+"://user:pass@"+cfg.Addr5Pass, t)

	c4 := buildClient(socks4+"://"+cfg.Addr4, t)
	c4p := buildClient(socks4+"://user@"+cfg.Addr4Pass, t)
	c4a := buildClient(socks4a+"://"+cfg.Addr4, t)
	c4ap := buildClient(socks4a+"://user@"+cfg.Addr4Pass, t)

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

	if !tls {
		t.Run("DNSRequest", func(t *testing.T) {
			testUDPDial(c5g, t, cfg.Pairs...)
			// testUDPDial(c5gp, t, cfg.Pairs...)
			testUDPDial(c5, t, cfg.Pairs...)
			// testUDPDial(c5p, t, cfg.Pairs...)
		})
	}

	t.Run("Listen", func(t *testing.T) {
		testListen(c5g, t, 10)
		testListen(c5gp, t, 10)
		testListen(c5, t, 1)
		testListen(c5p, t, 1)
	})

	if !tls {
		t.Run("ListenUDP", func(t *testing.T) {
			testUDPListen(c5g, t, 10, false)
			testUDPListen(c5gp, t, 10, false)
			testUDPListen(c5, t, 1, true)
			testUDPListen(c5p, t, 1, true)
		})
	}
}

func TestIntegrationWithGost(t *testing.T) {
	testIntegrationWithGost(t, false, false)
	// testIntegrationWithGost(t, true, false)
	// testIntegrationWithGost(t, false, true)
	// testIntegrationWithGost(t, true, true)
}
