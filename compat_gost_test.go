//go:build compattest

package socksgo_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/asciimoth/bufpool"
)

// runGost("socks5://user:pass@:1080")
func runGost(url, chain string, t *testing.T) (func(), string, error) {
	t.Log("Launching gost for", url)
	ctx := t.Context()
	args := []string{"-L", url}
	if chain != "" {
		args = append(args, "-F", chain)
	}
	cmd := exec.CommandContext(ctx, "gost", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, "", fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, "", fmt.Errorf("start gost: %w", err)
	}

	lines := make(
		chan string,
		256,
	) // buffered so scanners won't block the process quickly
	errc := make(chan error, 2) // buffer to avoid goroutine leak on send
	var wg sync.WaitGroup

	// scanner goroutine for a reader
	scan := func(r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			text := sc.Text()
			// t.Log(text)
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

	// regex to find host:port (handles bracketed IPv6 like [::1]:8080)
	reAddr := regexp.MustCompile(
		`(\[[0-9a-fA-F:]+\]:\d+)|([0-9A-Za-z\.\-]+:\d+)`,
	)
	cleanAddr := func(s string) string {
		// strip trailing /tcp or /udp if present
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, "/tcp")
		s = strings.TrimSuffix(s, "/udp")
		return s
	}

	tryExtract := func(line string) (string, bool) {
		// try JSON first
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err == nil {
			// 1) "local" field (common in gost logs)
			if v, ok := m["local"].(string); ok && v != "" {
				return cleanAddr(v), true
			}
			// 2) "msg" field that may contain "listening on ..."
			if v, ok := m["msg"].(string); ok &&
				strings.Contains(strings.ToLower(v), "listening on") {
				if found := reAddr.FindString(v); found != "" {
					return cleanAddr(found), true
				}
			}
		}

		// plain text search: look for "listening on" then regex
		if strings.Contains(strings.ToLower(line), "listening on") ||
			strings.Contains(strings.ToLower(line), "listening") {
			if found := reAddr.FindString(line); found != "" {
				return cleanAddr(found), true
			}
		}

		// last resort: any address-like token in the line (but require word "listen" or "listening" nearby to avoid false positives)
		if found := reAddr.FindString(line); found != "" {
			// be conservative: accept this only if the line seems to indicate a listener
			lower := strings.ToLower(line)
			if strings.Contains(lower, "listen") ||
				strings.Contains(lower, "listening") ||
				strings.Contains(lower, "listening on") {
				return cleanAddr(found), true
			}
		}

		return "", false
	}

	// watch lines / errors / ctx
	for {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			wg.Wait()
			return nil, "", ctx.Err()
		case e := <-errc:
			// process exited or reader error before we saw "listening on"
			wg.Wait()
			return nil, "", e
		case l := <-lines:
			if addr, ok := tryExtract(l); ok {
				cleanup := func() {
					// best-effort kill and wait
					_ = cmd.Process.Kill()
					wg.Wait()
				}
				return cleanup, addr, nil
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

type GostAddrs struct {
	Addr5, Addr5Pass, Addr4, Addr4Pass string
}

func runGostAll(
	t *testing.T,
	cfg EnvConfig,
	tls bool,
	ws bool,
) (func(), GostAddrs) {
	socks5, socks4, _ := getSchemes(tls, ws)

	killfuncs := []func(){}

	k, addr5, err := runGost(
		socks5+"://"+cfg.Host+":?udp=true&udpBufferSize=4096&bind=true", "", t,
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	fmt.Println(addr5)
	killfuncs = append(killfuncs, k)

	k, addr5pass, err := runGost(
		socks5+"://user:pass@"+cfg.Host+":?udp=true&udpBufferSize=4096&bind=true",
		"",
		t,
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	fmt.Println(addr5pass)
	killfuncs = append(killfuncs, k)

	k, addr4, err := runGost(
		socks4+"://"+cfg.Host+":?bind=true", "", t,
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	fmt.Println(addr4)
	killfuncs = append(killfuncs, k)

	k, addr4pass, err := runGost(
		socks4+"://user@"+cfg.Host+":?bind=true", "", t,
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	fmt.Println(addr4pass)
	killfuncs = append(killfuncs, k)

	kill := func() {
		for _, kf := range killfuncs {
			kf()
		}
	}

	return kill, GostAddrs{
		Addr5:     addr5,
		Addr5Pass: addr5pass,
		Addr4:     addr4,
		Addr4Pass: addr4pass,
	}
}

func testGostCompat(t *testing.T, tls bool, ws bool) {
	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	cfg := GetEnvConfig()

	kill, gaddr := runGostAll(t, cfg, tls, ws)
	defer kill()

	socks5, socks4, socks4a := getSchemes(tls, ws)

	c5g := buildClient(socks5+"://"+gaddr.Addr5+"?gost", t, pool)
	c5gp := buildClient(socks5+"://user:pass@"+gaddr.Addr5Pass+"?gost", t, pool)
	c5 := buildClient(socks5+"://"+gaddr.Addr5, t, pool)
	c5p := buildClient(socks5+"://user:pass@"+gaddr.Addr5Pass, t, pool)

	c4 := buildClient(socks4+"://"+gaddr.Addr4, t, pool)
	c4p := buildClient(socks4+"://user@"+gaddr.Addr4Pass, t, pool)
	c4a := buildClient(socks4a+"://"+gaddr.Addr4, t, pool)
	c4ap := buildClient(socks4a+"://user@"+gaddr.Addr4Pass, t, pool)

	t.Run("Http Request", func(t *testing.T) {
		t.Run("socks5 gost", func(t *testing.T) {
			t.Parallel()
			testDial(c5g, t, cfg.Pairs...)
		})
		t.Run("socks5 gost pass", func(t *testing.T) {
			t.Parallel()
			testDial(c5gp, t, cfg.Pairs...)
		})
		t.Run("socks5", func(t *testing.T) {
			t.Parallel()
			testDial(c5, t, cfg.Pairs...)
		})
		t.Run("socks5 pass", func(t *testing.T) {
			t.Parallel()
			testDial(c5p, t, cfg.Pairs...)
		})
		t.Run("socks4", func(t *testing.T) {
			t.Parallel()
			testDial(c4, t, cfg.Pairs...)
		})
		t.Run("socks4 pass", func(t *testing.T) {
			t.Parallel()
			testDial(c4p, t, cfg.Pairs...)
		})
		t.Run("cocks4a", func(t *testing.T) {
			t.Parallel()
			testDial(c4a, t, cfg.Pairs...)
		})
		t.Run("socks4a pass", func(t *testing.T) {
			t.Parallel()
			testDial(c4ap, t, cfg.Pairs...)
		})
	})

	if !tls {
		t.Run("DNS Request", func(t *testing.T) {
			t.Run("socks5 gost", func(t *testing.T) {
				t.Parallel()
				testUDPDial(c5g, t, cfg.Pairs...)
			})
			t.Run("socks5 gost pass", func(t *testing.T) {
				t.Parallel()
				testUDPDial(c5gp, t, cfg.Pairs...)
			})
			t.Run("socks5", func(t *testing.T) {
				t.Parallel()
				testUDPDial(c5, t, cfg.Pairs...)
			})
			t.Run("socks5 pass", func(t *testing.T) {
				t.Parallel()
				testUDPDial(c5p, t, cfg.Pairs...)
			})
		})
	}

	t.Run("Listen", func(t *testing.T) {
		t.Run("socks5 gost", func(t *testing.T) {
			t.Parallel()
			testListen(c5g, t, 10)
		})
		t.Run("socks5 gost pass", func(t *testing.T) {
			t.Parallel()
			testListen(c5gp, t, 10)
		})
		t.Run("socks5", func(t *testing.T) {
			t.Parallel()
			testListen(c5, t, 1)
		})
		t.Run("socks5 pass", func(t *testing.T) {
			t.Parallel()
			testListen(c5p, t, 1)
		})
	})

	if !tls {
		t.Run("Listen UDP", func(t *testing.T) {
			t.Run("socks5 gost", func(t *testing.T) {
				t.Parallel()
				testUDPListen(c5g, t, 10)
			})
			t.Run("socks5 gost pass", func(t *testing.T) {
				t.Parallel()
				testUDPListen(c5gp, t, 10)
			})
			t.Run("socks5", func(t *testing.T) {
				t.Parallel()
				testUDPListen(c5, t, 10)
			})
			t.Run("socks5 pass", func(t *testing.T) {
				t.Parallel()
				testUDPListen(c5p, t, 10)
			})
		})
	}
}

func TestGostCompat(t *testing.T) {
	t.Parallel()
	t.Run("notls+nows", func(t *testing.T) {
		t.Parallel()
		testGostCompat(t, false, false)
	})
	t.Run("tls+nows", func(t *testing.T) {
		t.Parallel()
		testGostCompat(t, true, false)
	})
	t.Run("notls+ws", func(t *testing.T) {
		t.Parallel()
		testGostCompat(t, false, true)
	})
	t.Run("tls+ws", func(t *testing.T) {
		t.Parallel()
		testGostCompat(t, true, true)
	})
}
