//go:build compattest

package socksgo_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo"
)

func curlViaSocks(t *testing.T, targetURL, proxyURL string) error {
	t.Helper()

	// Make the test fail quickly if curl is not available.
	if _, err := exec.LookPath("curl"); err != nil {
		t.Fatalf("curl binary not found in PATH: %v", err)
	}

	// Use a context timeout so tests don't hang forever.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Build curl args:
	// -sS      : silent but show errors
	// --fail   : exit non-zero on HTTP 4xx/5xx
	// -L       : follow redirects
	// --proxy  : supply full proxy URL (including scheme)
	// -o <devnull> : discard response body
	args := []string{
		"-sS",
		"--fail",
		"-L",
		"--proxy", proxyURL,
		"-o", os.DevNull,
		targetURL,
	}

	cmd := exec.CommandContext(ctx, "curl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// If the context deadline was exceeded, the error may be context.DeadlineExceeded
		// or an ExitError from curl; include both error and output for debugging.
		return fmt.Errorf(
			"curl -> proxy=%q url=%q: err=%v\noutput:\n%s",
			proxyURL,
			targetURL,
			err,
			string(out),
		)
	}
	// success (optionally log something)
	return nil
}

func curlViaSocksList(t *testing.T, targets []string, proxyURL string) {
	var err error
	for _, target := range targets {
		err = curlViaSocks(t, target, proxyURL)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatal(err)
	}
}

func runCurl5Test(t *testing.T, addr string, targets []string) {
	t.Run("socks5", func(t *testing.T) {
		t.Parallel()
		curlViaSocksList(t, targets, "socks5://"+addr)
	})
	t.Run("socks5h", func(t *testing.T) {
		t.Parallel()
		curlViaSocksList(t, targets, "socks5h://"+addr)
	})
	t.Run("socks5 pass", func(t *testing.T) {
		t.Parallel()
		curlViaSocksList(t, targets, "socks5://user:pass@"+addr)
	})
	t.Run("socks5h pass", func(t *testing.T) {
		t.Parallel()
		curlViaSocksList(t, targets, "socks5h://user:pass@"+addr)
	})
}

func runCurl4Test(t *testing.T, addr string, targets []string) {
	t.Run("socks4", func(t *testing.T) {
		t.Parallel()
		curlViaSocksList(t, targets, "socks4://"+addr)
	})
	t.Run("socks4a", func(t *testing.T) {
		t.Parallel()
		curlViaSocksList(t, targets, "socks4a://"+addr)
	})
	t.Run("socks4 user", func(t *testing.T) {
		t.Parallel()
		curlViaSocksList(t, targets, "socks4://user@"+addr)
	})
	t.Run("socks4a user", func(t *testing.T) {
		t.Parallel()
		curlViaSocksList(t, targets, "socks4a://user@"+addr)
	})
}

func TestCurlSocksCompat(t *testing.T) {
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

	t.Run("group", func(t *testing.T) {
		runCurl4Test(t, addr.String(), cfg.CurlURLs)
		runCurl5Test(t, addr.String(), cfg.CurlURLs)
	})
}

func TestCurlGostSocksTlsCompat(t *testing.T) {
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

	gcancel, gaddr, err := runGost(
		"socks5://"+net.JoinHostPort(cfg.Host, ""),
		"socks5+tls://"+addr.String(), t,
	)
	defer gcancel()

	t.Run("group", func(t *testing.T) {
		runCurl5Test(t, gaddr, cfg.CurlURLs)
	})
}

func TestCurlGostSocksWSCompat(t *testing.T) {
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

	gcancel, gaddr, err := runGost(
		"socks5://"+net.JoinHostPort(cfg.Host, ""),
		"socks5+ws://"+addr.String(), t,
	)
	defer gcancel()

	t.Run("group", func(t *testing.T) {
		runCurl5Test(t, gaddr, cfg.CurlURLs)
	})
}

func TestCurlGostSocksWSSCompat(t *testing.T) {
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

	gcancel, gaddr, err := runGost(
		"socks5://"+net.JoinHostPort(cfg.Host, ""),
		"socks5+wss://"+addr.String(), t,
	)
	defer gcancel()

	t.Run("group", func(t *testing.T) {
		runCurl5Test(t, gaddr, cfg.CurlURLs)
	})
}
