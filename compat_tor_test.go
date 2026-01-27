//go:build compattest

package socksgo_test

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo"
)

func torResolve(t *testing.T, v string, proxy, req string, rev bool) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, err := exec.LookPath("curl"); err != nil {
		t.Fatalf("curl binary not found in PATH: %v", err)
	}

	args := []string{"-" + v, req, proxy}
	if rev {
		args = []string{"-" + v, "-x", req, proxy}
	}

	cmd := exec.CommandContext(ctx, "tor-resolve", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func runTorResolve(t *testing.T, proxy string, pairs []HostPort, v string) {
	var (
		err error
		ips []string = []string{
			"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
		}
	)

	for _, addr := range pairs {
		var ip string
		ip, err = torResolve(t, v, proxy, addr.Host, false)
		if err == nil {
			ips = append(ips, ip)
			break
		}
	}

	if err != nil {
		t.Fatal(err)
	}

	if v != "5" {
		return
	}

	for _, ip := range ips {
		_, err = torResolve(t, v, proxy, ip, true)
		if err == nil {
			return
		}
	}

	if err != nil {
		t.Fatalf("failed to reverse lookup with tor-resolve %v", err)
	}
}

func TestTorCompat(t *testing.T) {
	t.Parallel()
	pool := bufpool.NewTestDebugPool(t)
	defer pool.Close()

	cfg := GetEnvConfig()

	c5 := buildClient("socks5://"+cfg.Tor+"?tor", t, pool)
	c4a := buildClient("socks4a://"+cfg.Tor+"?tor", t, pool)

	t.Run("HttpRequest", func(t *testing.T) {
		testDial(c5, t, cfg.Pairs...)
		testDial(c4a, t, cfg.Pairs...)
	})

	t.Run("Lookup", func(t *testing.T) {
		testLookup(c5, t, true, cfg.Pairs...)
		testLookup(c4a, t, false, cfg.Pairs...)
	})
}

func TestTorResolve(t *testing.T) {
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
		runTorResolve(t, addr.String(), cfg.Pairs, "5")
		runTorResolve(t, addr.String(), cfg.Pairs, "4")
	})
}
