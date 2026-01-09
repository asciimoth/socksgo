package socks_test

import (
	"context"
	"os/exec"
	"testing"
	"time"
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

func getShcemes(tls bool, ws bool) (socks5, socks4, socks4a string) {
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
	socks5, socks4, _ := getShcemes(tls, ws)

	killfuncs := []func(){}

	k, err := runGost(
		socks5+"://"+cfg.Addr5+"?udp=true&udpBufferSize=4096&bind=true", t.Context(),
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	killfuncs = append(killfuncs, k)

	k, err = runGost(
		socks5+"://user:pass@"+cfg.Addr5Pass+"?udp=true&udpBufferSize=4096&bind=true", t.Context(),
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	killfuncs = append(killfuncs, k)

	k, err = runGost(
		socks4+"://"+cfg.Addr4+"?bind=true", t.Context(),
	)
	if err != nil {
		t.Fatalf("failed to spawn gost proc: %v", err)
	}
	killfuncs = append(killfuncs, k)

	k, err = runGost(
		socks4+"://user@"+cfg.Addr4Pass+"?bind=true", t.Context(),
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

	// TODO: Avoid RC here
	time.Sleep(time.Millisecond * time.Duration(cfg.RCTimeout)) // Wait for all gost instances to start

	return kill
}

func testIntegrationWithGost(t *testing.T, tls bool, ws bool) {
	cfg := GetEnvConfig()

	kill := runGostAll(t, cfg, tls, ws)
	defer kill()

	socks5, socks4, socks4a := getShcemes(tls, ws)

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
			testUDPListen(c5g, t, 10)
			testUDPListen(c5gp, t, 10)
			// testUDPListen(c5, t, 1)
			// testUDPListen(c5p, t, 1)
		})
	}
}

func TestIntegrationWithGost(t *testing.T) {
	testIntegrationWithGost(t, false, false)
	testIntegrationWithGost(t, true, false)
	testIntegrationWithGost(t, false, true)
	testIntegrationWithGost(t, true, true)
}
