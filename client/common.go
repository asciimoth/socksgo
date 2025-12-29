package client

import (
	"context"
	"errors"
	"net"
	"net/url"
	"slices"
	"strings"
)

var (
	ResolveDisabledErr = errors.New("tor resolve extension for socks is disabled")
)

var networks = map[string]string{
	"tcp":  "ip",
	"tcp4": "ip4",
	"tcp6": "ip6",

	"udp":  "ip",
	"udp4": "ip4",
	"udp6": "ip6",
}

func PassAll(_, _ string) bool {
	return true
}

func DirectLoopback(_, address string) bool {
	if address == "localhost" {
		return false
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return true
	}
	if host == "localhost" {
		return false
	}
	if net.ParseIP(host).IsLoopback() {
		return false
	}
	return true
}

type Client interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
	Listen(ctx context.Context, network, address string) (net.Listener, error)

	DialPacket(ctx context.Context, network, address string) (net.PacketConn, error)
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)

	LookupIP(ctx context.Context, network, address string) ([]net.IP, error)
	LookupAddr(ctx context.Context, address string) ([]string, error)
}

// TODO: Test
func parseSheme(scheme string) (base string, tls, ws bool) {
	parts := strings.Split(strings.TrimSpace(strings.ToLower(scheme)), "+")
	for _, p := range []string{"socks", "socks5", "socks5h"} {
		if slices.Contains(parts, p) {
			base = "5"
		}
	}
	for _, p := range []string{"sockss", "socks5s", "socks5hs"} {
		if slices.Contains(parts, p) {
			base = "5"
			tls = true
		}
	}
	if slices.Contains(parts, "socks4") {
		base = "4"
	}
	if slices.Contains(parts, "socks4s") {
		base = "4"
		tls = true
	}
	if slices.Contains(parts, "socks4a") {
		base = "4a"
	}
	if slices.Contains(parts, "socks4as") {
		base = "4a"
		tls = true
	}
	if slices.Contains(parts, "tls") {
		tls = true
	}
	if slices.Contains(parts, "ws") {
		ws = true
	}
	if slices.Contains(parts, "wss") {
		ws = true
		tls = true
	}
	return
}

// TODO: Document url options
func ClientFomURLObj(u *url.URL, mods ...ConfigMod) (Client, error) {
	base, isTls, isWs := parseSheme(u.Scheme)

	wsUrl := ""
	if isWs {
		wsu := url.URL{
			Scheme: "ws",
			Host:   u.Host,
			Path:   "/ws", // For gost compat
		}
		if u.Path != "" {
			wsu.Path = u.Path
		}
		if isTls {
			wsu.Scheme = "wss"
		}
		wsUrl = wsu.String()
	}

	if base == "5" {
		cfg, err := configFromURL(u, nil)
		if err != nil {
			// TODO: Better error
			return nil, err
		}
		cfg.WebSocketURL = wsUrl
		if isTls {
			cfg.TLS = true
		}
		cfg.apply(mods...)
		return &Client5{
			Config: cfg,
		}, nil
	}

	if base == "4" || base == "4a" {
		def := &Config{}
		if base == "4" {
			def.LocalResolve = true
		}
		cfg, err := configFromURL(u, def)
		if err != nil {
			// TODO: Better error
			return nil, err
		}
		cfg.WebSocketURL = wsUrl
		if isTls {
			cfg.TLS = true
		}
		cfg.apply(mods...)
		return &client4ToClientWrapper{
			Client4: Client4{
				Config: cfg,
			},
		}, nil
	}

	// TODO: Better error
	return nil, errors.New("unknown scheme: " + u.Scheme)
}

// TODO: Document url options
func ClientFomURL(urlstr string, mods ...ConfigMod) (Client, error) {
	u, err := url.Parse(urlstr)
	if err != nil {
		// TODO: Better error
		return nil, err
	}

	return ClientFomURLObj(u, mods...)
}
