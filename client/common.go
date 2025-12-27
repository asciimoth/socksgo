package client

import (
	"context"
	"errors"
	"net"
	"net/url"
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
	DialWithConn(ctx context.Context, network, address string, conn net.Conn) (net.Conn, error)
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	ListenWithConn(ctx context.Context, network, address string, conn net.Conn) (net.Listener, error)

	DialPacket(ctx context.Context, network, address string) (net.PacketConn, error)
	DialPacketWithConn(ctx context.Context, network, address string, conn net.Conn) (net.PacketConn, error)
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
	ListenPacketWithConn(ctx context.Context, network, address string, conn net.Conn) (net.PacketConn, error)

	LookupIP(ctx context.Context, network, address string) ([]net.IP, error)
	LookupIPWithConn(ctx context.Context, network, address string, conn net.Conn) ([]net.IP, error)
	LookupAddr(ctx context.Context, address string) ([]string, error)
	LookupAddrWithConn(ctx context.Context, address string, conn net.Conn) ([]string, error)
}

// TODO: Document url options
func ClientFomURLObj(u *url.URL, mods ...ConfigMod) (Client, error) {
	scheme := strings.ToLower(u.Scheme)

	if scheme == "socks" || scheme == "socks5" || scheme == "socks5h" {
		cfg, err := configFromURL(u, nil)
		if err != nil {
			// TODO: Better error
			return nil, err
		}
		cfg.apply(mods...)
		return &Client5{
			Config: cfg,
		}, nil
	}

	if scheme == "socks4" || scheme == "socks4a" {
		def := &Config{}
		if scheme == "socks4" {
			def.LocalResolve = true
		}
		cfg, err := configFromURL(u, def)
		if err != nil {
			// TODO: Better error
			return nil, err
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
