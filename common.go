package socksgo

import (
	"context"
	"net"
	"path"
	"strings"
)

var supportedNetworks = map[string]any{
	"tcp":  nil,
	"tcp4": nil,
	"tcp6": nil,

	"udp":  nil,
	"udp4": nil,
	"udp6": nil,
}

type PacketConn interface {
	net.PacketConn
	net.Conn
}

type Dialer = func(ctx context.Context, network, address string) (net.Conn, error)

type PacketDialer = func(ctx context.Context, network, address string) (PacketConn, error)

type Listener = func(ctx context.Context, network, address string) (net.Listener, error)

type PacketListener = func(ctx context.Context, network, address string) (PacketConn, error)
type Resolver interface {
	LookupIP(ctx context.Context, network, address string) ([]net.IP, error)
	LookupAddr(ctx context.Context, address string) ([]string, error)
}

// Client side connection filter.
// Return true if direct Dial/Listen function should be called instead of
// passing it to proxy.
// Return false if proxy should be used.
// network may be "" if it is unknown.
type Filter = func(network, address string) bool

// Always returns false
func PassAllFilter(_, _ string) bool {
	return false
}

// Always returns true
func MatchAllFilter(_, _ string) bool {
	return true
}

// Return true for "localhost" and loopback ip addrs
func LoopbackFilter(_, address string) bool {
	if address == "localhost" {
		return true
	}
	if net.ParseIP(address).IsLoopback() {
		return true
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	if net.ParseIP(host).IsLoopback() {
		return true
	}
	return false
}

// Builds new filter from coma delimited entry list as
// format widely used in no_proxy env var.
// Each entry can be
// - host:port
// - host - for any port on this host
// - ip
// - ip/subnet - for any ip in this subnet
//
// In hosts wildcards can be used
func BuildFilter(str string) Filter {
	type hostEntry struct {
		pattern string // wildcard pattern, lowercased, no trailing dot
		hasPort bool
		port    string
	}
	type ipEntry struct {
		ip      net.IP
		hasPort bool
		port    string
	}
	var hosts []hostEntry
	var ips []ipEntry
	var cidrs []*net.IPNet

	// parse entries
	for raw := range strings.SplitSeq(str, ",") {
		e := strings.TrimSpace(raw)

		// Try CIDR
		if strings.Contains(e, "/") {
			if _, ipnet, err := net.ParseCIDR(e); err == nil {
				cidrs = append(cidrs, ipnet)
				continue
			}
			// fallthrough if not valid CIDR
		}

		// Try plain IP (v4 or v6) without port
		if ip := net.ParseIP(e); ip != nil {
			ips = append(ips, ipEntry{ip: ip, hasPort: false})
			continue
		}

		// Try split host:port (handles bracketed IPv6)
		if host, port, err := net.SplitHostPort(e); err == nil {
			// host part might be IP or pattern/hostname
			host = trimDot(strings.ToLower(host))
			if ip := net.ParseIP(host); ip != nil {
				ips = append(ips, ipEntry{ip: ip, hasPort: true, port: port})
			} else {
				hosts = append(
					hosts,
					hostEntry{pattern: host, hasPort: true, port: port},
				)
			}
			continue
		}

		// Finally treat as host pattern (may include wildcards)
		if e != "" {
			patt := trimDot(strings.ToLower(e))
			hosts = append(hosts, hostEntry{pattern: patt, hasPort: false})
		}
	}

	// filter function
	return func(network, address string) bool {
		// normalize host and port from address input
		var host string
		var port string

		// Try to split host:port using net.SplitHostPort (will handle [::1]:80)
		if h, p, err := net.SplitHostPort(address); err == nil {
			host, port = h, p
		} else {
			host = address
			port = ""
		}

		// normalize host for comparisons
		normHost := trimDot(strings.ToLower(host))

		// Try parse host as IP
		if ip := net.ParseIP(strings.Trim(normHost, "[]")); ip != nil {
			// match exact IP entries
			for _, e := range ips {
				if e.ip.Equal(ip) {
					if !e.hasPort || e.port == port {
						return true
					}
				}
			}
			// match CIDR entries
			for _, n := range cidrs {
				if n.Contains(ip) {
					return true
				}
			}
			// no host-pattern match for numeric IPs
			return false
		}

		// host is a hostname - match host patterns (with wildcard support)
		for _, h := range hosts {
			// path.Match uses shell-style globs: '*' '?' '[]'
			if ok, _ := path.Match(h.pattern, normHost); ok {
				if !h.hasPort || h.port == port {
					return true
				}
			}
		}
		return false
	}
}

func trimDot(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, ".") {
		s = strings.TrimRight(s, ".")
	}
	return s
}
