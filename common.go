package socksgo

import (
	"context"
	"errors"
	"net"
	"path"
	"strings"

	"github.com/asciimoth/socksgo/protocol"
)

// supportedNetworks lists network types that can be used with Dial/Listen.
var supportedNetworks = map[string]any{
	"tcp":  nil,
	"tcp4": nil,
	"tcp6": nil,

	"udp":  nil,
	"udp4": nil,
	"udp6": nil,
}

// PacketConn is a combined interface for UDP packet connections.
// It embeds both net.PacketConn and net.Conn for full duplex communication.
type PacketConn interface {
	net.PacketConn
	net.Conn
}

// Dialer is a function type for establishing TCP connections.
// It matches the signature of net.Dialer.DialContext.
type Dialer = func(ctx context.Context, network, address string) (net.Conn, error)

// PacketDialer is a function type for establishing UDP packet connections.
type PacketDialer = func(ctx context.Context, network, address string) (PacketConn, error)

// Listener is a function type for creating TCP listeners.
type Listener = func(ctx context.Context, network, address string) (net.Listener, error)

// PacketListener is a function type for creating UDP packet listeners.
type PacketListener = func(ctx context.Context, network, address string) (PacketConn, error)

// Resolver provides DNS lookup capabilities.
// It matches the interface of net.Resolver.
type Resolver interface {
	LookupIP(ctx context.Context, network, address string) ([]net.IP, error)
	LookupAddr(ctx context.Context, address string) ([]string, error)
}

// Filter determines whether an address should bypass the proxy and use direct connection.
// Return true to use direct connection, false to route through proxy.
// network may be "" if unknown.
//
// Filters are used with the Client.Filter field and server address filters.
// Use BuildFilter() to create filters from no_proxy-style strings.
type Filter = func(network, address string) bool

// PassAllFilter is a Filter that always returns false.
// All connections will use the proxy (none bypass to direct connection).
func PassAllFilter(_, _ string) bool {
	return false
}

// MatchAllFilter is a Filter that always returns true.
// All connections bypass the proxy and use direct connection.
func MatchAllFilter(_, _ string) bool {
	return true
}

// LoopbackFilter returns true for localhost and loopback addresses.
// Use this filter to route local traffic directly while sending
// external traffic through the proxy.
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

// BuildFilter creates a Filter from a comma-separated string similar to the
// NO_PROXY environment variable format.
//
// Each entry can be:
//   - host:port - matches this host and port combination
//   - host - matches this host on any port
//   - ip - matches this exact IP address
//   - ip/subnet - matches any IP in this CIDR subnet
//   - Wildcards (*, ?) are supported in host patterns using shell glob matching
//
// Examples:
//   - "localhost,127.0.0.1" - bypass for localhost and IPv4 loopback
//   - "*.example.com" - bypass for all subdomains of example.com
//   - "192.168.0.0/16" - bypass for entire 192.168.x.x subnet
//   - "internal.corp:8080" - bypass for specific host:port
//
// The filter is case-insensitive and handles both bracketed IPv6 addresses
// (e.g., [::1]:8080) and trailing dots in hostnames.
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

func errorToReplyStatus(err error) protocol.ReplyStatus {
	if err == nil {
		return protocol.SuccReply
	}

	// Unwrap to get to the underlying error
	var unwrapped = err
	for {
		u := errors.Unwrap(unwrapped)
		if u == nil {
			break
		}
		unwrapped = u
	}

	// Check for specific error types
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		err = opErr
		unwrapped = opErr.Err
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return protocol.HostUnreachReply
	}

	// Check error message for known patterns
	errStr := unwrapped.Error()
	if strings.Contains(errStr, "connection refused") {
		return protocol.ConnRefusedReply
	}
	if strings.Contains(errStr, "network unreachable") {
		return protocol.NetUnreachReply
	}
	if strings.Contains(errStr, "host unreachable") {
		return protocol.HostUnreachReply
	}
	if strings.Contains(errStr, "connection timed out") ||
		strings.Contains(errStr, "i/o timeout") {
		return protocol.TTLExpiredReply
	}
	if strings.Contains(errStr, "permission denied") {
		return protocol.DisallowReply
	}

	// Default to general failure
	return protocol.FailReply
}
