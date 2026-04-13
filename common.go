package socksgo

import (
	"errors"
	"net"
	"strings"

	"github.com/asciimoth/gonnect"
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
//
// Deprecated: Use gonnect.FilterFromString(str).Filter instead.
func BuildFilter(str string) gonnect.Filter {
	cf := gonnect.FilterFromString(str)
	return cf.Filter
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
