package protocol

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/asciimoth/gonnect/helpers"
)

// Address type constants for SOCKS protocol.
//
// These values are used in the ATYP field of SOCKS5 requests/replies
// and in the address encoding of SOCKS4a requests.
const (
	// IP4Addr indicates an IPv4 address (4 bytes).
	// Wire value: 0x01
	IP4Addr AddrType = 0x01

	// IP6Addr indicates an IPv6 address (16 bytes).
	// Wire value: 0x04
	IP6Addr AddrType = 0x04

	// FQDNAddr indicates a fully qualified domain name.
	// Wire value: 0x03
	// The domain name is preceded by a single byte length field.
	FQDNAddr AddrType = 0x03
)

var (
	_ net.Addr = Addr{}
)

// AddrType represents the type of address in the SOCKS protocol.
//
// AddrType is used to encode/decode addresses in SOCKS requests and replies.
// The type determines how the Host field in Addr should be interpreted:
//   - IP4Addr: Host contains 4-byte IPv4 address
//   - IP6Addr: Host contains 16-byte IPv6 address
//   - FQDNAddr: Host contains domain name string
type AddrType uint8

// String returns a human-readable representation of the address type.
// Returns "IPv4 addr", "IPv6 addr", or "fully qualified domain name addr"
// for known types, or "addr type noX" for unknown values.
func (a AddrType) String() string {
	switch a {
	case IP4Addr:
		return "IPv4 addr"
	case IP6Addr:
		return "IPv6 addr"
	case FQDNAddr:
		return "fully qualified domain name addr"
	default:
		return "addr type no" + strconv.Itoa(int(a))
	}
}

// Addr represents a network address in the SOCKS protocol.
//
// Addr is the central type for representing addresses throughout socksgo.
// It can represent IPv4, IPv6, or domain name addresses with an associated
// port and network type.
//
// # Wire Format
//
// SOCKS5 encodes addresses as:
//   - ATYP (1 byte): Address type (IP4Addr=0x01, IP6Addr=0x04, FQDNAddr=0x03)
//   - DST.ADDR (variable): IP address or domain name
//   - DST.PORT (2 bytes): Port number in big-endian order
//
// # Examples
//
//	// Create from IP address
//	addr := protocol.AddrFromIP(net.ParseIP("192.168.1.1"), 8080, "tcp")
//
//	// Create from domain name
//	addr := protocol.AddrFromFQDN("example.com", 443, "tcp")
//
//	// Create from host:port string
//	addr := protocol.AddrFromHostPort("example.com:443", "tcp")
//
//	// Convert to net.TCPAddr
//	tcpAddr := addr.ToTCP()
type Addr struct {
	// Type specifies the address format: IP4Addr, IP6Addr, or FQDNAddr.
	// This determines how the Host field should be interpreted.
	Type AddrType

	// Host contains the address data:
	//   - For IP4Addr: 4-byte IPv4 address
	//   - For IP6Addr: 16-byte IPv6 address
	//   - For FQDNAddr: Domain name as a byte slice
	Host []byte

	// Port is the TCP or UDP port number (0-65535).
	Port uint16

	// NetTyp specifies the network type: "tcp" or "udp".
	// Values like "tcp4", "tcp6", "udp4", "udp6" are normalized to "tcp" or "udp".
	// Empty string is treated as "tcp" in most conversions.
	NetTyp string
}

// AddrFromNetAddr converts a net.Addr to protocol Addr.
//
// This function provides a unified way to convert standard Go network
// addresses to protocol.Addr. It specially handles *net.TCPAddr and
// *net.UDPAddr for efficiency. For other net.Addr implementations,
// it falls back to parsing addr.String() and uses addr.Network()
// as the NetTyp.
//
// # Examples
//
//	tcpAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
//	addr := protocol.AddrFromNetAddr(tcpAddr)
//
//	udpAddr := &net.UDPAddr{IP: net.ParseIP("::1"), Port: 53}
//	addr := protocol.AddrFromNetAddr(udpAddr)
func AddrFromNetAddr(addr net.Addr) Addr {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return AddrFromTCPAddr(tcp)
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		return AddrFromUDPAddr(udp)
	}
	return AddrFromHostPort(
		addr.String(), addr.Network()).WithNetTyp(addr.Network())
}

// AddrFromHostPort creates an Addr from a host:port string and a network name.
//
// Parses a host:port string (e.g., "example.com:8080" or "[::1]:443") and
// creates an Addr with the appropriate Type (IP4Addr, IP6Addr, or FQDNAddr).
//
// If hostport is empty, a suitable wildcard host is chosen based on the
// network:
//   - "tcp6" or "udp6": IPv6 wildcard "[::]:0"
//   - Others: IPv4 wildcard "0.0.0.0:0"
//
// # Examples
//
//	addr := protocol.AddrFromHostPort("example.com:443", "tcp")
//	addr := protocol.AddrFromHostPort("192.168.1.1:8080", "tcp")
//	addr := protocol.AddrFromHostPort("", "tcp6") // Returns [::]:0
func AddrFromHostPort(hostport, network string) Addr {
	if hostport == "" {
		if network == "tcp6" || network == "udp6" {
			hostport = "[::]:0"
		} else {
			hostport = "0.0.0.0:0"
		}
	}
	host, port := helpers.SplitHostPort(network, hostport, 0)
	return AddrFromString(host, port, network)
}

// AddrFromString constructs an Addr from a host string and numeric port.
//
// Examines the host string: if it parses as a valid IP address (IPv4 or IPv6),
// an IP Addr is returned with the appropriate Type. Otherwise, an FQDN Addr
// is returned.
//
// # Examples
//
//	// IP address
//	addr := protocol.AddrFromString("192.168.1.1", 8080, "tcp") // Type: IP4Addr
//	addr := protocol.AddrFromString("::1", 80, "tcp")           // Type: IP6Addr
//
//	// Domain name
//	addr := protocol.AddrFromString("example.com", 443, "tcp") // Type: FQDNAddr
func AddrFromString(host string, port uint16, network string) Addr {
	ip := net.ParseIP(host)
	if ip != nil {
		return AddrFromIP(ip, port, network)
	}
	return AddrFromFQDN(host, port, network)
}

// AddrFromIP returns an Addr representing the provided net.IP and port.
//
// Automatically detects IPv4 vs IPv6 and stores the canonical byte
// representation in Host:
//   - IPv4: 4-byte representation (via ip.To4())
//   - IPv6: 16-byte representation (via ip.To16())
//
// # Examples
//
//	// IPv4
//	addr := protocol.AddrFromIP(net.ParseIP("192.168.1.1"), 8080, "tcp")
//
//	// IPv6
//	addr := protocol.AddrFromIP(net.ParseIP("2001:db8::1"), 443, "tcp")
func AddrFromIP(ip net.IP, port uint16, net string) Addr {
	if ip4 := ip.To4(); ip4 != nil {
		return Addr{
			Type:   IP4Addr,
			Host:   append([]byte{}, []byte(ip4)...),
			Port:   port,
			NetTyp: net,
		}
	}
	ip6 := ip.To16()
	return Addr{
		Type:   IP6Addr,
		Host:   append([]byte{}, []byte(ip6)...),
		Port:   port,
		NetTyp: net,
	}
}

// AddrFromFQDN constructs an FQDN Addr from a domain name string.
//
// If the fqdn argument already contains a port (e.g., "example.com:80"),
// the embedded port will override the provided port argument.
//
// # Examples
//
//	addr := protocol.AddrFromFQDN("example.com", 443, "tcp")
//	addr := protocol.AddrFromFQDN("example.com:8080", 443, "tcp") // Uses port 8080
func AddrFromFQDN(fqdn string, port uint16, net string) Addr {
	fqdn, port = helpers.SplitHostPort(net, fqdn, port)
	return Addr{
		Type:   FQDNAddr,
		Host:   []byte(fqdn),
		Port:   port,
		NetTyp: net,
	}
}

// AddrFromFQDNNoDot constructs an FQDN Addr, trimming any trailing dot from
// the domain name.
//
// This is useful for compatibility with some DNS implementations (such as Tor's
// ResolvePtr).
//
// # Examples
//
//	// Standard FQDN
//	addr := protocol.AddrFromFQDNNoDot("example.com", 443, "tcp")
//
//	// FQDN with trailing dot (from DNS response)
//	addr := protocol.AddrFromFQDNNoDot("example.com.", 443, "tcp") // Trims to "example.com"
func AddrFromFQDNNoDot(fqdn string, port uint16, net string) Addr {
	fqdn, port = helpers.SplitHostPort(net, fqdn, port)
	trimmed := strings.TrimRight(fqdn, ".")
	if len(trimmed) > 0 {
		fqdn = trimmed
	}
	return Addr{
		Type:   FQDNAddr,
		Host:   []byte(fqdn),
		Port:   port,
		NetTyp: net,
	}
}

// AddrFromUDPAddr converts a *net.UDPAddr to protocol Addr.
//
// A nil input yields the zero Addr. Port values outside the valid range
// (0-65535) are clamped to zero. The NetTyp is set to "udp".
//
// # Examples
//
//	udpAddr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
//	addr := protocol.AddrFromUDPAddr(udpAddr)
func AddrFromUDPAddr(u *net.UDPAddr) Addr {
	var a Addr
	if u == nil {
		return a
	}
	var port uint16 = 0
	if u.Port <= 65535 && u.Port >= 0 {
		port = uint16(u.Port)
	}
	a = AddrFromIP(u.IP, port, "udp")
	return a
}

// AddrFromTCPAddr converts a *net.TCPAddr to protocol Addr.
//
// A nil input yields the zero Addr. Port values outside the valid range
// (0-65535) are clamped to zero. The NetTyp is set to "tcp".
//
// # Examples
//
//	tcpAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
//	addr := protocol.AddrFromTCPAddr(tcpAddr)
func AddrFromTCPAddr(t *net.TCPAddr) Addr {
	var a Addr
	if t == nil {
		return a
	}
	var port uint16 = 0
	if t.Port <= 65535 && t.Port >= 0 {
		port = uint16(t.Port)
	}
	a = AddrFromIP(t.IP, port, "tcp")
	return a
}

// AddrFromNetIPAddrPort converts a netip.AddrPort to protocol Addr.
//
// A zero value input yields the zero Addr. The NetTyp is set based
// on the network parameter.
//
// # Examples
//
//	addrPort := netip.MustParseAddrPort("192.168.1.1:8080")
//	addr := protocol.AddrFromNetIPAddrPort(addrPort)
func AddrFromNetIPAddrPort(addrPort netip.AddrPort, network ...string) Addr {
	var a Addr
	if !addrPort.IsValid() {
		return a
	}
	netTyp := "udp"
	if len(network) > 0 && network[0] != "" {
		netTyp = network[0]
	}
	a = AddrFromIP(addrPort.Addr().AsSlice(), addrPort.Port(), netTyp)
	return a
}

// IsUnspecified reports whether the address has an unspecified host.
//
// Returns true for:
//   - Empty Host slice
//   - IPv4 wildcard address (0.0.0.0)
//   - IPv6 wildcard address (::)
//
// Returns false for FQDN addresses unless Host is empty.
//
// # Examples
//
//	addr := protocol.AddrFromHostPort("0.0.0.0:0", "tcp")
//	addr.IsUnspecified() // true
//
//	addr := protocol.AddrFromHostPort("192.168.1.1:8080", "tcp")
//	addr.IsUnspecified() // false
func (a Addr) IsUnspecified() bool {
	if len(a.Host) < 1 {
		return true
	}
	if a.Type == IP4Addr || a.Type == IP6Addr {
		return net.IP(a.Host).IsUnspecified()
	}
	return false
}

// Copy returns a deep copy of the Addr.
//
// Creates a new Addr with all fields copied, including a new slice for Host.
//
// # Examples
//
//	original := protocol.AddrFromHostPort("example.com:443", "tcp")
//	copy := original.Copy()
//	// Modifying original won't affect copy
func (a Addr) Copy() Addr {
	cp := Addr{
		Type:   a.Type,
		NetTyp: a.NetTyp,
		Port:   a.Port,
	}
	if a.Host != nil {
		cp.Host = append(cp.Host, a.Host...)
	}
	return cp
}

// Len returns the length of the Host field in bytes.
//
// Returns:
//   - 4 for IPv4 addresses (IP4Addr)
//   - 16 for IPv6 addresses (IP6Addr)
//   - len(Host) for FQDN addresses (FQDNAddr)
func (a Addr) Len() int {
	switch a.Type {
	case IP4Addr:
		return 4 //nolint mnd
	case IP6Addr:
		return 16 //nolint mnd
	case FQDNAddr:
		return len(a.Host)
	default:
		return len(a.Host)
	}
}

// WithNetTyp returns a copy of the Addr with NetTyp normalized.
//
// Normalizes network type strings:
//   - "tcp4", "tcp6" -> "tcp"
//   - "udp4", "udp6" -> "udp"
//   - Other strings are preserved as-is
//
// # Examples
//
//	addr := protocol.AddrFromHostPort("192.168.1.1:8080", "tcp4")
//	addr = addr.WithNetTyp("tcp4") // NetTyp becomes "tcp"
//
//	addr := protocol.AddrFromHostPort("8.8.8.8:53", "udp")
//	addr = addr.WithNetTyp("udp4") // NetTyp becomes "udp"
func (a Addr) WithNetTyp(nt string) Addr {
	n := a.Copy()
	switch nt {
	case "tcp4", "tcp6":
		n.NetTyp = "tcp"
	case "udp4", "udp6":
		n.NetTyp = "udp"
	default:
		n.NetTyp = nt
	}
	return n
}

// WithDefaultHost returns a copy of Addr where an unspecified host is
// replaced with the provided host.
//
// If the address is already specified (IsUnspecified returns false), it is
// returned unchanged. If the address is unspecified and host is empty,
// the IPv4 wildcard "0.0.0.0" is used.
//
// # Examples
//
//	// Unspecified address with custom host
//	addr := protocol.AddrFromHostPort("0.0.0.0:0", "tcp")
//	addr = addr.WithDefaultHost("127.0.0.1") // Returns 127.0.0.1:0
//
//	// Unspecified address with empty host (uses 0.0.0.0)
//	addr := protocol.AddrFromHostPort("0.0.0.0:8080", "tcp")
//	addr = addr.WithDefaultHost("") // Returns 0.0.0.0:8080
//
//	// Already specified - unchanged
//	addr := protocol.AddrFromHostPort("192.168.1.1:8080", "tcp")
//	addr = addr.WithDefaultHost("127.0.0.1") // Returns 192.168.1.1:8080
func (a Addr) WithDefaultHost(host string) Addr {
	if a.IsUnspecified() {
		if host == "" {
			return AddrFromString("0.0.0.0", a.Port, a.NetTyp)
		} else {
			return AddrFromString(host, a.Port, a.NetTyp)
		}
	}
	var nhost []byte // nil
	if a.Host != nil {
		nhost = append(nhost, a.Host...)
	}
	return Addr{
		Type:   a.Type,
		Host:   nhost,
		Port:   a.Port,
		NetTyp: a.NetTyp,
	}
}

// WithDefaultAddr returns def if it is not nil and the address is
// unspecified, otherwise returns itself.
//
// This is useful for providing a default address when dealing with
// wildcard/unspecified addresses.
//
// # Examples
//
//	defaultAddr := protocol.AddrFromHostPort("127.0.0.1:0", "tcp")
//
//	addr := protocol.AddrFromHostPort("0.0.0.0:0", "tcp")
//	addr = addr.WithDefaultAddr(&defaultAddr) // Returns 127.0.0.1:0
//
//	addr = protocol.AddrFromHostPort("192.168.1.1:8080", "tcp")
//	addr = addr.WithDefaultAddr(&defaultAddr) // Returns 192.168.1.1:8080 (unchanged)
func (a Addr) WithDefaultAddr(def *Addr) Addr {
	if a.IsUnspecified() && def != nil {
		return def.Copy()
	}
	return a
}

// ToIP returns the net.IP representation of the address.
//
// Returns:
//   - IPv4 address (4-byte) for IP4Addr
//   - IPv6 address (16-byte) for IP6Addr
//   - nil for FQDNAddr or unknown types
//
// # Examples
//
//	addr := protocol.AddrFromHostPort("192.168.1.1:8080", "tcp")
//	ip := addr.ToIP() // Returns net.IP{192, 168, 1, 1}
//
//	addr := protocol.AddrFromFQDN("example.com", 443, "tcp")
//	ip := addr.ToIP() // Returns nil
func (a Addr) ToIP() net.IP {
	switch a.Type {
	case IP4Addr:
		return net.IP(a.Host).To4()
	case IP6Addr:
		return net.IP(a.Host).To16()
	case FQDNAddr:
		return nil
	default:
		return nil
	}
}

// ToFQDN returns the textual representation of the address host.
//
// Returns:
//   - IP address string (e.g., "192.168.1.1" or "2001:db8::1") for IP addresses
//   - Domain name string for FQDN addresses
//
// This is useful for formatting the host portion of a host:port string.
//
// # Examples
//
//	addr := protocol.AddrFromHostPort("192.168.1.1:8080", "tcp")
//	host := addr.ToFQDN() // Returns "192.168.1.1"
//
//	addr := protocol.AddrFromFQDN("example.com", 443, "tcp")
//	host := addr.ToFQDN() // Returns "example.com"
func (a Addr) ToFQDN() string {
	if ip := a.ToIP(); ip != nil {
		return ip.String()
	}

	return string(a.Host)
}

// PortStr returns the port as a decimal string.
//
// # Examples
//
//	addr := protocol.AddrFromHostPort("example.com:8080", "tcp")
//	port := addr.PortStr() // Returns "8080"
func (a Addr) PortStr() string {
	return strconv.Itoa(int(a.Port))
}

// ToUDP returns a *net.UDPAddr for IP addresses.
//
// Returns nil for FQDN addresses since UDP connections require IP addresses.
//
// # Examples
//
//	addr := protocol.AddrFromHostPort("8.8.8.8:53", "udp")
//	udpAddr := addr.ToUDP() // Returns &net.UDPAddr{IP: ..., Port: 53}
func (a Addr) ToUDP() *net.UDPAddr {
	if ip := a.ToIP(); ip != nil {
		return &net.UDPAddr{
			IP:   ip,
			Port: int(a.Port),
		}
	}
	return nil
}

// ToTCP returns a *net.TCPAddr for IP addresses.
//
// Returns nil for FQDN addresses since TCP connections require IP addresses.
//
// # Examples
//
//	addr := protocol.AddrFromHostPort("192.168.1.1:8080", "tcp")
//	tcpAddr := addr.ToTCP() // Returns &net.TCPAddr{IP: ..., Port: 8080}
func (a Addr) ToTCP() *net.TCPAddr {
	if ip := a.ToIP(); ip != nil {
		return &net.TCPAddr{
			IP:   ip,
			Port: int(a.Port),
		}
	}
	return nil
}

// ToUnspecified returns a new Addr with the same Type and NetTyp but with
// an unspecified host and zero port.
//
// Returns:
//   - For IP4Addr: Host set to 0.0.0.0
//   - For IP6Addr: Host set to ::
//   - For FQDNAddr: Host remains nil
//
// This is useful for creating reply addresses or wildcard addresses.
func (a Addr) ToUnspecified() Addr {
	n := Addr{
		Type:   a.Type,
		NetTyp: a.NetTyp,
	}
	switch a.Type {
	case IP6Addr:
		n.Host = net.IPv6unspecified.To16()
	case IP4Addr:
		n.Host = net.IPv4zero.To4()
	case FQDNAddr:
		return n
	}
	return n
}

// ToHostPort returns a host:port string suitable for use with net package
// functions like net.Dial or net.Listen.
//
// The host is formatted as an IP address or domain name as appropriate.
// IPv6 addresses are automatically enclosed in brackets.
//
// # Examples
//
//	addr := protocol.AddrFromHostPort("192.168.1.1:8080", "tcp")
//	hostPort := addr.ToHostPort() // Returns "192.168.1.1:8080"
//
//	addr := protocol.AddrFromHostPort("::1:443", "tcp")
//	hostPort := addr.ToHostPort() // Returns "[::1]:443"
func (a Addr) ToHostPort() string {
	return net.JoinHostPort(a.ToFQDN(), strconv.Itoa(int(a.Port)))
}

// Network implements net.Addr.Network.
//
// Returns a network string based on Type and NetTyp:
//   - IP4Addr: "tcp4" or "udp4"
//   - IP6Addr: "tcp6" or "udp6"
//   - FQDNAddr: "tcp" or "udp" (no version suffix)
//
// If NetTyp is empty, "tcp" is used as the default.
//
// This method satisfies the net.Addr interface.
func (a Addr) Network() string {
	net := a.NetTyp
	if a.Type != FQDNAddr {
		net = helpers.NormalNet(net)
	}
	if a.NetTyp == "" {
		net = "tcp"
	}
	switch a.Type {
	case IP4Addr:
		return net + "4"
	case IP6Addr:
		return net + "6"
	case FQDNAddr:
		return net
	}
	return net
}

// IpNetwork returns the IP network family name based on NetTyp.
//
// Returns:
//   - "ip" for generic networks ("", "tcp", "udp", "ip")
//   - "ip4" for IPv4 networks ("tcp4", "udp4", "ip4")
//   - "ip6" for IPv6 networks ("tcp6", "udp6", "ip6")
//   - The original NetTyp for unknown values
//
// This is useful for determining the address family when creating
// network connections.
func (a Addr) IpNetwork() string {
	switch a.NetTyp {
	case "", "tcp", "udp", "ip":
		return "ip"
	case "tcp4", "udp4", "ip4":
		return "ip4"
	case "tcp6", "udp6", "ip6":
		return "ip6"
	}
	return a.NetTyp
}

// String returns the string representation of the address.
//
// Returns:
//   - Just the host (IP or FQDN) if Port is zero
//   - host:port format if Port is non-zero
//
// This method satisfies the net.Addr interface and fmt.Stringer.
//
// # Examples
//
//	addr := protocol.AddrFromHostPort("192.168.1.1:8080", "tcp")
//	s := addr.String() // Returns "192.168.1.1:8080"
//
//	addr := protocol.AddrFromHostPort("example.com:0", "tcp")
//	s := addr.String() // Returns "example.com"
func (a Addr) String() string {
	if a.Port == 0 {
		return a.ToFQDN()
	}
	return a.ToHostPort()
}

// ResolveToIP4 resolves an FQDN address to an IPv4 address.
//
// If the address is already IPv4, it returns itself. If it's an FQDN,
// it uses the provided lookup function to resolve to an IPv4 address.
// Returns nil for IPv6 addresses or if resolution fails.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - lookup: DNS lookup function (e.g., net.Resolver.LookupIP)
//
// # Examples
//
//	addr := protocol.AddrFromFQDN("example.com", 443, "tcp")
//	resolved := addr.ResolveToIP4(ctx, net.DefaultResolver.LookupIP)
//	if resolved != nil {
//	    // resolved is now an IPv4 address
//	}
func (a Addr) ResolveToIP4(
	ctx context.Context,
	lookup func(context.Context, string, string) ([]net.IP, error),
) *Addr {
	if a.Type == IP4Addr {
		return &a
	}
	if a.Type == FQDNAddr {
		ips, err := lookup(ctx, "ip4", a.ToFQDN())
		if err != nil || len(ips) < 1 {
			return nil
		}
		a = AddrFromIP(ips[0], a.Port, "tcp4")
		return &a
	}
	return nil
}
