package protocol

import (
	"net"
	"strconv"
	"strings"

	"github.com/asciimoth/socksgo/internal"
)

const (
	IP4Addr  AddrType = 0x01
	IP6Addr  AddrType = 0x04
	FQDNAddr AddrType = 0x03 // Fully qualified domain name
)

var (
	_ net.Addr = Addr{}
)

// AddrType is an enumeration of supported address kinds (IPv4, IPv6 or FQDN).
type AddrType uint8

// String returns a human readable representation of AddrType.
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

// Addr represents an IP (IPv4/IPv6) address or a fully qualified domain
// name together with a port and a network type.
type Addr struct {
	Type AddrType // IP4Addr | IP6Addr | FQDNAddr
	Host []byte   // Binary representation of IP addr or FQDN string.
	Port uint16

	// NetTyp can be "tcp" or "udp", not "tcp4"/"udp6"/etc.
	// Empty string implies "tcp" in some conversions.
	NetTyp string
}

// AddrFromNetAddr converts a net.Addr to protocol Addr. It specially
// handles *net.TCPAddr and *net.UDPAddr. For other net.Addr types the
// function falls back to parsing addr.String() and uses addr.Network()
// as the NetTyp.
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

// AddrFromHostPort creates an Addr from a host:port string and a network
// name. If hostport is empty a suitable wildcard host is chosen based on
// the provided network (IPv6 wildcard for "*6" networks, IPv4
// wildcard otherwise).
func AddrFromHostPort(hostport, network string) Addr {
	if hostport == "" {
		if network == "tcp6" || network == "udp6" {
			hostport = "[::]:0"
		} else {
			hostport = "0.0.0.0:0"
		}
	}
	host, port := internal.SplitHostPort(network, hostport, 0)
	return AddrFromString(host, port, network)
}

// AddrFromString constructs an Addr from a host string and numeric port.
// The host is examined: if it parses as an IP address an IP Addr is
// returned, otherwise an FQDN Addr is returned.
func AddrFromString(host string, port uint16, network string) Addr {
	ip := net.ParseIP(host)
	if ip != nil {
		return AddrFromIP(ip, port, network)
	}
	return AddrFromFQDN(host, port, network)
}

// AddrFromIP returns an Addr representing the provided net.IP and port.
// The function detects IPv4 vs IPv6 and stores the canonical byte
// representation in Host.
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

// AddrFromFQDN constructs an FQDN Addr. If the fqdn argument already
// contains a port (for example "example.com:80") the embedded port will
// override the provided port argument.
func AddrFromFQDN(fqdn string, port uint16, net string) Addr {
	fqdn, port = internal.SplitHostPort(net, fqdn, port)
	return Addr{
		Type:   FQDNAddr,
		Host:   []byte(fqdn),
		Port:   port,
		NetTyp: net,
	}
}

// AddrFromFQDNNoDot is like AddrFromFQDN but trims a trailing dot from
// the FQDN. This is useful for compatibility with implementations that
// may return names with a trailing dot (such as Tor's ResolvePtr).
func AddrFromFQDNNoDot(fqdn string, port uint16, net string) Addr {
	fqdn, port = internal.SplitHostPort(net, fqdn, port)
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

// AddrFromUDPAddr converts a *net.UDPAddr into an Addr. A nil input
// yields the zero Addr. Port values outside the 0..65535 range are
// clamped to zero.
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

// AddrFromTCPAddr converts a *net.TCPAddr into an Addr. A nil input
// yields the zero Addr. Port values outside the 0..65535 range are
// clamped to zero.
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

// IsUnspecified reports whether the Addr carries an unspecified host
// (e.g. 0.0.0.0 or ::) or has an empty Host slice. For FQDN addresses
// the function returns false unless Host is empty.
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

// Len returns the length of the Host field in bytes according to the
// address Type: 4 for IPv4, 16 for IPv6 and len(Host) for FQDN.
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

// WithNetTyp returns a copy of the Addr with NetTyp normalized. Values
// like "tcp4"/"tcp6" are mapped to "tcp", "udp4"/"udp6" to
// "udp"; other strings are preserved.
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

// WithDefaultHost returns a copy of Addr where an unspecified Host is
// replaced with the provided host. If host is empty the IPv4 wildcard
// "0.0.0.0" is used. If the original Addr is already specified it is
// returned unchanged.
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

// WithDefaultAddr returns def if it is not nil and a.IsUnspecified() or
// else returns itself.
func (a Addr) WithDefaultAddr(def *Addr) Addr {
	if a.IsUnspecified() && def != nil {
		return def.Copy()
	}
	return a
}

// ToIP returns the net.IP representation of the address if it's an IP
// Addr, or nil for FQDN addresses.
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

// ToFQDN returns the textual representation of the address suitable for
// host portions of host:port: IP addresses are formatted using the
// standard IP string form; FQDNs are returned as-is.
func (a Addr) ToFQDN() string {
	if ip := a.ToIP(); ip != nil {
		return ip.String()
	}

	return string(a.Host)
}

// PortStr returns the port as a decimal string.
func (a Addr) PortStr() string {
	return strconv.Itoa(int(a.Port))
}

// ToUDP returns a *net.UDPAddr for IP addresses or nil for FQDN addrs.
func (a Addr) ToUDP() *net.UDPAddr {
	if ip := a.ToIP(); ip != nil {
		return &net.UDPAddr{
			IP:   ip,
			Port: int(a.Port),
		}
	}
	return nil
}

// ToTCP returns a *net.TCPAddr for IP addresses or nil for FQDN addrs.
func (a Addr) ToTCP() *net.TCPAddr {
	if ip := a.ToIP(); ip != nil {
		return &net.TCPAddr{
			IP:   ip,
			Port: int(a.Port),
		}
	}
	return nil
}

// ToUnspecified returns a new Addr with the same Type and NetTyp, an
// unspecified Host (0.0.0.0 or ::) and zero Port. For FQDN addrs the
// Host remains nil.
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

// ToHostPort returns a host:port string suitable for use with net
// functions (the host will be formatted as an IP or FQDN as needed).
func (a Addr) ToHostPort() string {
	return net.JoinHostPort(a.ToFQDN(), strconv.Itoa(int(a.Port)))
}

// Network implements net.Addr.Network. It returns a network string
// such as "tcp4", "udp6" or "tcp" (for FQDN addresses). If NetTyp
// is empty "tcp" is used as the default.
func (a Addr) Network() string {
	net := a.NetTyp
	if a.Type != FQDNAddr {
		net = internal.NormalNet(net)
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

// IpNetwork returns a name for the IP network family such as "ip",
// "ip4" or "ip6" based on NetTyp. Unknown NetTyp values are returned
// unchanged.
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

// String returns either the FQDN/IP string when Port is zero or the
// host:port representation when a port is present.
func (a Addr) String() string {
	if a.Port == 0 {
		return a.ToFQDN()
	}
	return a.ToHostPort()
}
