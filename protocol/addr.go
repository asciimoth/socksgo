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

type AddrType uint8

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

// Addr represents IP or FQDN addr.
type Addr struct {
	Type AddrType // IP4Addr | IP6Addr | FQDNAddr
	Host []byte   // Binary representation of IP addr or FQDN string.
	Port uint16

	// NetTyp can be "tcp" or "udp", not "tcp4"/"udp6"/etc.
	// Blank string means "tcp" by default.
	NetTyp string
}

func AddrFromNetAddr(addr net.Addr) Addr {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return AddrFromTCPAddr(tcp)
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		return AddrFromUDPAddr(udp)
	}
	return AddrFromHostPort(addr.String(), addr.Network())
}

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

func AddrFromString(host string, port uint16, network string) Addr {
	ip := net.ParseIP(host)
	if ip != nil {
		return AddrFromIP(ip, port, network)
	}
	return AddrFromFQDN(host, port, network)
}

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

// If fqdn already contains port (e.g. "example.com:80") it will be used instead of port arg.
func AddrFromFQDN(fqdn string, port uint16, net string) Addr {
	fqdn, port = internal.SplitHostPort(net, fqdn, port)
	return Addr{
		Type:   FQDNAddr,
		Host:   []byte(fqdn),
		Port:   port,
		NetTyp: net,
	}
}

// Like AddrFromFQDN but with trimming trailing dot
// Need for compat with ResolvePtr implementation in tor
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

func AddrFromUDPAddr(u *net.UDPAddr) Addr {
	var a Addr
	if u == nil {
		return a
	}
	a = AddrFromIP(u.IP, uint16(u.Port), "udp")
	return a
}

func AddrFromTCPAddr(t *net.TCPAddr) Addr {
	var a Addr
	if t == nil {
		return a
	}
	a = AddrFromIP(t.IP, uint16(t.Port), "tcp")
	return a
}

func (a Addr) IsUnspecified() bool {
	if len(a.Host) < 1 {
		return true
	}
	if a.Type == IP4Addr || a.Type == IP6Addr {
		return net.IP(a.Host).IsUnspecified()
	}
	return false
}

func (a Addr) Len() int {
	switch a.Type {
	case IP4Addr:
		return 4
	case IP6Addr:
		return 6
	}
	return len(a.Host)
}

// If host is not "" and a.IsUnspecified, a.Host will
// be replaced with host.
// If a.IsUnspecified and host is "", a.Host will be replaced with "0.0.0.0"
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

func (a Addr) ToIP() net.IP {
	switch a.Type {
	case IP4Addr:
		return net.IP(a.Host).To4()
	case IP6Addr:
		return net.IP(a.Host).To16()
	}
	return nil
}

func (a Addr) ToFQDN() string {
	if ip := a.ToIP(); ip != nil {
		return ip.String()
	}

	return string(a.Host)
}

func (a Addr) ToUDP() *net.UDPAddr {
	if ip := a.ToIP(); ip != nil {
		return &net.UDPAddr{
			IP:   ip,
			Port: int(a.Port),
		}
	}
	return nil
}

func (a Addr) ToTCP() *net.TCPAddr {
	if ip := a.ToIP(); ip != nil {
		return &net.TCPAddr{
			IP:   ip,
			Port: int(a.Port),
		}
	}
	return nil
}

func (a Addr) ToHostPort() string {
	return net.JoinHostPort(a.ToFQDN(), strconv.Itoa(int(a.Port)))
}

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
	}
	return net
}

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

func (a Addr) String() string {
	if a.Port == 0 {
		return a.ToFQDN()
	}
	return a.ToHostPort()
}
