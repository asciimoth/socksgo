package protocol

import (
	"net"
	"strconv"

	"github.com/asciimoth/socks/internal"
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

func (a Addr) String() string {
	if a.Port == 0 {
		return a.ToFQDN()
	}
	return net.JoinHostPort(a.ToFQDN(), strconv.Itoa(int(a.Port)))
}
