package socksgo

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

func ClientFromURLObj(u *url.URL) *Client {
	config := clientConfigFromURL(u, nil)
	client := &Client{
		ClientConfig: config,
	}
	return client
}

func ClientFromURL(urlstr string) (*Client, error) {
	u, err := url.Parse(urlstr)
	if err != nil {
		return nil, err
	}
	return ClientFromURLObj(u), nil
}

type Client struct {
	ClientConfig
}

func (c *Client) Request(
	ctx context.Context,
	cmd protocol.Cmd,
	address protocol.Addr,
) (
	proxy net.Conn,
	addr protocol.Addr,
	err error,
) {
	err = c.CheckNetworkSupport(address.Network())
	if err != nil {
		return
	}
	ver := c.Version()
	if ver == "5" {
		return c.request5(ctx, cmd, address)
	}
	if ver == "4a" {
		return c.request4(ctx, cmd, address)
	}
	if ver == "4" {
		ipaddr := resolveTcp4Addr(ctx, address, c.GetResolver())
		if ipaddr == nil {
			err = UnsupportedAddrError{
				SocksVersion: ver,
				Addr:         address.ToFQDN(),
			}
			return
		}
		return c.request4(ctx, cmd, *ipaddr)
	}
	err = UnknownSocksVersionError{ver}
	return
}

func (c *Client) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	err := c.CheckNetworkSupport(network)
	if err != nil {
		return nil, err
	}
	if c.DoFilter(network, address) {
		return c.GetDialer()(ctx, network, address)
	}
	conn, _, err := c.Request(ctx, protocol.CmdConnect, protocol.AddrFromHostPort(address, network))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// To listen, address = "0.0.0.0:0"
func (c *Client) DialPacket(ctx context.Context, network, address string) (PacketConn, error) {
	err := c.CheckNetworkSupport(network)
	if err != nil {
		return nil, err
	}
	if c.DoFilter(network, address) {
		return c.GetPacketDialer()(ctx, network, address)
	}
	raddr := protocol.AddrFromHostPort(address, network)
	if c.GostUDPTun {
		return c.setupUDPTun5(ctx, protocol.AddrFromHostPort("", network), &raddr)
	}
	return c.dialPacket5(ctx, raddr)
}

// If GostUDPTun extension is disabled, server will act like NAT and
// will not return binded udp addr,
// so user should find it out using somesing like STUN.
func (c *Client) ListenPacket(ctx context.Context, network, address string) (PacketConn, error) {
	err := c.CheckNetworkSupport(network)
	if err != nil {
		return nil, err
	}
	if c.DoFilter(network, address) {
		return c.GetPacketListener()(ctx, network, address)
	}
	laddr := protocol.AddrFromHostPort(address, network)
	if c.GostUDPTun {
		return c.setupUDPTun5(ctx, laddr, nil)
	}
	// Standard UDP ASSOC doesn't support listen addr specification
	return c.dialPacket5(ctx, protocol.AddrFromHostPort("", network))
}

func (c *Client) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	err := c.CheckNetworkSupport(network)
	if err != nil {
		return nil, err
	}
	if c.DoFilter(network, address) {
		return c.GetListener()(ctx, network, address)
	}
	cmd := protocol.CmdBind
	ver := c.Version()
	if c.GostMbind && ver == "5" {
		cmd = protocol.CmdGostMuxBind
	}
	conn, addr, err := c.Request(ctx, cmd, protocol.AddrFromHostPort(address, network))
	if err != nil {
		return nil, err
	}
	addr.NetTyp = network
	if ver == "4" || ver == "4a" {
		return &clientListener4{
			conn: conn,
			addr: addr,
		}, nil
	}
	if ver == "5" {
		if c.GostMbind {
			session, err := smux.Server(conn, c.Smux)
			if err != nil {
				conn.Close()
				return nil, err
			}
			return &clientListener5mux{
				session: session,
				addr:    addr,
			}, nil
		}
		return &clientListener5{
			conn: conn,
			addr: addr,
		}, nil
	}
	conn.Close()
	return nil, UnknownSocksVersionError{ver}
}

// Note: due limitations of tor socks extension, ipv6 addr can be returned
// when ipv4 was requested and vise versa
func (c *Client) LookupIP(ctx context.Context, network, address string) ([]net.IP, error) {
	if network != "ip" && network != "ip4" && network != "ip6" {
		return nil, &net.DNSError{
			UnwrapErr:  net.UnknownNetworkError(network),
			Err:        fmt.Sprintf("network type is unsupported: %s", network),
			Name:       address,
			IsNotFound: true,
		}
	}
	if !c.TorLookup {
		return nil, &net.DNSError{
			UnwrapErr: ErrResolveDisabled,
			Err:       ErrResolveDisabled.Error(),
			Name:      address,
		}
	}
	if c.DoFilter(network, address) {
		return c.GetResolver().LookupIP(ctx, network, address)
	}

	proxy, addr, err := c.Request(ctx, protocol.CmdTorResolve, protocol.AddrFromHostPort(address, ""))
	if err != nil {
		return nil, err
	}
	proxy.Close()

	ip := addr.ToIP()
	if ip == nil {
		return nil, ErrWrongAddrInLookupResponse
	}
	return []net.IP{ip}, nil
}

func (c *Client) LookupAddr(ctx context.Context, address string) ([]string, error) {
	if !c.TorLookup {
		return nil, &net.DNSError{
			UnwrapErr: ErrResolveDisabled,
			Err:       ErrResolveDisabled.Error(),
			Name:      address,
		}
	}
	if c.DoFilter("", address) {
		return c.GetResolver().LookupAddr(ctx, address)
	}

	proxy, addr, err := c.Request(ctx, protocol.CmdTorResolvePtr, protocol.AddrFromHostPort(address, ""))
	if err != nil {
		return nil, err
	}
	proxy.Close()

	return []string{addr.ToFQDN()}, nil
}
