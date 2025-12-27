package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/asciimoth/socks/common"
	"github.com/asciimoth/socks/internal"
)

type listener4 struct {
	addr internal.NetAddr
	conn net.Conn
}

func (l *listener4) Addr() net.Addr {
	return l.addr
}

func (l *listener4) Close() error {
	return l.conn.Close()
}

func (l *listener4) Accept() (net.Conn, error) {
	_, _, err := internal.Read4TCPResponse(l.conn)
	if err != nil {
		l.conn.Close()
	}
	return l.conn, err
}

type Client4 struct {
	Config
}

func (c *Client4) request(
	ctx context.Context,
	cmd common.Cmd,
	network, address string,
	proxy net.Conn,
) (net.Conn, net.IP, uint16, error) {
	if network != "tcp4" && network != "tcp" {
		// TODO: Better error
		return nil, nil, 0, net.UnknownNetworkError(network)
	}

	host, strport, err := net.SplitHostPort(address)
	if err != nil {
		// TODO: Better error
		return nil, nil, 0, err
	}
	port, err := c.lookupPort(ctx, "tcp4", strport)
	if err != nil {
		// TODO: Better error
		return nil, nil, 0, err
	}
	var request []byte = nil
	if !c.LocalResolve {
		request = internal.Make4aTCPRequest(cmd, host, uint16(port), c.user())
	} else {
		ips, err := c.resolver().LookupIP(ctx, "ip4", host)
		if err != nil {
			// TODO: Better error
			return nil, nil, 0, err
		}
		request = internal.Make4TCPRequest(cmd, ips[0].To4(), uint16(port), c.user())
	}

	if proxy == nil {
		proxy, err = c.dialer()(ctx, c.proxynet(), c.proxyaddr())
		if err != nil {
			// TODO: Better error
			return nil, nil, 0, err
		}
	}

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		proxy.Close()
		// TODO: Better error
		return nil, nil, 0, err
	}

	incIp, incPort, err := internal.Read4TCPResponse(proxy)
	if err != nil {
		proxy.Close()
		return nil, nil, 0, err
	}

	// Use server host:port if returned one is 0.0.0.0
	if incIp.IsUnspecified() {
		h, p, err := net.SplitHostPort(proxy.RemoteAddr().String())
		if err == nil {
			incIp = net.ParseIP(h)
			pp, err := strconv.Atoi(p)
			if err == nil {
				incPort = uint16(pp)
			}
		}
	}
	return proxy, incIp, incPort, nil
}

func (c *Client4) ListenWithConn(ctx context.Context, network, address string, conn net.Conn) (net.Listener, error) {
	if !c.dialFilter(network, address) {
		return c.listener()(ctx, network, address)
	}
	conn, ip, port, err := c.request(ctx, common.CmdBind, network, address, conn)
	if err != nil {
		return nil, err
	}

	return &listener4{
		conn: conn,
		addr: internal.NetAddr{
			Net: "tcp4",
			Host: net.JoinHostPort(
				ip.String(),
				strconv.Itoa(int(port)),
			),
		},
	}, nil
}

func (c *Client4) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return c.ListenWithConn(ctx, network, address, nil)
}

func (c *Client4) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if !c.dialFilter(network, address) {
		return c.dialer()(ctx, network, address)
	}
	conn, _, _, err := c.request(ctx, common.CmdConnect, network, address, nil)
	if err != nil {
		return nil, err
	}
	return conn, err
}

func (c *Client4) DialWithConn(ctx context.Context, network, address string, conn net.Conn) (net.Conn, error) {
	if !c.dialFilter(network, address) {
		return c.dialer()(ctx, network, address)
	}
	conn, _, _, err := c.request(ctx, common.CmdConnect, network, address, conn)
	if err != nil {
		return nil, err
	}
	return conn, err
}

func (c *Client4) LookupIPWithConn(ctx context.Context, network, address string, conn net.Conn) ([]net.IP, error) {
	if network != "ip" && network != "ip4" {
		return nil, &net.DNSError{
			UnwrapErr:  net.UnknownNetworkError(network),
			Err:        fmt.Sprintf("network type is unsupported: %s", network),
			Name:       address,
			IsNotFound: true,
		}
	}

	if !c.TorLookup {
		return nil, &net.DNSError{
			UnwrapErr: ResolveDisabledErr,
			Err:       ResolveDisabledErr.Error(),
			Name:      address,
		}
	}

	if c.LocalResolve {
		return c.resolver().LookupIP(ctx, network, address)
	}

	if !c.dialFilter(network, address) {
		return c.resolver().LookupIP(ctx, network, address)
	}

	request := internal.Make4aTCPRequest(common.CmdTorResolve, address, 0, c.user())

	proxy := conn
	var err error
	if proxy == nil {
		proxy, err = c.dialer()(ctx, c.proxynet(), c.proxyaddr())
		if err != nil {
			// TODO: Better error
			return nil, err
		}
	}

	_, err = io.Copy(proxy, bytes.NewReader(request))
	if err != nil {
		proxy.Close()
		// TODO: Better error
		return nil, err
	}

	ip, _, err := internal.Read4TCPResponse(proxy)
	if err != nil {
		proxy.Close()
		// TODO: Better error
		return nil, err
	}

	return []net.IP{ip}, err
}

func (c *Client4) LookupIP(ctx context.Context, network, address string) ([]net.IP, error) {
	return c.LookupIPWithConn(ctx, network, address, nil)
}

func (c *Client4) String() string {
	ver := "4a"
	if c.LocalResolve {
		ver = "4"
	}
	return fmt.Sprintf("[ socks %s client ]\n%s", ver, c.Config.String())
}

type client4ToClientWrapper struct {
	Client4
}

func (c *client4ToClientWrapper) DialPacket(_ context.Context, _, _ string) (net.PacketConn, error) {
	// TODO: Better error
	return nil, errors.New("UDP related features are not avalable in 4 ver of socks protocol")
}

func (c *client4ToClientWrapper) DialPacketWithConn(_ context.Context, _, _ string, _ net.Conn) (net.PacketConn, error) {
	// TODO: Better error
	return nil, errors.New("UDP related features are not avalable in 4 ver of socks protocol")
}

func (c *client4ToClientWrapper) ListenPacket(_ context.Context, _, _ string) (net.PacketConn, error) {
	// TODO: Better error
	return nil, errors.New("UDP related features are not avalable in 4 ver of socks protocol")
}

func (c *client4ToClientWrapper) ListenPacketWithConn(_ context.Context, _, _ string, _ net.Conn) (net.PacketConn, error) {
	// TODO: Better error
	return nil, errors.New("UDP related features are not avalable in 4 ver of socks protocol")
}

func (c *client4ToClientWrapper) LookupAddr(_ context.Context, _ string) ([]string, error) {
	// TODO: Better error
	return nil, errors.New("reverse lookup not avalable in 4 ver of socks protocol")
}

func (c *client4ToClientWrapper) LookupAddrWithConn(_ context.Context, _ string, _ net.Conn) ([]string, error) {
	// TODO: Better error
	return nil, errors.New("reverse lookup not avalable in 4 ver of socks protocol")
}
