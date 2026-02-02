package socksgo

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

// Returns Client that pass all operations directly without using any proxy
// TODO: Better comment
func ClientNoProxy() *Client {
	return &Client{
		Filter:     MatchAllFilter,
		GostMbind:  true,
		GostUDPTun: true,
		TorLookup:  true,
	}
}

// Keys ignored:
// - insecureudp
// - assocprob
// - secure
func ClientFromURLObjSafe(u *url.URL) *Client {
	client := &Client{}
	if u == nil {
		return client
	}

	version, isTLS, isWS := internal.ParseScheme(u.Scheme)
	client.SocksVersion = version
	client.TLS = isTLS

	client.ProxyAddr = u.Host

	wsUrl := ""
	if isWS {
		wsu := url.URL{
			Scheme: "ws",
			Host:   u.Host,
			Path:   "/ws", // Default for gost compat
		}
		if u.Path != "" {
			wsu.Path = u.Path
		}
		if isTLS {
			wsu.Scheme = "wss"
		}
		wsUrl = wsu.String()
	}
	client.WebSocketURL = wsUrl

	q := u.Query()

	if f, s := internal.CheckURLBoolKey(q, "gost"); s {
		client.GostMbind = f
		client.GostUDPTun = f
	}

	if f, s := internal.CheckURLBoolKey(q, "tor"); s {
		client.TorLookup = f
	}

	if u.User != nil {
		var password string
		if pass, ok := u.User.Password(); ok {
			password = pass
		}
		client.Auth = client.Auth.Add(&protocol.PassAuthMethod{
			User: u.User.Username(),
			Pass: password,
		})
	}

	if f, s := internal.CheckURLBoolKey(q, "pass"); s && f {
		client.Filter = PassAllFilter
	}

	client.TLSConfig = &tls.Config{
		InsecureSkipVerify: true, //nolint
	}
	// In safe constructor we can enable it but not disable
	if f, s := internal.CheckURLBoolKey(q, "secure"); s && f {
		client.TLSConfig.InsecureSkipVerify = false
	}
	return client
}

func ClientFromURLSafe(urlstr string) (*Client, error) {
	u, err := url.Parse(urlstr)
	if err != nil {
		return nil, err
	}
	return ClientFromURLObjSafe(u), nil
}

func ClientFromENVSafe(scheme string) (*Client, error) {
	urlstring := getProxyFromEnvVar(scheme)
	if urlstring == "" {
		return ClientNoProxy(), nil
	}
	return ClientFromURLSafe(urlstring)
}

func ClientFromURLObj(u *url.URL) *Client {
	client := ClientFromURLObjSafe(u)

	q := u.Query()
	if f, s := internal.CheckURLBoolKey(q, "insecureudp"); s {
		client.InsecureUDP = f
	}
	if f, s := internal.CheckURLBoolKey(q, "assocprob"); s {
		client.DoNotSpawnUDPAsocProbber = !f
	}
	if f, s := internal.CheckURLBoolKey(q, "secure"); s {
		client.TLSConfig.InsecureSkipVerify = !f
	}
	// TODO: Add more TLS related args

	return client
}

func ClientFromURL(urlstr string) (*Client, error) {
	u, err := url.Parse(urlstr)
	if err != nil {
		return nil, err
	}
	return ClientFromURLObj(u), nil
}

func ClientFromENV(scheme string) (*Client, error) {
	urlstring := getProxyFromEnvVar(scheme)
	if urlstring == "" {
		return ClientNoProxy(), nil
	}
	return ClientFromURL(urlstring)
}

type Client struct {
	// "4" | "4a" | "5" | ""
	// "" means default means "5"
	SocksVersion string

	// For standard (not ws) proxies
	// Default: "tcp"
	ProxyNet string
	// If port not provided ("<host>" instead of "<host>:<port>")
	// 1080 will be used
	ProxyAddr string

	Auth *protocol.AuthMethods

	// Allow plaintext UDP ASSOC for socks over tls proxies
	InsecureUDP bool
	// Goroutine that check if original tcp conn is closed
	DoNotSpawnUDPAsocProbber bool

	// Extensions
	GostMbind  bool
	GostUDPTun bool
	TorLookup  bool

	Filter Filter

	// Will be used to connect to proxy server or for addrs marked by Filter
	Dialer       Dialer
	PacketDialer PacketDialer
	// Will be used for addrs marked by Filter
	DirectListener       Listener
	DirectPacketListener PacketListener
	// For socks4 (not socks4a) clients or Lookup* requests for addrs marked by Filter
	Resolver Resolver

	HandshakeTimeout time.Duration

	// For gost MBIND extension
	Smux *smux.Config

	// Enable socks over tls/ws
	TLS       bool
	TLSConfig *tls.Config

	// If not "" socks over ws/wss will be enabled
	// For ws/wss connections ProxyNet and ProxyAddr are ignored
	WebSocketURL    string
	WebSocketConfig *WebSocketConfig

	Pool bufpool.Pool
}

func (c *Client) IsNoProxy() bool {
	return c == nil || (c.ProxyAddr == "" && c.WebSocketURL == "")
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
	proxy, addr, err = c.request(ctx, cmd, address)
	if err == nil {
		// Unset timeout after successful socks handshake
		err = proxy.SetDeadline(time.Time{})
	}
	return
}

func (c *Client) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	if network == "udp" || network == "udp4" || network == "udp6" {
		return c.DialPacket(ctx, network, address)
	}
	err := c.CheckNetworkSupport(network)
	if err != nil {
		return nil, err
	}
	if c.DoFilter(network, address) {
		return c.GetDialer()(ctx, network, address)
	}
	conn, _, err := c.Request(
		ctx,
		protocol.CmdConnect,
		protocol.AddrFromHostPort(address, network),
	)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// To listen, address = "0.0.0.0:0"
func (c *Client) DialPacket(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
	err := c.CheckNetworkSupport(network)
	if err != nil {
		return nil, err
	}
	if c.DoFilter(network, address) {
		return c.GetPacketDialer()(ctx, network, address)
	}
	raddr := protocol.AddrFromHostPort(address, network)
	if c.GostUDPTun {
		return c.setupUDPTun5(
			ctx,
			protocol.AddrFromHostPort("", network),
			&raddr,
		)
	}
	return c.dialPacket5(ctx, raddr)
}

// If GostUDPTun extension is disabled, server will act like NAT and
// will not return binded udp addr,
// so user should find it out using somesing like STUN.
func (c *Client) ListenPacket(
	ctx context.Context,
	network, address string,
) (PacketConn, error) {
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

func (c *Client) Listen(
	ctx context.Context,
	network, address string,
) (net.Listener, error) {
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
	conn, addr, err := c.Request(
		ctx,
		cmd,
		protocol.AddrFromHostPort(address, network),
	)
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
				_ = conn.Close()
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
	_ = conn.Close()
	return nil, UnknownSocksVersionError{ver}
}

// Note: due limitations of tor socks extension, ipv6 addr can be returned
// when ipv4 was requested and vise versa
func (c *Client) LookupIP(
	ctx context.Context,
	network, address string,
) ([]net.IP, error) {
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

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdTorResolve,
		protocol.AddrFromHostPort(address, ""),
	)
	if err != nil {
		return nil, err
	}
	_ = proxy.Close()

	ip := addr.ToIP()
	if ip == nil {
		return nil, ErrWrongAddrInLookupResponse
	}
	return []net.IP{ip}, nil
}

func (c *Client) LookupAddr(
	ctx context.Context,
	address string,
) ([]string, error) {
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

	proxy, addr, err := c.Request(
		ctx,
		protocol.CmdTorResolvePtr,
		protocol.AddrFromHostPort(address, ""),
	)
	if err != nil {
		return nil, err
	}
	_ = proxy.Close()

	return []string{addr.ToFQDN()}, nil
}

func (c *Client) request(
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
