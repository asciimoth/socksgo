package socksgo

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/gonnect/helpers"
	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/xtaci/smux"
)

// Static type assertions
var (
	_ gonnect.Network      = &Client{}
	_ gonnect.Dial         = (&Client{}).Dial
	_ gonnect.PacketDial   = (&Client{}).PacketDial
	_ gonnect.Listen       = (&Client{}).Listen
	_ gonnect.PacketListen = (&Client{}).ListenPacket
	_ gonnect.LookupIP     = (&Client{}).LookupIP
	_ gonnect.LookupIPAddr = (&Client{}).LookupIPAddr
	_ gonnect.LookupNetIP  = (&Client{}).LookupNetIP
	_ gonnect.LookupHost   = (&Client{}).LookupHost
	_ gonnect.LookupAddr   = (&Client{}).LookupAddr
	_ gonnect.DialTCP      = (&Client{}).DialTCP
	_ gonnect.ListenTCP    = (&Client{}).ListenTCP
	_ gonnect.DialUDP      = (&Client{}).DialUDP
	_ gonnect.ListenUDP    = (&Client{}).ListenUDP
)

// ClientNoProxy returns a Client that bypasses any proxy.
//
// This client passes all connections directly without using a proxy.
// It's equivalent to setting Filter to gonnect.TrueFilter.
//
// # Examples
//
//	// Direct connections only
//	client := socksgo.ClientNoProxy()
//	conn, err := client.Dial(ctx, "tcp", "example.com:80")
//	// conn is a direct TCP connection to example.com:80
//
// # See Also
//
//   - gonnect.TrueFilter: Filter that always returns true
func ClientNoProxy() *Client {
	return &Client{
		Filter:     gonnect.TrueFilter,
		GostMbind:  true,
		GostUDPTun: true,
		TorLookup:  true,
	}
}

// ClientFromURLObjSafe creates a Client from a URL without insecure options.
//
// This is a safe constructor that parses a URL and creates a Client with
// secure defaults. Insecure options like insecureudp are ignored.
//
// # URL Format
//
//	socks[4|4a|5][+tls|+ws|+wss]://[user:pass@]host[:port][?options]
//
// # Supported Options
//
//   - pass: Enable PassAllFilter (all connections through proxy, no bypass)
//   - gost: Enable Gost extensions (MBIND, UDPTun)
//   - tor: Enable Tor lookup extensions
//   - secure: Enable TLS certificate verification (default: skip verification)
//
// # Defaults
//
//   - TLS: InsecureSkipVerify = true (disable with "secure" option)
//   - UDP: Plaintext UDP over TLS disabled (use "insecureudp" in unsafe version)
//   - Filter: LoopbackFilter (bypass proxy for localhost)
//
// # The "pass" Option
//
// The "pass" option enables PassAllFilter, which forces ALL connections
// through the proxy with no bypass. Without this option, LoopbackFilter
// is used by default ("localhost" and loopback addresses bypass the proxy).
//
// # Examples
//
//	// Basic SOCKS5 proxy
//	u, _ := url.Parse("socks5://proxy.example.com:1080")
//	client := socksgo.ClientFromURLObjSafe(u)
//
//	// With authentication (credentials in URL)
//	u, _ := url.Parse("socks5://user:pass@proxy.example.com:1080")
//	client := socksgo.ClientFromURLObjSafe(u)
//
//	// Force all traffic through proxy (no bypass)
//	u, _ := url.Parse("socks5://proxy.example.com:1080?pass")
//	client := socksgo.ClientFromURLObjSafe(u)
//
//	// SOCKS5 over TLS with certificate verification
//	u, _ := url.Parse("socks5+tls://proxy.example.com:1080?secure")
//	client := socksgo.ClientFromURLObjSafe(u)
//
//	// SOCKS5 over WebSocket
//	u, _ := url.Parse("socks5+ws://proxy.example.com:8080/ws")
//	client := socksgo.ClientFromURLObjSafe(u)
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

	if f, s := helpers.CheckURLBoolKey(q, "gost"); s {
		client.GostMbind = f
		client.GostUDPTun = f
	}

	if f, s := helpers.CheckURLBoolKey(q, "tor"); s {
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

	if f, s := helpers.CheckURLBoolKey(q, "pass"); s && f {
		client.Filter = gonnect.FalseFilter
	}

	client.TLSConfig = &tls.Config{
		InsecureSkipVerify: true, //nolint
	}
	// In safe constructor we can enable it but not disable
	if f, s := helpers.CheckURLBoolKey(q, "secure"); s && f {
		client.TLSConfig.InsecureSkipVerify = false
	}
	return client
}

// ClientFromURLSafe creates a Client from a URL string safely.
//
// Wrapper around ClientFromURLObjSafe that parses the URL string first.
// Returns an error if the URL cannot be parsed.
//
// # Examples
//
//	client, err := socksgo.ClientFromURLSafe("socks5://proxy.example.com:1080")
//
// # See Also
//
//   - ClientFromURLObjSafe: Parse *url.URL safely
//   - ClientFromURL: Unsafe version with all options
func ClientFromURLSafe(urlstr string) (*Client, error) {
	u, err := url.Parse(urlstr)
	if err != nil {
		return nil, err
	}
	return ClientFromURLObjSafe(u), nil
}

// ClientFromENVSafe creates a Client from environment variables safely.
//
// Reads the proxy URL from standard environment variables:
//   - ALL_PROXY, all_proxy: Fallback for any scheme
//   - {scheme}_proxy, {scheme}_PROXY: Scheme-specific (e.g., http_proxy)
//
// Returns ClientNoProxy() if no environment variable is set.
//
// # Examples
//
//	// Reads HTTP_PROXY or ALL_PROXY
//	client, err := socksgo.ClientFromENVSafe("http")
//
// # Environment Variable Priority
//
// 1. {scheme}_proxy (lowercase)
// 2. {scheme}_PROXY (uppercase)
// 3. ALL_PROXY (lowercase)
// 4. all_proxy (uppercase)
//
// # See Also
//
//   - ClientFromURLObjSafe: Parse URL safely
//   - ClientNoProxy: Default when no env var set
func ClientFromENVSafe(scheme string) (*Client, error) {
	urlstring := internal.GetProxyFromEnvVar(scheme)
	if urlstring == "" {
		return ClientNoProxy(), nil
	}
	return ClientFromURLSafe(urlstring)
}

// ClientFromURLObj creates a Client from a URL with all options.
//
// This is the unsafe constructor that supports all URL options including
// insecure ones. Use ClientFromURLObjSafe for secure defaults.
//
// # Supported Options
//
//   - pass: Enable PassAllFilter (all connections through proxy, no bypass)
//   - gost: Enable Gost extensions (MBIND, UDPTun)
//   - tor: Enable Tor lookup extensions
//   - secure: Disable TLS certificate verification (default: skip)
//   - insecureudp: Allow plaintext UDP over TLS (security risk!)
//   - assocprob: Enable UDP assoc prober (monitors control connection)
//
// # Security Warning
//
// Using "insecureudp" allows plaintext UDP even when the control connection
// is encrypted. This can lead to security vulnerabilities.
//
// # The "pass" Option
//
// The "pass" option enables PassAllFilter, which forces ALL connections
// through the proxy with no bypass. Without this option, LoopbackFilter
// is used by default (localhost and loopback addresses bypass the proxy).
//
// # Examples
//
//	// With insecure UDP over TLS (NOT RECOMMENDED)
//	u, _ := url.Parse("socks5+tls://proxy.example.com:1080?insecureudp")
//	client := socksgo.ClientFromURLObj(u)
//
//	// Force all traffic through proxy (no bypass)
//	u, _ := url.Parse("socks5://proxy.example.com:1080?pass")
//	client := socksgo.ClientFromURLObj(u)
//
// # See Also
//
//   - ClientFromURLObjSafe: Safe version without insecure options
//   - ClientFromURL: Parse URL string with all options
func ClientFromURLObj(u *url.URL) *Client {
	client := ClientFromURLObjSafe(u)

	q := u.Query()
	if f, s := helpers.CheckURLBoolKey(q, "insecureudp"); s {
		client.InsecureUDP = f
	}
	if f, s := helpers.CheckURLBoolKey(q, "assocprob"); s {
		client.DoNotSpawnUDPAsocProbber = !f
	}
	if f, s := helpers.CheckURLBoolKey(q, "secure"); s {
		client.TLSConfig.InsecureSkipVerify = !f
	}

	return client
}

// ClientFromURL creates a Client from a URL string with all options.
//
// Wrapper around ClientFromURLObj that parses the URL string first.
// Supports all options including insecure ones.
//
// # Examples
//
//	client, err := socksgo.ClientFromURL("socks5://user:pass@proxy.example.com:1080?pass")
//
// # See Also
//
//   - ClientFromURLObj: Parse *url.URL with all options
//   - ClientFromURLSafe: Safe version without insecure options
func ClientFromURL(urlstr string) (*Client, error) {
	u, err := url.Parse(urlstr)
	if err != nil {
		return nil, err
	}
	return ClientFromURLObj(u), nil
}

// ClientFromENV creates a Client from environment variables with all options.
//
// Reads the proxy URL from environment variables and creates a Client
// with all options enabled. Uses ClientFromURL which supports insecure options
// if specified in the URL.
//
// # Examples
//
//	// Reads SOCKS5_PROXY environment variable
//	client, err := socksgo.ClientFromENV("socks5")
//
// # See Also
//
//   - ClientFromENVSafe: Safe version without insecure options
//   - ClientFromURL: Parse URL string with all options
func ClientFromENV(scheme string) (*Client, error) {
	urlstring := internal.GetProxyFromEnvVar(scheme)
	if urlstring == "" {
		return ClientNoProxy(), nil
	}
	return ClientFromURL(urlstring)
}

// Client is a SOCKS proxy client configuration.
//
// Client provides a high-level interface for connecting through SOCKS4, SOCKS4a,
// and SOCKS5 proxies. It supports TCP connections, UDP associations, BIND commands,
// and extensions for Gost and Tor compatibility.
//
// # Quick Start
//
//	// Basic SOCKS5 client
//	client := &socksgo.Client{
//	    SocksVersion: "5",
//	    ProxyAddr:    "proxy.example.com:1080",
//	}
//	conn, err := client.Dial(ctx, "tcp", "example.com:80")
//
//	// With authentication
//	client := &socksgo.Client{
//	    SocksVersion: "5",
//	    ProxyAddr:    "proxy.example.com:1080",
//	    Auth: (&protocol.AuthMethods{}).Add(&protocol.PassAuthMethod{
//	        User: "username",
//	        Pass: "password",
//	    }),
//	}
//
//	// SOCKS over TLS
//	client := &socksgo.Client{
//	    SocksVersion: "5",
//	    ProxyAddr:    "proxy.example.com:1080",
//	    TLS:          true,
//	}
//
//	// SOCKS over WebSocket
//	client := &socksgo.Client{
//	    SocksVersion:   "5",
//	    WebSocketURL:   "wss://proxy.example.com/ws",
//	}
//
//	// Tor stream isolation
//	client := &socksgo.Client{
//	    SocksVersion: "5",
//	    ProxyAddr:    "127.0.0.1:9050",
//	}
//	isolatedClient := client.WithTorIsolation(nil) // Random isolation
//	sessionID := "my-session"
//	isolatedClient = client.WithTorIsolation(&sessionID) // Specific isolation
//
// # Thread Safety
//
// Client is safe for concurrent use after initialization. Do not modify
// fields after calling Dial, Listen, or other methods.
//
// # See Also
//
//   - ClientFromURL: Create client from URL string
//   - ClientFromENV: Create client from environment variables
//   - ClientNoProxy: Create client that bypasses proxy
//   - Client.WithTorIsolation: Enable Tor stream isolation
type Client struct {
	// SocksVersion specifies the SOCKS protocol version.
	//
	// Valid values:
	//   - "4": SOCKS4 (no domain name support)
	//   - "4a": SOCKS4a (supports domain names)
	//   - "5": SOCKS5 (full feature support)
	//   - "": Empty string defaults to "5"
	//
	// Default: "5"
	SocksVersion string

	// ProxyNet specifies the network type for connecting to the proxy.
	//
	// Valid values: "tcp", "tcp4", "tcp6"
	//
	// Default: "tcp"
	ProxyNet string

	// ProxyAddr is the proxy server address in host:port format.
	//
	// If port is omitted (e.g., "proxy.example.com"), port 1080 is used.
	// Ignored when WebSocketURL is set.
	//
	// Examples:
	//   - "proxy.example.com:1080"
	//   - "192.168.1.1:9050"
	//   - "proxy.example.com" (uses default port 1080)
	ProxyAddr string

	// Auth contains authentication methods for SOCKS5.
	//
	// Multiple methods can be added; the server selects one during negotiation.
	//
	// Examples:
	//
	//	client.Auth = (&protocol.AuthMethods{}).
	//	    Add(&protocol.PassAuthMethod{User: "user", Pass: "pass"}).
	//	    Add(&protocol.NoAuthMethod{})
	Auth *protocol.AuthMethods

	// InsecureUDP allows plaintext UDP over TLS connections.
	//
	// WARNING: This is a security risk! When true, UDP packets are sent
	// unencrypted even when the control TCP connection uses TLS.
	//
	// Only enable in trusted networks or when you understand the implications.
	//
	// Default: false
	InsecureUDP bool

	// DoNotSpawnUDPAsocProbber disables the UDP ASSOC prober goroutine.
	//
	// When false (default), a goroutine monitors the control TCP connection
	// and closes the UDP association when the control connection closes.
	//
	// Set to true to disable this behavior (manual cleanup required).
	DoNotSpawnUDPAsocProbber bool

	// GostMbind enables Gost multiplexed BIND extension.
	//
	// When enabled, the client can use MBIND command for multiplexed
	// incoming connections over a single TCP connection using smux.
	//
	// Default: false
	GostMbind bool

	// GostUDPTun enables Gost UDP Tunnel extension.
	//
	// When enabled, UDP traffic is tunneled over TCP instead of using
	// standard UDP ASSOCIATE.
	//
	// Default: false
	GostUDPTun bool

	// TorLookup enables Tor DNS resolution extensions.
	//
	// When enabled, LookupIP and LookupAddr methods use Tor's SOCKS
	// extensions for DNS resolution through the proxy.
	//
	// Default: false
	TorLookup bool

	// Filter determines which connections bypass the proxy.
	//
	// When Filter returns true, connections use direct dialing instead
	// of going through the proxy. Commonly used for NO_PROXY-style rules.
	//
	// Default: gonnect.LoopbackFilter (bypasses localhost and loopback addresses)
	//
	// Examples:
	//
	//	client.Filter = gonnect.FilterFromString("localhost,192.168.0.0/16").Filter
	Filter gonnect.Filter

	// Dialer is used to establish TCP connections to the proxy.
	//
	// Also used for direct connections when Filter returns true.
	//
	// Default: net.Dialer.DialContext
	Dialer gonnect.Dial

	// PacketDialer is used to establish UDP connections for proxy operations.
	//
	// Also used for direct UDP when Filter returns true.
	//
	// Default: net.DialUDP
	PacketDialer gonnect.PacketDial

	// DirectListener is used for direct TCP listening (BIND) when
	// Filter returns true.
	//
	// Default: net.ListenConfig.Listen
	DirectListener gonnect.Listen

	// DirectPacketListener is used for direct UDP listening when
	// Filter returns true.
	//
	// Default: net.ListenUDP
	DirectPacketListener gonnect.PacketListen

	// Resolver is used for DNS lookups.
	//
	// Used for SOCKS4 (non-4a) clients and Tor LookupIP/LookupAddr
	// requests when Filter returns true.
	//
	// Default: net.DefaultResolver
	Resolver gonnect.Resolver

	// HandshakeTimeout specifies the timeout for SOCKS handshake.
	//
	// If zero, uses context deadline or no timeout.
	//
	// Default: 0 (no explicit timeout)
	HandshakeTimeout time.Duration

	// Smux configures connection multiplexing for Gost MBIND.
	//
	// Only used when GostMbind is true.
	//
	// Example:
	//
	//	client.Smux = &smux.Config{
	//	    MaxFrameSize:     65535,
	//	    MaxReceiveBuffer: 4194304,
	//	}
	Smux *smux.Config

	// TLS enables TLS for the proxy connection.
	//
	// When true, the connection to ProxyAddr is wrapped in TLS.
	// TLSConfig controls certificate verification and other TLS settings.
	//
	// Default: false
	TLS bool

	// TLSConfig configures TLS behavior.
	//
	// If nil, a default config is used with:
	//   - InsecureSkipVerify: true (disable with "secure" URL option)
	//   - ServerName: Auto-set from ProxyAddr or WebSocketURL
	//
	// Example for secure connections:
	//
	//	client.TLSConfig = &tls.Config{
	//	    InsecureSkipVerify: false,
	//	    ServerName:         "proxy.example.com",
	//	}
	TLSConfig *tls.Config

	// WebSocketURL enables SOCKS over WebSocket transport.
	//
	// When non-empty, connects to this WebSocket URL instead of
	// ProxyAddr. ProxyNet and ProxyAddr are ignored.
	//
	// URL scheme determines encryption:
	//   - "ws://": Plaintext WebSocket
	//   - "wss://": Encrypted WebSocket (TLS)
	//
	// Examples:
	//   - "ws://proxy.example.com/ws"
	//   - "wss://proxy.example.com/socks"
	WebSocketURL string

	// WebSocketConfig configures WebSocket-specific options.
	//
	// If nil, default WebSocket settings are used.
	//
	// See WebSocketConfig for available options.
	WebSocketConfig *WebSocketConfig

	// Pool is a buffer pool for memory-efficient operations.
	//
	// If nil, a no pool is used.
	//
	// Using a shared pool across multiple clients can reduce
	// memory allocations and GC pressure.
	Pool bufpool.Pool
}

// IsNoProxy reports whether the client bypasses the proxy.
//
// Returns true if:
//   - Client is nil
//   - Both ProxyAddr and WebSocketURL are empty
//
// When true, all connections use direct.
func (c *Client) IsNoProxy() bool {
	return c == nil || (c.ProxyAddr == "" && c.WebSocketURL == "")
}

func (c *Client) IsNative() bool {
	return c.IsNoProxy()
}

// Request sends a low-level SOCKS request to the proxy.
//
// Request establishes a connection to the proxy, performs authentication
// if needed, and sends the specified command for the given address.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - cmd: SOCKS command (Connect, Bind, UDPAssoc, or extensions)
//   - address: Target address for the command
//
// # Returns
//
//   - proxy: Established connection to proxy (or target for CONNECT)
//   - addr: Bound address from server (relevant for BIND/UDPAssoc)
//   - err: Error if connection, auth, or request fails
//
// # Behavior
//
// On success, the connection deadline is cleared for indefinite use.
// On error, the connection is closed.
//
// # Examples
//
//	// CONNECT command
//	conn, _, err := client.Request(ctx, protocol.CmdConnect,
//	    protocol.AddrFromHostPort("example.com:80", "tcp"))
//
//	// BIND command
//	listener, bindAddr, err := client.Request(ctx, protocol.CmdBind,
//	    protocol.AddrFromHostPort("0.0.0.0:0", "tcp"))
//
// # See Also
//
//   - Dial: High-level TCP connection
//   - DialPacket: High-level UDP connection
//   - Listen: High-level BIND
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

// Dial establishes a TCP connection through the SOCKS proxy.
//
// Dial is the primary method for creating TCP connections through the proxy.
// It handles network validation, filter checking, and SOCKS protocol handshake.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - network: Network type ("tcp", "tcp4", "tcp6")
//   - address: Target address in host:port format
//
// # Returns
//
// Established net.Conn or error.
//
// # Behavior
//
//  1. Validates network support for the SOCKS version
//  2. Checks Filter - if true, dials directly
//  3. Sends CONNECT command through proxy
//  4. Returns established connection
//
// # UDP Networks
//
// If network is "udp", "udp4", or "udp6", DialPacket is called instead.
//
// # Examples
//
//	// Basic connection
//	conn, err := client.Dial(ctx, "tcp", "example.com:80")
//
//	// With timeout context
//	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
//	defer cancel()
//	conn, err := client.Dial(ctx, "tcp", "example.com:443")
//
//	// Direct connection via filter
//	client.Filter = socksgo.BuildFilter("localhost")
//	conn, err := client.Dial(ctx, "tcp", "localhost:8080") // Direct, not via proxy
//
// # Errors
//
// Returns WrongNetworkError for unsupported networks.
// Returns RejectdError if server rejects the connection.
//
// # See Also
//
//   - DialPacket: UDP connections
//   - Listen: BIND command for incoming connections
//   - Request: Low-level SOCKS request
func (c *Client) Dial(
	ctx context.Context,
	network, address string,
) (net.Conn, error) {
	if network == "udp" || network == "udp4" || network == "udp6" {
		return c.PacketDial(ctx, network, address)
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

// PacketDial establishes a UDP connection through the SOCKS proxy.
//
// PacketDial creates a PacketConn for UDP communication through the proxy.
// It supports both standard UDP ASSOCIATE and Gost UDP Tunnel extensions.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - network: Network type ("udp", "udp4", "udp6")
//   - address: Target address in host:port format
//
// # Returns
//
// PacketConn for UDP communication or error.
//
// # Behavior
//
//  1. Validates network support
//  2. Checks Filter - if true, dials UDP directly
//  3. If GostUDPTun enabled: Uses UDP tunnel over TCP
//  4. Otherwise: Uses standard UDP ASSOCIATE
//
// # Gost UDP Tunnel
//
// When GostUDPTun is true, UDP is encapsulated in TCP.
//
// # Examples
//
//	// DNS query through proxy
//	conn, err := client.PacketDial(ctx, "udp", "8.8.8.8:53")
//	if err == nil {
//	    _, err := conn.Write(dnsQuery)
//	    _, err = conn.Read(response)
//	}
//
//	// Gost UDP tunnel
//	client.GostUDPTun = true
//	conn, err := client.PacketDial(ctx, "udp", "target:123")
//
// # See Also
//
//   - ListenPacket: Listen for UDP packets
//   - Dial: TCP connections
func (c *Client) PacketDial(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
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

// ListenPacket listens for UDP packets through the SOCKS proxy.
//
// ListenPacket creates a UDP listener that receives packets through
// the SOCKS proxy. It supports both standard UDP ASSOCIATE and
// Gost UDP Tunnel extensions.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - network: Network type ("udp", "udp4", "udp6")
//   - address: Local address to listen on (use "0.0.0.0:0" for any)
//
// # Returns
//
// PacketConn for receiving UDP packets or error.
//
// # Behavior
//
//  1. Validates network support
//  2. Checks Filter - if true, listens directly
//  3. If GostUDPTun enabled: Uses UDP tunnel over TCP
//  4. Otherwise: Uses standard UDP ASSOCIATE
//
// # Gost UDP Tunnel
//
// When GostUDPTun is true, creates a bound UDP tunnel. The server
// acts like NAT and doesn't return the bound address - use STUN or
// similar to discover the external address.
//
// # Standard UDP ASSOCIATE
//
// For standard UDP ASSOCIATE, the laddr parameter is ignored. The
// server assigns a UDP port and returns it in the BIND address.
//
// # Examples
//
//	// Listen on any available port
//	conn, err := client.ListenPacket(ctx, "udp", "0.0.0.0:0")
//
//	// Gost UDP tunnel (bound)
//	client.GostUDPTun = true
//	conn, err := client.ListenPacket(ctx, "udp", "0.0.0.0:0")
//	// Use STUN to discover external address
//
// # See Also
//
//   - DialPacket: Send UDP packets
//   - Listen: TCP BIND command
func (c *Client) ListenPacket(
	ctx context.Context,
	network, address string,
) (gonnect.PacketConn, error) {
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

// Listen establishes a TCP listener through the SOCKS proxy (BIND command).
//
// Listen uses the SOCKS BIND command to create a listener on the proxy
// server that forwards incoming connections to the client.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - network: Network type ("tcp", "tcp4", "tcp6")
//   - address: Local address to bind (use "0.0.0.0:0" for any)
//
// # Returns
//
// net.Listener for accepting connections or error.
//
// # Behavior
//
//  1. Validates network support
//  2. Checks Filter - if true, listens directly
//  3. Sends BIND command to proxy
//  4. Returns listener for incoming connections
//
// # Examples
//
//	// Listen for incoming connections
//	listener, err := client.Listen(ctx, "tcp", "0.0.0.0:0")
//	if err == nil {
//	    for {
//	        conn, err := listener.Accept()
//	        if err != nil {
//	            break
//	        }
//	        go handleConnection(conn)
//	    }
//	}
//
// # See Also
//
//   - Dial: Outgoing TCP connections
//   - DialPacket: UDP connections
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
			return c.listenSmuxWithHook(conn, addr)
		}
		return &clientListener5{
			conn: conn,
			addr: addr,
		}, nil
	}
	testListenCloseHook(conn)
	return nil, UnknownSocksVersionError{ver}
}

// LookupIP performs a forward DNS lookup through the SOCKS proxy.
//
// LookupIP uses Tor's SOCKS extension to resolve hostnames to IP addresses
// through the proxy. This provides DNS privacy by preventing DNS leaks.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - network: IP version ("ip", "ip4", "ip6")
//   - address: Hostname to resolve
//
// # Returns
//
// Slice of resolved IP addresses or error.
//
// # Requirements
//
// TorLookup must be enabled. Returns ErrResolveDisabled if not set.
//
// # IP types Note
//
// Due to Tor SOCKS extension limitations, the returned IP version may
// differ from the requested network
// (e.g., ipv6 when ipv4 was requested or vise versa).
//
// # Examples
//
//	// Enable Tor lookup
//	client.TorLookup = true
//
//	// Resolve hostname
//	ips, err := client.LookupIP(ctx, "ip4", "example.com")
//	if err == nil && len(ips) > 0 {
//	    fmt.Printf("Resolved to: %v\n", ips[0])
//	}
//
// # Errors
//
// Returns *net.DNSError with ErrResolveDisabled if TorLookup is false.
//
// # See Also
//
//   - LookupAddr: Reverse DNS lookup
//   - net.Resolver.LookupIP: Standard DNS lookup
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

	return c.lookupIPWithHook(ctx, network, address, addr)
}

// LookupAddr performs a reverse DNS lookup through the SOCKS proxy.
//
// LookupAddr uses Tor's SOCKS extension to resolve IP addresses to
// hostnames through the proxy. This provides DNS privacy for reverse
// lookups.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - address: IP address to resolve (as string)
//
// # Returns
//
// Slice of resolved hostnames or error.
//
// # Requirements
//
// TorLookup must be enabled. Returns ErrResolveDisabled if not set.
//
// # Examples
//
//	// Enable Tor lookup
//	client.TorLookup = true
//
//	// Reverse lookup
//	names, err := client.LookupAddr(ctx, "8.8.8.8")
//	if err == nil && len(names) > 0 {
//	    fmt.Printf("Resolved to: %s\n", names[0])
//	}
//
// # Errors
//
// Returns *net.DNSError with ErrResolveDisabled if TorLookup is false.
//
// # See Also
//
//   - LookupIP: Forward DNS lookup
//   - net.Resolver.LookupAddr: Standard reverse lookup
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

	return c.lookupAddrWithHook(ctx, addr)
}

// LookupIPAddr performs a DNS lookup through the SOCKS proxy and returns IPAddr structs.
//
// LookupIPAddr wraps LookupIP to return []net.IPAddr instead of []net.IP.
// This provides compatibility with net.Resolver.LookupIPAddr.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - host: Hostname to resolve
//
// # Returns
//
// Slice of net.IPAddr containing resolved IP addresses and their network type.
//
// # Requirements
//
// TorLookup must be enabled. Returns ErrResolveDisabled if not set.
//
// # Examples
//
//	client.TorLookup = true
//	addrs, err := client.LookupIPAddr(ctx, "example.com")
//	if err == nil && len(addrs) > 0 {
//	    fmt.Printf("Resolved to: %v\n", addrs[0].IP)
//	}
//
// # See Also
//
//   - LookupIP: Returns []net.IP
//   - net.Resolver.LookupIPAddr: Standard DNS lookup
func (c *Client) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	ips, err := c.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	addrs := make([]net.IPAddr, len(ips))
	for i, ip := range ips {
		addrs[i] = net.IPAddr{IP: ip}
	}
	return addrs, nil
}

// LookupNetIP performs a DNS lookup through the SOCKS proxy and returns netip.Addr structs.
//
// LookupNetIP wraps LookupIP to return []netip.Addr instead of []net.IP.
// This provides compatibility with net.Resolver.LookupNetIP.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - network: Network type ("ip", "ip4", "ip6")
//   - host: Hostname to resolve
//
// # Returns
//
// Slice of netip.Addr containing resolved IP addresses.
//
// # Requirements
//
// TorLookup must be enabled. Returns ErrResolveDisabled if not set.
//
// # Examples
//
//	client.TorLookup = true
//	addrs, err := client.LookupNetIP(ctx, "ip4", "example.com")
//	if err == nil && len(addrs) > 0 {
//	    fmt.Printf("Resolved to: %v\n", addrs[0])
//	}
//
// # See Also
//
//   - LookupIP: Returns []net.IP
//   - net.Resolver.LookupNetIP: Standard DNS lookup
func (c *Client) LookupNetIP(
	ctx context.Context,
	network, host string,
) ([]netip.Addr, error) {
	ips, err := c.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if ok {
			addrs = append(addrs, addr)
		}
	}
	return addrs, nil
}

// LookupHost performs a DNS lookup through the SOCKS proxy and returns address strings.
//
// LookupHost wraps LookupIP to return []string instead of []net.IP.
// This provides compatibility with net.Resolver.LookupHost.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - host: Hostname to resolve
//
// # Returns
//
// Slice of IP address strings.
//
// # Requirements
//
// TorLookup must be enabled. Returns ErrResolveDisabled if not set.
//
// # Examples
//
//	client.TorLookup = true
//	addrs, err := client.LookupHost(ctx, "example.com")
//	if err == nil && len(addrs) > 0 {
//	    fmt.Printf("Resolved to: %s\n", addrs[0])
//	}
//
// # See Also
//
//   - LookupIP: Returns []net.IP
//   - net.Resolver.LookupHost: Standard DNS lookup
func (c *Client) LookupHost(
	ctx context.Context,
	host string,
) ([]string, error) {
	ips, err := c.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = ip.String()
	}
	return addrs, nil
}

// DialTCP establishes a TCP connection through the SOCKS proxy with
// explicit local and remote addresses.
//
// DialTCP is similar to Dial but returns a gonnect.TCPConn instead of
// net.Conn. The laddr parameter is ignored as SOCKS proxies don't
// support binding to specific local addresses.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - network: Network type ("tcp", "tcp4", "tcp6")
//   - laddr: Local address (ignored)
//   - raddr: Remote address in host:port format
//
// # Returns
//
// gonnect.TCPConn or error.
//
// # Examples
//
//	conn, err := client.DialTCP(ctx, "tcp", "", "example.com:80")
//
// # See Also
//
//   - Dial: TCP connections without TCPConn interface
//   - ListenTCP: TCP listener
func (c *Client) DialTCP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.TCPConn, error) {
	conn, err := c.Dial(ctx, network, raddr)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(gonnect.TCPConn); ok {
		return tcpConn, nil
	}
	return &tcpConnWrapper{conn}, nil
}

// ListenTCP establishes a TCP listener through the SOCKS proxy.
//
// ListenTCP uses the SOCKS BIND command to create a listener on the
// proxy server.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - network: Network type ("tcp", "tcp4", "tcp6")
//   - laddr: Local address to bind (ignored, use "0.0.0.0:0")
//
// # Returns
//
// gonnect.TCPListener or error.
//
// # Examples
//
//	listener, err := client.ListenTCP(ctx, "tcp", "", "0.0.0.0:0")
//
// # See Also
//
//   - Listen: TCP listener without TCPListener interface
//   - DialTCP: TCP connections
func (c *Client) ListenTCP(
	ctx context.Context,
	network, laddr string,
) (gonnect.TCPListener, error) {
	listener, err := c.Listen(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	if tcpListener, ok := listener.(gonnect.TCPListener); ok {
		return tcpListener, nil
	}
	// This should not happen as our listener types already implement TCPListener
	return nil, fmt.Errorf("listener does not implement gonnect.TCPListener")
}

// DialUDP establishes a UDP connection through the SOCKS proxy with
// explicit local and remote addresses.
//
// DialUDP is similar to PacketDial but returns a gonnect.UDPConn
// instead of gonnect.PacketConn. The laddr parameter is ignored.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - network: Network type ("udp", "udp4", "udp6")
//   - laddr: Local address (ignored)
//   - raddr: Remote address in host:port format
//
// # Returns
//
// gonnect.UDPConn or error.
//
// # Examples
//
//	conn, err := client.DialUDP(ctx, "udp", "", "8.8.8.8:53")
//
// # See Also
//
//   - PacketDial: UDP connections without UDPConn interface
//   - ListenUDP: UDP listener
func (c *Client) DialUDP(
	ctx context.Context,
	network, laddr, raddr string,
) (gonnect.UDPConn, error) {
	conn, err := c.PacketDial(ctx, network, raddr)
	if err != nil {
		return nil, err
	}
	if udpConn, ok := conn.(gonnect.UDPConn); ok {
		return udpConn, nil
	}
	// This should not happen as our UDP client types already implement UDPConn
	return nil, fmt.Errorf("connection does not implement gonnect.UDPConn")
}

// ListenUDP establishes a UDP listener through the SOCKS proxy.
//
// ListenUDP creates a UDP listener that receives packets through the
// SOCKS proxy. The laddr parameter determines the local binding
// address.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//   - network: Network type ("udp", "udp4", "udp6")
//   - laddr: Local address to listen on (use "0.0.0.0:0" for any)
//
// # Returns
//
// gonnect.UDPConn or error.
//
// # Examples
//
//	conn, err := client.ListenUDP(ctx, "udp", "0.0.0.0:0")
//
// # See Also
//
//   - ListenPacket: UDP listener without UDPConn interface
//   - DialUDP: UDP connections
func (c *Client) ListenUDP(
	ctx context.Context,
	network, laddr string,
) (gonnect.UDPConn, error) {
	conn, err := c.ListenPacket(ctx, network, laddr)
	if err != nil {
		return nil, err
	}
	if udpConn, ok := conn.(gonnect.UDPConn); ok {
		return udpConn, nil
	}
	// This should not happen as our UDP client types already implement UDPConn
	return nil, fmt.Errorf("connection does not implement gonnect.UDPConn")
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
	// Test hook for bypassing normal flow (only compiled with testhooks tag)
	if conn, a, ok := testRequestHook(ctx, cmd, address); ok {
		return conn, a, nil
	}

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
		ipaddr := address.ResolveToIP4(ctx, c.GetResolver().LookupIP)
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
