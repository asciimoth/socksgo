package socksgo

// Client configuration and connection helpers.
//
// This file contains the Client configuration struct, URL/ENV parsing,
// and helper methods for establishing connections to SOCKS proxies.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo/protocol"
	cws "github.com/coder/websocket"
	"github.com/gorilla/websocket"
)

// Tor stream isolation constants.
// See: https://spec.torproject.org/socks-extensions.html#extended-auth
const (
	// torMagicPrefix is the magic sequence indicating Tor extended authentication.
	// ASCII: <torS0X>
	torMagicPrefix = "\x3c\x74\x6f\x72\x53\x30\x58\x3e"

	// torFormatType0 is the format type for simple stream isolation.
	// Format: Username = <torS0X>0, Password = stream isolation parameter
	torFormatType0 = "0"

	// torMaxPasswordLen is the maximum password length per SOCKS5 spec (RFC 1929).
	torMaxPasswordLen = 255

	// torRandomIDBytes is the number of random bytes used for generating
	// stream isolation IDs when none is provided.
	torRandomIDBytes = 16
)

// wsBufferPoolAdapter adapts bufpool.Pool to websocket.BufferPool
type wsBufferPoolAdapter struct {
	pool bufpool.Pool
}

func (a *wsBufferPoolAdapter) Get() any {
	if a.pool == nil {
		return nil
	}
	return bufpool.GetBuffer(a.pool, 0)
}

func (a *wsBufferPoolAdapter) Put(x any) {
	if a.pool == nil {
		return
	}
	if buf, ok := x.([]byte); ok {
		bufpool.PutBuffer(a.pool, buf)
	}
}

// WebSocketConfig configures WebSocket connections for SOCKS over WS.
//
// WebSocketConfig provides options for customizing WebSocket dialing
// when using SOCKS over WebSocket transport (WebSocketURL is set).
//
// # Examples
//
//	client := &socksgo.Client{
//	    SocksVersion:   "5",
//	    WebSocketURL:   "wss://proxy.example.com/ws",
//	    WebSocketConfig: &socksgo.WebSocketConfig{
//	        ReadBufferSize:    32768,
//	        Subprotocols:      []string{"binary"},
//	        EnableCompression: true,
//	        RequestHeader: http.Header{
//	            "X-Custom-Header": []string{"value"},
//	        },
//	    },
//	}
//
// # See Also
//
//   - Client.WebSocketURL: Enable WebSocket transport
//   - github.com/gorilla/websocket: Underlying WebSocket library
type WebSocketConfig struct {
	// ReadBufferSize is the buffer size for WebSocket reads.
	//
	// If zero, websocket.DefaultDialer.ReadBufferSize is used.
	ReadBufferSize int

	// Subprotocols is the list of WebSocket subprotocols to negotiate.
	//
	// If nil, websocket.DefaultDialer.Subprotocols is used.
	Subprotocols []string

	// EnableCompression enables per-message compression (RFC 7692).
	//
	// If false, compression is disabled.
	//
	// Default: false (websocket.DefaultDialer.EnableCompression)
	EnableCompression bool

	// Jar is the cookie jar for HTTP cookies during WebSocket handshake.
	//
	// If nil, websocket.DefaultDialer.Jar is used.
	Jar http.CookieJar

	// RequestHeader contains custom HTTP headers for WebSocket upgrade request.
	RequestHeader http.Header
}

func (w *WebSocketConfig) jar() http.CookieJar {
	if w == nil {
		return websocket.DefaultDialer.Jar
	}
	return w.Jar
}

func (w *WebSocketConfig) readBufferSize() int {
	if w == nil {
		return websocket.DefaultDialer.ReadBufferSize
	}
	return w.ReadBufferSize
}

func (w *WebSocketConfig) subprotocols() []string {
	if w == nil {
		return websocket.DefaultDialer.Subprotocols
	}
	return w.Subprotocols
}

func (w *WebSocketConfig) enableCompression() bool {
	if w == nil {
		return websocket.DefaultDialer.EnableCompression
	}
	return w.EnableCompression
}

var _ Network = &Client{}

// Network is a subset of gonnect.Network.
type Network interface {
	Dial(
		ctx context.Context,
		network, address string,
	) (net.Conn, error)

	Listen(
		ctx context.Context,
		network, address string,
	) (net.Listener, error)

	PacketDial(
		ctx context.Context,
		network, address string,
	) (gonnect.PacketConn, error)

	ListenPacket(
		ctx context.Context,
		network, address string,
	) (gonnect.PacketConn, error)
}

func (c *Client) WithNetwork(network Network) {
	if network == nil {
		return
	}
	c.Dialer = network.Dial
	c.DirectListener = network.Listen
	c.PacketDialer = network.PacketDial
	c.DirectPacketListener = network.ListenPacket
}

// Version returns the SOCKS protocol version.
//
// Returns "5" as default if SocksVersion is empty.
//
// # Returns
//
// "4", "4a", "5", or "5" (default)
func (c *Client) Version() string {
	if c.SocksVersion == "" {
		return "5"
	}
	return c.SocksVersion
}

// GetNet returns the network type for proxy connections.
//
// Returns "tcp" as default if ProxyNet is empty.
//
// # Returns
//
// ProxyNet or "tcp" (default)
func (c *Client) GetNet() string {
	if c == nil {
		return "tcp"
	}
	if c.ProxyNet == "" {
		return "tcp"
	}
	return c.ProxyNet
}

// GetAddr returns the proxy server address with default port.
//
// If ProxyAddr doesn't contain a port, appends ":1080" (default SOCKS port).
//
// # Returns
//
// ProxyAddr or ProxyAddr:1080 if no port specified.
//
// # Examples
//
//	client.ProxyAddr = "proxy.example.com"
//	addr := client.GetAddr() // Returns "proxy.example.com:1080"
//
//	client.ProxyAddr = "proxy.example.com:9050"
//	addr := client.GetAddr() // Returns "proxy.example.com:9050"
func (c *Client) GetAddr() string {
	if !strings.Contains(c.ProxyAddr, ":") {
		// Default port
		return net.JoinHostPort(c.ProxyAddr, "1080")
	}
	return c.ProxyAddr
}

// IsTLS reports whether TLS is enabled for the proxy connection.
//
// Returns true if:
//   - TLS field is true, or
//   - WebSocketURL starts with "wss"
//
// # Examples
//
//	client.TLS = true
//	client.IsTLS() // true
//
//	client.WebSocketURL = "wss://proxy.example.com/ws"
//	client.IsTLS() // true
func (c *Client) IsTLS() bool {
	return c.TLS || strings.HasPrefix(c.WebSocketURL, "wss")
}

// IsUDPAllowed reports whether UDP operations are permitted.
//
// Returns true if:
//   - TLS is not enabled, or
//   - InsecureUDP is true (allows plaintext UDP over TLS)
//
// # Security Warning
//
// When TLS is enabled and InsecureUDP is true, UDP packets are sent
// unencrypted. This is a security risk!
//
// # Examples
//
//	client.TLS = false
//	client.IsUDPAllowed() // true
//
//	client.TLS = true
//	client.InsecureUDP = false
//	client.IsUDPAllowed() // false (UDP blocked over TLS)
//
//	client.TLS = true
//	client.InsecureUDP = true // NOT RECOMMENDED
//	client.IsUDPAllowed() // true (but UDP is plaintext!)
func (c *Client) IsUDPAllowed() bool {
	return !c.IsTLS() || c.InsecureUDP
}

// DoFilter checks if a connection should bypass the proxy.
//
// DoFilter evaluates the Filter function to determine if a connection
// should use direct dialing instead of going through the proxy.
//
// # Parameters
//
//   - network: Network type (may be "" if unknown)
//   - address: Target address (host:port format)
//
// # Returns
//
//   - true: Use direct connection (bypass proxy)
//   - false: Use SOCKS proxy
//
// # Behavior
//
//  1. If IsNoProxy() returns true: Always returns true (all direct)
//  2. If Filter is nil: Uses LoopbackFilter
//  3. Otherwise: Calls Filter(network, address)
//
// # Examples
//
//	client.Filter = socksgo.BuildFilter("localhost,192.168.0.0/16")
//
//	client.DoFilter("tcp", "localhost:8080")  // true (direct)
//	client.DoFilter("tcp", "example.com:80")  // false (proxy)
func (c *Client) DoFilter(network, address string) bool {
	if c.IsNoProxy() {
		// All connections goes directly
		return true
	}
	filter := gonnect.LoopbackFilter
	if c.Filter != nil {
		filter = c.Filter
	}
	return filter(network, address)
}

// GetListener returns the TCP listener for direct connections.
//
// Returns DirectListener if set, otherwise uses net.ListenConfig.Listen.
//
// # Returns
//
// Listener function for creating TCP listeners.
//
// # See Also
//
//   - DirectListener: Custom listener configuration
func (c *Client) GetListener() gonnect.Listen {
	if c.DirectListener == nil {
		return (&net.ListenConfig{}).Listen
	}
	return c.DirectListener
}

// GetPacketListener returns the UDP packet listener for direct connections.
//
// Returns DirectPacketListener if set, otherwise creates a UDP listener
// using net.ListenUDP.
//
// # Returns
//
// PacketListener function for creating UDP listeners.
//
// # See Also
//
//   - DirectPacketListener: Custom listener configuration
func (c *Client) GetPacketListener() gonnect.PacketListen {
	if c.DirectPacketListener == nil {
		return func(ctx context.Context, network, laddr string) (gonnect.PacketConn, error) {
			udpAddr := protocol.AddrFromHostPort(laddr, network).ToUDP()
			return net.ListenUDP(network, udpAddr)
		}
	}
	return c.DirectPacketListener
}

// GetDialer returns the dialer for TCP connections.
//
// Returns Dialer if set, otherwise uses net.Dialer.DialContext.
//
// # Returns
//
// Dialer function for establishing TCP connections.
//
// # See Also
//
//   - Dialer: Custom dialer configuration
func (c *Client) GetDialer() gonnect.Dial {
	if c.Dialer == nil {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	return c.Dialer
}

// GetPacketDialer returns the dialer for UDP connections.
//
// Returns PacketDialer if set, otherwise creates UDP connections
// using net.DialUDP.
//
// # Returns
//
// PacketDialer function for establishing UDP connections.
//
// # See Also
//
//   - PacketDialer: Custom dialer configuration
func (c *Client) GetPacketDialer() gonnect.PacketDial {
	if c.Dialer == nil {
		return func(ctx context.Context, network, raddr string) (gonnect.PacketConn, error) {
			udpAddr := protocol.AddrFromHostPort(raddr, network).ToUDP()
			return net.DialUDP(network, nil, udpAddr)
		}
	}
	return c.PacketDialer
}

// GetResolver returns the DNS resolver for lookups.
//
// Returns Resolver if set, otherwise uses net.DefaultResolver.
//
// # Returns
//
// Resolver for DNS lookups.
//
// # See Also
//
//   - Resolver: Custom resolver configuration
//   - net.DefaultResolver: System default resolver
func (c *Client) GetResolver() gonnect.Resolver {
	if c.Resolver == nil {
		return net.DefaultResolver
	}
	return c.Resolver
}

// GetTLSConfig builds the TLS configuration for secure connections.
//
// GetTLSConfig creates a TLS configuration from TLSConfig field or
// returns a default configuration. If TLS is not enabled, returns nil.
//
// # Behavior
//
//  1. If !IsTLS(): Returns nil
//  2. If TLSConfig is nil: Creates default config
//  3. Clones TLSConfig to avoid mutation
//  4. Sets ServerName from ProxyAddr if empty
//
// # ServerName
//
// If TLSConfig.ServerName is empty, extracts the hostname from
// GetAddr() (removes port).
//
// # Returns
//
// *tls.Config for TLS connections, or nil if TLS is disabled.
//
// # Examples
//
//	// Default TLS config
//	client.TLS = true
//	config := client.GetTLSConfig()
//	// config.InsecureSkipVerify = true (default)
//	// config.ServerName = "proxy.example.com" (from ProxyAddr)
//
//	// Custom TLS config
//	client.TLSConfig = &tls.Config{
//	    InsecureSkipVerify: false,
//	    ServerName:         "custom.example.com",
//	}
//	config := client.GetTLSConfig()
func (c *Client) GetTLSConfig() (config *tls.Config) {
	if !c.IsTLS() {
		return nil
	}
	sname := c.GetAddr()
	h, _, err := net.SplitHostPort(sname)
	if err == nil {
		sname = h
	}

	config = &tls.Config{} //nolint
	if c.TLSConfig != nil {
		config = c.TLSConfig.Clone()
	}
	if config.ServerName == "" {
		config.ServerName = sname
	}

	return config
}

// GetHandshakeTimeout returns the SOCKS handshake timeout.
//
// # Returns
//
// HandshakeTimeout duration, or 0 if not set.
func (c *Client) GetHandshakeTimeout() time.Duration {
	if c == nil {
		return 0
	}
	return c.HandshakeTimeout
}

// GetWsDialer builds the WebSocket dialer options for SOCKS over WS.
//
// GetWsDialer creates coder/websocket.DialOptions configured from WebSocketConfig,
// GetDialer, and GetTLSConfig. Returns nil if WebSocketURL is empty.
//
// # Configuration
//
// The dialer is configured with:
//   - HTTPClient: Uses custom Dialer via Transport for TCP connections
//   - Subprotocols: From WebSocketConfig
//   - CompressionMode: From WebSocketConfig.EnableCompression
//   - HTTPHeader: From WebSocketConfig.RequestHeader
//
// # Returns
//
// *websocket.DialOptions for WebSocket connections, or nil if WebSocketURL is empty.
//
// # See Also
//
//   - WebSocketConfig: WebSocket configuration options
//   - github.com/coder/websocket: Underlying WebSocket library
func (c *Client) GetWsDialer() *cws.DialOptions {
	if c.WebSocketURL == "" {
		return nil
	}

	httpClient := &http.Client{
		Jar: c.WebSocketConfig.jar(),
	}
	tlsConfig := c.GetTLSConfig()

	if tlsConfig != nil || c.Dialer != nil {
		transport := &http.Transport{}
		if c.Dialer != nil {
			transport.DialContext = c.Dialer
		}
		if tlsConfig != nil {
			transport.TLSClientConfig = tlsConfig
		}
		httpClient.Transport = transport
	}

	// Configure compression
	compressionMode := cws.CompressionDisabled
	var httpHeader http.Header
	var subprotocols []string

	if c.WebSocketConfig != nil {
		if c.WebSocketConfig.enableCompression() {
			compressionMode = cws.CompressionContextTakeover
		}
		httpHeader = c.WebSocketConfig.RequestHeader
		subprotocols = c.WebSocketConfig.subprotocols()
	}

	return &cws.DialOptions{
		HTTPClient:      httpClient,
		HTTPHeader:      httpHeader,
		Subprotocols:    subprotocols,
		CompressionMode: compressionMode,
	}
}

// connectWebSocket establishes a WebSocket connection to the proxy.
//
// connectWebSocket dials the WebSocket URL and wraps the connection
// in a wsConn for use with the SOCKS protocol.
//
// # Parameters
//
//   - ctx: Context for cancellation and timeouts
//
// # Returns
//
// Established net.Conn over WebSocket or error.
//
// # Behavior
//
//  1. Gets WebSocket dialer from GetWsDialer()
//  2. Dials WebSocketURL with optional headers
//  3. Wraps connection in wsConn
//  4. Closes response body
//
// # See Also
//
//   - Connect: High-level connection method
//   - wsConn: WebSocket connection wrapper
func (c *Client) connectWebSocket(
	ctx context.Context,
) (conn net.Conn, err error) {
	ws, resp, err := cws.Dial(ctx, c.WebSocketURL, c.GetWsDialer())
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	return &wsCoderConn{
		Conn: cws.NetConn(ctx, ws, cws.MessageBinary),
	}, nil
}

// Connect establishes a connection to the SOCKS proxy server.
//
// Connect creates a TCP or WebSocket connection to the proxy server
// and applies TLS if configured. It's used internally by Request()
// but can be called directly for low-level control.
//
// # Returns
//
// Established net.Conn to the proxy server or error.
//
// # Behavior
//
//  1. If WebSocketURL is set: Establishes WebSocket connection
//  2. Otherwise: Dials ProxyAddr using Dialer
//  3. If TLS enabled: Wraps connection in TLS
//  4. Sets handshake timeout deadline
//
// # WebSocket
//
// When WebSocketURL is set, connects via WebSocket and returns
// a wrapped connection. ProxyAddr is ignored.
//
// # TLS
//
// When TLS is true (or WebSocketURL starts with "wss"), wraps
// the connection in TLS using GetTLSConfig().
//
// # Timeout
//
// Uses HandshakeTimeout if set, otherwise uses context deadline.
//
// # Examples
//
//	// Direct connection to proxy
//	conn, err := client.Connect(ctx)
//	if err != nil {
//	    return err
//	}
//	defer conn.Close()
//
//	// Use with Request for manual control
//	conn, err := client.Connect(ctx)
//	// Send custom SOCKS request...
//
// # See Also
//
//   - Request: High-level SOCKS request
//   - Dial: High-level TCP connection
//   - GetTLSConfig: TLS configuration
func (c *Client) Connect(ctx context.Context) (conn net.Conn, err error) {
	if c.WebSocketURL != "" {
		conn, err = c.connectWebSocket(ctx)
	} else {
		conn, err = c.GetDialer()(ctx, c.GetNet(), c.GetAddr())
	}

	if err != nil {
		return nil, err
	}

	if c.WebSocketURL == "" && c.IsTLS() {
		conn = tls.Client(conn, c.GetTLSConfig())
	}

	timeout := c.GetHandshakeTimeout()
	if timeout == 0 {
		// Use context deadline if no explicit handshake timeout is set
		if deadline, ok := ctx.Deadline(); ok {
			err = conn.SetDeadline(deadline)
		} else {
			err = conn.SetDeadline(time.Time{})
		}
	} else {
		err = conn.SetDeadline(time.Now().Add(timeout))
	}

	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return
}

// CheckNetworkSupport validates network support for the SOCKS version.
//
// CheckNetworkSupport checks if the requested network type is supported
// by the configured SOCKS protocol version.
//
// # Parameters
//
//   - net: Network type to validate ("tcp", "tcp4", "tcp6", "udp", etc.)
//
// # Returns
//
// nil if supported, WrongNetworkError if not.
//
// # Supported Networks
//
// SOCKS5:
//   - tcp, tcp4, tcp6
//   - udp, udp4, udp6
//
// SOCKS4/4a:
//   - tcp, tcp4 (UDP not supported)
//
// # Examples
//
//	err := client.CheckNetworkSupport("tcp")    // nil
//	err := client.CheckNetworkSupport("udp")    // nil for SOCKS5
//	err := client.CheckNetworkSupport("unix")   // WrongNetworkError
//
//	client.SocksVersion = "4"
//	err := client.CheckNetworkSupport("udp")    // WrongNetworkError
func (c *Client) CheckNetworkSupport(net string) error {
	ver := c.Version()
	_, ok := supportedNetworks[net]
	if !ok {
		return WrongNetworkError{
			SocksVersion: ver,
			Network:      net,
		}
	}
	if (ver == "4" || ver == "4a") && net != "tcp" && net != "tcp4" {
		return WrongNetworkError{
			SocksVersion: ver,
			Network:      net,
		}
	}
	return nil
}

// WithTorIsolation creates a copy of the Client with Tor stream isolation enabled.
//
// WithTorIsolation implements the Tor SOCKS extension for stream isolation
// as specified in https://spec.torproject.org/socks-extensions.html#extended-auth
//
// The method configures the client to use extended authentication with format
// type 0, where the stream isolation parameter is sent in the password field.
//
// # Parameters
//
//   - id: Pointer to stream isolation ID string. If nil, a random ID is generated.
//
// # Behavior
//
//  1. Creates a shallow copy of the Client
//  2. Generates or uses the provided stream isolation ID
//  3. Trims the ID if it exceeds the maximum password length (255 bytes)
//  4. Sets username to "<torS0X>0" (magic prefix + format type 0)
//  5. Sets password to the stream isolation ID
//  6. Removes all other authentication methods
//
// # Stream Isolation
//
// Streams with different isolation IDs will use separate Tor circuits.
// Streams with the same isolation ID may share a circuit.
//
// # Examples
//
//	// Client with random stream isolation
//	client := &socksgo.Client{
//	    SocksVersion: "5",
//	    ProxyAddr:    "127.0.0.1:9050",
//	}
//	isolatedClient := client.WithTorIsolation(nil)
//
//	// Client with specific isolation ID
//	client := &socksgo.Client{
//	    SocksVersion: "5",
//	    ProxyAddr:    "127.0.0.1:9050",
//	}
//	sessionID := "user-session-123"
//	isolatedClient := client.WithTorIsolation(&sessionID)
//
//	// Long IDs are automatically trimmed
//	longID := strings.Repeat("x", 300)
//	isolatedClient := client.WithTorIsolation(&longID)
//
// # Notes
//
//   - This method is designed for SOCKS5 clients connecting to Tor
//   - For SOCKS4 or non-Tor proxies, the credentials are sent as-is
//     (behavior depends on proxy implementation)
//   - The original client is not modified; a copy is returned
func (c *Client) WithTorIsolation(id *string) *Client {
	if c == nil {
		return nil
	}

	// Create a shallow copy of the client
	clone := *c

	// Generate or use provided isolation ID
	var isolationID string
	if id == nil {
		isolationID = generateTorIsolationID()
	} else {
		isolationID = *id
	}

	// Trim ID if too long (must fit in password field)
	if len(isolationID) > torMaxPasswordLen {
		isolationID = isolationID[:torMaxPasswordLen]
	}

	// Build Tor extended authentication credentials
	// Format type 0: Username = <torS0X>0, Password = isolation parameter
	username := torMagicPrefix + torFormatType0

	// Create new auth methods with only PassAuth using Tor credentials
	clone.Auth = (&protocol.AuthMethods{}).Add(&protocol.PassAuthMethod{
		User: username,
		Pass: isolationID,
	})

	return &clone
}

// generateTorIsolationID generates a random stream isolation ID.
//
// Generates a cryptographically secure random hex string suitable for
// use as a Tor stream isolation parameter.
//
// # Returns
//
// A hex-encoded random string of 32 characters (16 bytes).
func generateTorIsolationID() string {
	bytes := make([]byte, torRandomIDBytes)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if random generation fails
		// This should never happen in practice
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}
