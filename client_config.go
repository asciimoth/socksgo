package socks

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

func cloneSmuxConfig(src *smux.Config) *smux.Config {
	if src == nil {
		return nil
	}
	return &smux.Config{
		Version:           src.Version,
		KeepAliveDisabled: src.KeepAliveDisabled,
		KeepAliveInterval: src.KeepAliveInterval,
		KeepAliveTimeout:  src.KeepAliveTimeout,
		MaxFrameSize:      src.MaxFrameSize,
		MaxReceiveBuffer:  src.MaxReceiveBuffer,
		MaxStreamBuffer:   src.MaxStreamBuffer,
	}
}

type WebSocketConfig struct {
	ReadBufferSize    int
	Subprotocols      []string
	EnableCompression bool
	Jar               http.CookieJar
	HandshakeTimeout  time.Duration
	RequestHeader     http.Header
}

func (w *WebSocketConfig) handshakeTimeout() time.Duration {
	if w == nil || w.HandshakeTimeout == 0 {
		return websocket.DefaultDialer.HandshakeTimeout
	}
	return w.HandshakeTimeout
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

func (w *WebSocketConfig) jar() http.CookieJar {
	if w == nil {
		return websocket.DefaultDialer.Jar
	}
	return w.Jar
}

func (w *WebSocketConfig) Clone() *WebSocketConfig {
	if w == nil {
		return nil
	}
	var subprotocols []string
	for _, p := range w.Subprotocols {
		subprotocols = append(subprotocols, p)
	}
	cfg := WebSocketConfig{
		ReadBufferSize:    w.ReadBufferSize,
		Subprotocols:      subprotocols,
		EnableCompression: w.EnableCompression,
		Jar:               w.Jar,
		HandshakeTimeout:  w.HandshakeTimeout,
		RequestHeader:     w.RequestHeader.Clone(),
	}
	return &cfg
}

type ClientConfig struct {
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

	// For gost MBIND extension
	Smux *smux.Config

	// Enable socks over tls/ws
	TLS       bool
	TLSConfig *tls.Config

	// If not "" socks over ws/wss will be enabled
	// For ws/wss connections ProxyNet and ProxyAddr are ignored
	WebSocketURL    string
	WebSocketConfig *WebSocketConfig

	Pool protocol.BufferPool
}

func (c *ClientConfig) Version() string {
	if c.SocksVersion == "" {
		return "5"
	}
	return c.SocksVersion
}

// c.ProxyNet or "tcp"
func (c *ClientConfig) GetNet() string {
	if c == nil {
		return "tcp"
	}
	if c.ProxyNet == "" {
		return "tcp"
	}
	return c.ProxyNet
}

// c.ProxyAddr or c.ProxyAddr + ":1080" if no port provided
func (c *ClientConfig) GetAddr() string {
	if !strings.Contains(c.ProxyAddr, ":") {
		// Default port
		return net.JoinHostPort(c.ProxyAddr, "1080")
	}
	return c.ProxyAddr
}

// Return true if c.TLS is true or c.WebSocketURL starts with "wss"
func (c *ClientConfig) IsTLS() bool {
	return c.TLS || strings.HasPrefix(c.WebSocketURL, "wss")
}

// !c.IsTLS() || c.InsecureUDP
func (c *ClientConfig) IsUDPAllowed() bool {
	return !c.IsTLS() || c.InsecureUDP
}

// Run c.Filter or LoopbackFilter if c.Filter is nil.
func (c *ClientConfig) DoFilter(network, address string) bool {
	filter := LoopbackFilter
	if c.Filter != nil {
		filter = c.Filter
	}
	return filter(network, address)
}

// Return c.DirectListener or default net listener.
func (c *ClientConfig) GetListener() Listener {
	if c.DirectListener == nil {
		return (&net.ListenConfig{}).Listen
	}
	return c.DirectListener
}

// Return c.DirectPacketListener or default net UDP listener.
func (c *ClientConfig) GetPacketListener() PacketListener {
	if c.DirectListener == nil {
		return func(ctx context.Context, network, laddr string) (PacketConn, error) {
			udpAddr := protocol.AddrFromHostPort(laddr, network).ToUDP()
			return net.ListenUDP(network, udpAddr)
		}
	}
	return c.DirectPacketListener
}

// Return c.Dialer or default net dialer.
func (c *ClientConfig) GetDialer() Dialer {
	if c.Dialer == nil {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	return c.Dialer
}

// Return c.PacketDialer or default net udp dialer.
func (c *ClientConfig) GetPacketDialer() PacketDialer {
	if c.Dialer == nil {
		return func(ctx context.Context, network, raddr string) (PacketConn, error) {
			udpAddr := protocol.AddrFromHostPort(raddr, network).ToUDP()
			return net.DialUDP(network, nil, udpAddr)
		}
	}
	return c.PacketDialer
}

// Return c.Resolver4 or net.DefaultResolver
func (c *ClientConfig) GetResolver() Resolver {
	if c.Resolver == nil {
		return net.DefaultResolver
	}
	return c.Resolver
}

// Build TLS config from c.TLSConfig or default tls.Config{}.
// If config.ServerName == "", set it to c.GetAddr().
// If !c.IsTLS() always return nil.
func (c *ClientConfig) GetTLSConfig() (config *tls.Config) {
	if !c.IsTLS() {
		return nil
	}
	sname := c.GetAddr()
	h, _, err := net.SplitHostPort(sname)
	if err == nil {
		sname = h
	}

	config = &tls.Config{}
	if c.TLSConfig != nil {
		config = c.TLSConfig.Clone()
	}
	if config.ServerName == "" {
		config.ServerName = sname
	}

	return config
}

// Build webSocket.Dialer from c.WebSocketConfig,
// c.GetDialer() and c.GetTLSConfig.
// if c.WebSocketURL == "" always return nil.
func (c *ClientConfig) GetWsDialer() *websocket.Dialer {
	if c.WebSocketURL == "" {
		return nil
	}
	dialer := &websocket.Dialer{
		NetDialContext:  c.GetDialer(),
		TLSClientConfig: c.GetTLSConfig(),
		// TODO: Convert somehow BufferPool to websocket.BufferPool
		WriteBufferPool: nil,

		HandshakeTimeout:  c.WebSocketConfig.handshakeTimeout(),
		ReadBufferSize:    c.WebSocketConfig.readBufferSize(),
		Subprotocols:      c.WebSocketConfig.subprotocols(),
		EnableCompression: c.WebSocketConfig.enableCompression(),
		Jar:               c.WebSocketConfig.jar(),
	}
	return dialer
}

// Connect to socks over ws proxy
func (c *ClientConfig) connectWebSocket(ctx context.Context) (conn net.Conn, err error) {
	var header http.Header
	if c.WebSocketConfig != nil {
		header = c.WebSocketConfig.RequestHeader
	}
	ws, resp, err := c.GetWsDialer().DialContext(
		ctx,
		c.WebSocketURL,
		header,
	)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()

	return &internal.WSConn{
		Conn: ws,
	}, nil
}

// Connect to proxy server
func (c *ClientConfig) Connect(ctx context.Context) (conn net.Conn, err error) {
	if c.WebSocketURL != "" {
		return c.connectWebSocket(ctx)
	}

	conn, err = c.GetDialer()(ctx, c.GetNet(), c.GetAddr())
	if err != nil {
		return nil, err
	}

	if c.IsTLS() {
		conn = tls.Client(conn, c.GetTLSConfig())
	}

	return
}

func (c *ClientConfig) CheckNetworkSupport(net string) error {
	ver := c.Version()
	_, ok := supportedNetworks[net]
	if !ok {
		return WrongNetworkError{
			SocksVersion: ver,
			Network:      net,
		}
	}
	if (ver == "4" || ver == "4a") && !(net == "tcp" || net == "tcp4") {
		return WrongNetworkError{
			SocksVersion: ver,
			Network:      net,
		}
	}
	return nil
}

func (c *ClientConfig) Clone() *ClientConfig {
	if c == nil {
		return nil
	}
	cfg := ClientConfig{
		SocksVersion: c.SocksVersion,

		ProxyNet:  c.ProxyNet,
		ProxyAddr: c.ProxyAddr,

		Auth: c.Auth.Clone(),

		InsecureUDP:              c.InsecureUDP,
		DoNotSpawnUDPAsocProbber: c.DoNotSpawnUDPAsocProbber,

		GostMbind:  c.GostMbind,
		GostUDPTun: c.GostUDPTun,
		TorLookup:  c.TorLookup,

		Filter: c.Filter,

		Dialer:               c.Dialer,
		PacketDialer:         c.PacketDialer,
		DirectListener:       c.DirectListener,
		DirectPacketListener: c.DirectPacketListener,
		Resolver:             c.Resolver,

		Smux: cloneSmuxConfig(c.Smux),

		TLS:       c.TLS,
		TLSConfig: c.TLSConfig.Clone(),

		WebSocketURL:    c.WebSocketURL,
		WebSocketConfig: c.WebSocketConfig.Clone(),
	}
	return &cfg
}

func clientConfigFromURL(u *url.URL, defaultCfg *ClientConfig) ClientConfig {
	cfg := ClientConfig{}
	if defaultCfg != nil {
		cfg = *defaultCfg.Clone()
	}
	if u == nil {
		return cfg
	}

	version, isTLS, isWS := parseScheme(u.Scheme)
	cfg.SocksVersion = version
	cfg.TLS = isTLS

	cfg.ProxyAddr = u.Host

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
	cfg.WebSocketURL = wsUrl

	q := u.Query()

	if f, s := checkURLBoolKey(q, "gost"); s {
		cfg.GostMbind = f
		cfg.GostUDPTun = f
	}

	if f, s := checkURLBoolKey(q, "tor"); s {
		cfg.TorLookup = f
	}

	if u.User != nil {
		var password string
		if pass, ok := u.User.Password(); ok {
			password = pass
		}
		cfg.Auth = cfg.Auth.Add(&protocol.PassAuthMethod{
			User: u.User.Username(),
			Pass: password,
		})
	}

	if f, s := checkURLBoolKey(q, "pass"); s && f {
		cfg.Filter = PassAllFilter
	}

	cfg.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	if f, s := checkURLBoolKey(q, "secure"); s {
		cfg.TLSConfig.InsecureSkipVerify = !f
	}
	// TODO: Add more TLS related args

	return cfg
}
