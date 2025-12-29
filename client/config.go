package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/asciimoth/socks/common"
	"github.com/asciimoth/socks/internal"
	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

type Credentials struct {
	User     string
	Password string
}

type SmuxConfig struct {
	// SMUX Protocol version, support 1,2
	Version int

	// Disabled keepalive
	KeepAliveDisabled bool

	// KeepAliveInterval is how often to send a NOP command to the remote
	KeepAliveInterval time.Duration

	// KeepAliveTimeout is how long the session
	// will be closed if no data has arrived
	KeepAliveTimeout time.Duration

	// MaxFrameSize is used to control the maximum
	// frame size to sent to the remote
	MaxFrameSize int

	// MaxReceiveBuffer is used to control the maximum
	// number of data in the buffer pool
	MaxReceiveBuffer int

	// MaxStreamBuffer is used to control the maximum
	// number of data per stream
	MaxStreamBuffer int
}

func (s *SmuxConfig) to() *smux.Config {
	if s == nil {
		return nil
	}
	return &smux.Config{
		Version:           s.Version,
		KeepAliveDisabled: s.KeepAliveDisabled,
		KeepAliveInterval: s.KeepAliveInterval,
		KeepAliveTimeout:  s.KeepAliveTimeout,
		MaxFrameSize:      s.MaxFrameSize,
		MaxReceiveBuffer:  s.MaxReceiveBuffer,
		MaxStreamBuffer:   s.MaxStreamBuffer,
	}
}

type WebSocketConfig struct {
	ReadBufferSize    int
	Subprotocols      []string
	EnableCompression bool
	Jar               http.CookieJar
	HandshakeTimeout  time.Duration
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

func checkURLBoolKey(values map[string][]string, key string) (f bool, s bool) {
	val, ok := values[key]
	if ok {
		if len(val) == 0 {
			return true, true
		}
		v := val[0]
		return v == "true" || v == "yes" || v == "ok" || v == "1" || v == "", true
	}
	return false, false
}

type Config struct {
	ProxyNet  string
	ProxyAddr string

	GostMbind       bool
	GostUDPTun      bool
	TorLookup       bool
	SpawnUDPProbber bool
	Dialer          common.Dialer
	DirectListener  common.Listener
	Resolver        common.Resolver
	// Resolve hostname locally instead of passing it to proxy
	// For socks4 LocalResolve == false means socks4a
	LocalResolve bool
	DirectFilter common.DirectFilter
	InsecureUDP  bool // Allow plaintext UDP ASSOC for tls proxies

	Credentials *Credentials
	Pool        common.BufferPool

	Smux *SmuxConfig

	TLS       bool
	TLSConfig *tls.Config

	WebSocketURL    string
	WebSocketConfig *WebSocketConfig
}

// TODO: Test
func configFromURL(u *url.URL, defaultCfg *Config) (Config, error) {
	q := u.Query()
	cfg := Config{}
	if defaultCfg != nil {
		cfg = *defaultCfg
	}
	cfg.ProxyAddr = u.Host
	if f, s := checkURLBoolKey(q, "gost"); s {
		cfg.GostMbind = f
		cfg.GostUDPTun = f
	}
	if f, s := checkURLBoolKey(q, "tor"); s {
		cfg.TorLookup = f
	}
	if f, s := checkURLBoolKey(q, "localresolve"); s {
		cfg.LocalResolve = f
	}
	if u.User != nil {
		creds := Credentials{
			User: u.User.Username(),
		}
		if pass, ok := u.User.Password(); ok {
			creds.Password = pass
		}
		cfg.Credentials = &creds
	}
	if f, s := checkURLBoolKey(q, "pass"); s && f {
		cfg.DirectFilter = PassAll
	}

	cfg.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	if f, s := checkURLBoolKey(q, "secure"); s {
		cfg.TLSConfig.InsecureSkipVerify = !f
	}
	// TODO: Add more TLS related args

	return cfg, nil
}

type ConfigMod = func(*Config)

func (cc *Config) apply(mods ...ConfigMod) {
	for _, mod := range mods {
		mod(cc)
	}
}

func (cc *Config) proxynet() string {
	if cc == nil {
		return "tcp"
	}
	if cc.ProxyNet == "" {
		return "tcp"
	}
	return cc.ProxyNet
}

func (cc *Config) proxyaddr() string {
	if !strings.Contains(cc.ProxyAddr, ":") {
		// Default port
		return net.JoinHostPort(cc.ProxyAddr, "1080")
	}
	return cc.ProxyAddr
}

func (cc *Config) user() string {
	if cc.Credentials == nil {
		return ""
	}
	return cc.Credentials.User
}

func (cc *Config) nuser() *string {
	if cc.Credentials == nil {
		return nil
	}
	return &cc.Credentials.User
}

func (cc *Config) npass() *string {
	if cc.Credentials == nil {
		return nil
	}
	return &cc.Credentials.Password
}

func (cc *Config) udpAllowed() bool {
	if !cc.TLS {
		return true
	}
	return (!cc.TLS) || cc.InsecureUDP
}

func (cc *Config) dialFilter(network, address string) bool {
	filter := DirectLoopback
	if cc.DirectFilter != nil {
		filter = cc.DirectFilter
	}
	return filter(network, address)
}

func (cc *Config) listener() common.Listener {
	if cc.DirectListener == nil {
		return (&net.ListenConfig{}).Listen
	}
	return cc.DirectListener
}

func (cc *Config) resolver() common.Resolver {
	if cc.Resolver == nil {
		return net.DefaultResolver
	}
	return cc.Resolver
}

func (cc *Config) tlsConfig() *tls.Config {
	if !cc.TLS {
		return nil
	}
	sname := cc.proxyaddr()
	h, _, err := net.SplitHostPort(sname)
	if err == nil {
		sname = h
	}

	config := &tls.Config{}
	if cc.TLSConfig != nil {
		config = cc.TLSConfig
	}
	if config.ServerName == "" {
		config.ServerName = sname
	}

	return config
}

func (cc *Config) wsDialer() *websocket.Dialer {
	if cc.WebSocketURL == "" {
		return nil
	}
	dialer := &websocket.Dialer{
		// NetDial: func(network, addr string) (net.Conn, error) {
		// 	return cc.netDialer()(context.Background(), network, addr)
		// },
		NetDialContext:  cc.netDialer(),
		TLSClientConfig: cc.tlsConfig(),
		WriteBufferPool: nil, // TODO: Convert somehow BufferPool to websocket.BufferPool

		HandshakeTimeout:  cc.WebSocketConfig.handshakeTimeout(),
		ReadBufferSize:    cc.WebSocketConfig.readBufferSize(),
		Subprotocols:      cc.WebSocketConfig.subprotocols(),
		EnableCompression: cc.WebSocketConfig.enableCompression(),
		Jar:               cc.WebSocketConfig.jar(),
	}
	return dialer
}

func (cc *Config) dialWebSocket(ctx context.Context) (conn net.Conn, err error) {
	// TODO: Add RequestHeader to config
	ws, resp, err := cc.wsDialer().DialContext(ctx, cc.WebSocketURL, nil)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()

	return &internal.WSConn{
		Conn: ws,
	}, nil
}

func (cc *Config) netDialer() common.Dialer {
	if cc.Dialer == nil {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	return cc.Dialer
}

func (cc *Config) dial(ctx context.Context) (conn net.Conn, err error) {
	if cc.WebSocketURL != "" {
		return cc.dialWebSocket(ctx)
	}

	conn, err = cc.netDialer()(ctx, cc.proxynet(), cc.proxyaddr())
	if err != nil {
		return nil, err
	}

	if cc.TLS {
		conn = tls.Client(conn, cc.tlsConfig())
	}

	return
}

func (cc *Config) lookupPort(ctx context.Context, network, strport string) (port int, err error) {
	// TODO: If strport is "" -> err missinng port
	port, err = strconv.Atoi(strport)
	if err == nil {
		return port, nil
	}
	port, err = cc.resolver().LookupPort(ctx, network, strport)
	return port, err
}

func (cc *Config) String() string {
	str := ""
	str += fmt.Sprintln("ProxyNet:", cc.ProxyNet)
	str += fmt.Sprintln("ProxyAddr:", cc.ProxyAddr)
	str += fmt.Sprintln("GostMbind:", cc.GostMbind)
	str += fmt.Sprintln("GostUDPTun:", cc.GostUDPTun)
	str += fmt.Sprintln("TorLookup:", cc.TorLookup)
	str += fmt.Sprintln("SpawnUDPProbber:", cc.SpawnUDPProbber)
	str += fmt.Sprintln("Dialer:", cc.Dialer)
	str += fmt.Sprintln("DirectListener:", cc.DirectListener)
	str += fmt.Sprintln("Resolver:", cc.Resolver)
	str += fmt.Sprintln("LocalResolve:", cc.LocalResolve)
	str += fmt.Sprintln("DirectFilter:", cc.DirectFilter)
	if cc.Credentials != nil {
		str += fmt.Sprintln("User:", cc.Credentials.User)
		str += fmt.Sprintln("Password:", cc.Credentials.Password)
	}
	str += fmt.Sprintln("Pool:", cc.Pool)
	str += fmt.Sprintln("Smux:", cc.Smux)
	str += fmt.Sprintln("TLS:", cc.TLS)
	str += fmt.Sprintln("TLSConfig:", cc.TLSConfig)
	if cc.WebSocketURL != "" {
		str += fmt.Sprintln("WebSocketURL:", cc.WebSocketURL)
		str += fmt.Sprintln("WebSocketConfig:", cc.WebSocketConfig)
	}
	return str
}

func ConfigWithNet(net string) ConfigMod {
	return func(c *Config) { c.ProxyNet = net }
}

func ConfigWithAddr(addr string) ConfigMod {
	return func(c *Config) { c.ProxyAddr = addr }
}

func ConfigWithGostMbind(enabled bool) ConfigMod {
	return func(c *Config) { c.GostMbind = enabled }
}

func ConfigWithGostUDPTun(enabled bool) ConfigMod {
	return func(c *Config) { c.GostUDPTun = enabled }
}

func ConfigWithTorLookup(enabled bool) ConfigMod {
	return func(c *Config) { c.TorLookup = enabled }
}

func ConfigWithSpawnUDPProbber(enabled bool) ConfigMod {
	return func(c *Config) { c.SpawnUDPProbber = enabled }
}

func ConfigWithLocalResolve(enabled bool) ConfigMod {
	return func(c *Config) { c.LocalResolve = enabled }
}

func ConfigWithDialer(d common.Dialer) ConfigMod {
	return func(c *Config) { c.Dialer = d }
}

func ConfigWithDirectListener(l common.Listener) ConfigMod {
	return func(c *Config) { c.DirectListener = l }
}

func ConfigWithResolver(r common.Resolver) ConfigMod {
	return func(c *Config) { c.Resolver = r }
}

func ConfigWithDirectFilter(f common.DirectFilter) ConfigMod {
	return func(c *Config) { c.DirectFilter = f }
}

func ConfigWithPool(p common.BufferPool) ConfigMod {
	return func(c *Config) { c.Pool = p }
}

func ConfigWithCredentials(creds *Credentials) ConfigMod {
	return func(c *Config) { c.Credentials = creds }
}

func ConfigWithUser(user string) ConfigMod {
	return func(c *Config) {
		if c.Credentials != nil {
			c.Credentials.User = user
		} else {
			c.Credentials = &Credentials{
				User: user,
			}
		}
	}
}

func ConfigWithPassword(pass string) ConfigMod {
	return func(c *Config) {
		if c.Credentials != nil {
			c.Credentials.Password = pass
		} else {
			c.Credentials = &Credentials{
				User: pass,
			}
		}
	}
}

func ConfigWithSmux(s *SmuxConfig) ConfigMod {
	return func(c *Config) { c.Smux = s }
}

func ConfigWithTLS(t *tls.Config) ConfigMod {
	return func(c *Config) { c.TLSConfig = t }
}

func ConfigWithWS(w *WebSocketConfig) ConfigMod {
	return func(c *Config) { c.WebSocketConfig = w }
}
