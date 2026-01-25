package socksgo

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/asciimoth/socksgo/internal"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/gorilla/websocket"
)

type WebSocketConfig struct {
	ReadBufferSize    int
	Subprotocols      []string
	EnableCompression bool
	Jar               http.CookieJar
	RequestHeader     http.Header
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
		RequestHeader:     w.RequestHeader.Clone(),
	}
	return &cfg
}

func (c *Client) Version() string {
	if c.SocksVersion == "" {
		return "5"
	}
	return c.SocksVersion
}

// c.ProxyNet or "tcp"
func (c *Client) GetNet() string {
	if c == nil {
		return "tcp"
	}
	if c.ProxyNet == "" {
		return "tcp"
	}
	return c.ProxyNet
}

// c.ProxyAddr or c.ProxyAddr + ":1080" if no port provided
func (c *Client) GetAddr() string {
	if !strings.Contains(c.ProxyAddr, ":") {
		// Default port
		return net.JoinHostPort(c.ProxyAddr, "1080")
	}
	return c.ProxyAddr
}

// Return true if c.TLS is true or c.WebSocketURL starts with "wss"
func (c *Client) IsTLS() bool {
	return c.TLS || strings.HasPrefix(c.WebSocketURL, "wss")
}

// !c.IsTLS() || c.InsecureUDP
func (c *Client) IsUDPAllowed() bool {
	return !c.IsTLS() || c.InsecureUDP
}

// Run c.Filter or LoopbackFilter if c.Filter is nil.
func (c *Client) DoFilter(network, address string) bool {
	filter := LoopbackFilter
	if c.Filter != nil {
		filter = c.Filter
	}
	return filter(network, address)
}

// Return c.DirectListener or default net listener.
func (c *Client) GetListener() Listener {
	if c.DirectListener == nil {
		return (&net.ListenConfig{}).Listen
	}
	return c.DirectListener
}

// Return c.DirectPacketListener or default net UDP listener.
func (c *Client) GetPacketListener() PacketListener {
	if c.DirectPacketListener == nil {
		return func(ctx context.Context, network, laddr string) (PacketConn, error) {
			udpAddr := protocol.AddrFromHostPort(laddr, network).ToUDP()
			return net.ListenUDP(network, udpAddr)
		}
	}
	return c.DirectPacketListener
}

// Return c.Dialer or default net dialer.
func (c *Client) GetDialer() Dialer {
	if c.Dialer == nil {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
	}
	return c.Dialer
}

// Return c.PacketDialer or default net udp dialer.
func (c *Client) GetPacketDialer() PacketDialer {
	if c.Dialer == nil {
		return func(ctx context.Context, network, raddr string) (PacketConn, error) {
			udpAddr := protocol.AddrFromHostPort(raddr, network).ToUDP()
			return net.DialUDP(network, nil, udpAddr)
		}
	}
	return c.PacketDialer
}

// Return c.Resolver4 or net.DefaultResolver
func (c *Client) GetResolver() Resolver {
	if c.Resolver == nil {
		return net.DefaultResolver
	}
	return c.Resolver
}

// Build TLS config from c.TLSConfig or default tls.Config{}.
// If config.ServerName == "", set it to c.GetAddr().
// If !c.IsTLS() always return nil.
func (c *Client) GetTLSConfig() (config *tls.Config) {
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

func (c *Client) GetHandshakeTimeout() time.Duration {
	if c == nil {
		return 0
	}
	return c.HandshakeTimeout
}

// Build webSocket.Dialer from c.WebSocketConfig,
// c.GetDialer() and c.GetTLSConfig.
// if c.WebSocketURL == "" always return nil.
func (c *Client) GetWsDialer() *websocket.Dialer {
	if c.WebSocketURL == "" {
		return nil
	}
	dialer := &websocket.Dialer{
		NetDialContext:  c.GetDialer(),
		TLSClientConfig: c.GetTLSConfig(),
		// TODO: Convert somehow BufferPool to websocket.BufferPool
		WriteBufferPool: nil,

		HandshakeTimeout:  c.GetHandshakeTimeout(),
		ReadBufferSize:    c.WebSocketConfig.readBufferSize(),
		Subprotocols:      c.WebSocketConfig.subprotocols(),
		EnableCompression: c.WebSocketConfig.enableCompression(),
		Jar:               c.WebSocketConfig.jar(),
	}
	return dialer
}

// Connect to socks over ws proxy
func (c *Client) connectWebSocket(ctx context.Context) (conn net.Conn, err error) {
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
		conn.SetDeadline(time.Time{})
	} else {
		conn.SetDeadline(time.Now().Add(timeout))
	}

	return
}

func (c *Client) CheckNetworkSupport(net string) error {
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
