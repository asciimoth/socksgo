//go:build !js

package socksgo

import (
	"net/http"

	"github.com/coder/websocket"
)

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
func (c *Client) GetWsDialer() *websocket.DialOptions {
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
	compressionMode := websocket.CompressionDisabled
	var httpHeader http.Header
	var subprotocols []string

	if c.WebSocketConfig != nil {
		if c.WebSocketConfig.enableCompression() {
			compressionMode = websocket.CompressionContextTakeover
		}
		httpHeader = c.WebSocketConfig.RequestHeader
		subprotocols = c.WebSocketConfig.subprotocols()
	}

	return &websocket.DialOptions{
		HTTPClient:      httpClient,
		HTTPHeader:      httpHeader,
		Subprotocols:    subprotocols,
		CompressionMode: compressionMode,
	}
}
