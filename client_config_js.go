//go:build js

package socksgo

import (
	"github.com/coder/websocket"
)

// GetWsDialer creates coder/websocket.DialOptions configured from WebSocketConfig,
// GetDialer, and GetTLSConfig. Returns nil if WebSocketURL is empty.
//
// # Configuration
//
// The dialer is configured with:
//   - Subprotocols: From WebSocketConfig
//
// Note: HTTPClient, HTTPHeader, and CompressionMode are not supported in WASM builds
// due to browser WebSocket API limitations.
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

	var subprotocols []string
	if c.WebSocketConfig != nil {
		subprotocols = c.WebSocketConfig.subprotocols()
	}

	return &websocket.DialOptions{
		Subprotocols: subprotocols,
	}
}
