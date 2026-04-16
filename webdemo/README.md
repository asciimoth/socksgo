# SOCKS WebSocket WASM Demo

A WebAssembly demo that demonstrates using socksgo library to make HTTP requests through a SOCKS proxy over WebSocket connections.

## Features

- Runs entirely in browser using WebAssembly
- Connects to SOCKS proxy servers over WebSocket (socks5+ws:// or socks5+wss://)
- Makes HTTP requests through the proxy
- Uses [coder/websocket](https://github.com/coder/websocket) library for WebSocket support

## Prerequisites

1. Go 1.25.5 or later
2. [gost](https://github.com/ginuerzh/gost) proxy tool (for SOCKS-over-WebSocket server)
3. Python 3 (for HTTP server)
4. [Just](https://just.systems) (optional, for build automation)

## Quick Start

### With Just (Recommended)

```bash
# Terminal 1: Start gost SOCKS-over-WebSocket server
just start-proxy

# Terminal 2: Build and serve the demo
just serve

# Open your browser to
# http://localhost:8000
```

### Without Just (Manual)

```bash
# Terminal 1: Start gost SOCKS-over-WebSocket server
gost -L socks5+ws://localhost:1080

# Terminal 2: Build WASM module
GOOS=js GOARCH=wasm go build -o main.wasm main.go
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" .

# Terminal 2 (continued): Start HTTP server
python3 -m http.server 8000

# Open your browser to
# http://localhost:8000
```

## Browser Compatibility

This demo requires a browser that supports:
- WebAssembly (all modern browsers)
- WebSocket API (all modern browsers)
- ES6+ JavaScript (all modern browsers)

## How It Works

1. **WASM Module**: The `main.go` file compiles to WebAssembly and contains:
   - socksgo client configured for WebSocket transport
   - HTTP client that routes requests through the SOCKS proxy
   - JavaScript bridge functions for DOM interaction

2. **WebSocket Connection**: The client connects to the gost SOCKS5-over-WebSocket server

3. **HTTP Request**: HTTP requests are made through the SOCKS connection, appearing to originate from the gost server

## References

- [socksgo Documentation](../README.md)
- [coder/websocket](https://github.com/coder/websocket)
- [gost Proxy Tool](https://github.com/go-gost/gost)
- [Go WebAssembly](https://go.dev/wiki/WebAssembly)
- [SOCKS Protocol](https://en.wikipedia.org/wiki/SOCKS)
