# SOCKS Proxy CONNECT Client Example

A simple CLI client example demonstrating how to use socksgo to make HTTP requests through a SOCKS proxy.

## Usage

```sh
go run . [options]
```

### Options

- `-proxy`: SOCKS proxy URL (default: `socks5://127.0.0.1:1080`)
- `-url`: Target URL to fetch (default: `http://example.com`)

## Examples

### Basic SOCKS5 Proxy

```sh
# Connect through local SOCKS5 proxy
go run . -proxy socks5://localhost:1080 -url http://example.com

# With authentication
go run . -proxy socks5://user:pass@localhost:1080 -url http://httpbin.org/ip
```

### SOCKS4 Proxy

```sh
go run . -proxy socks4://localhost:1080 -url http://example.com
```

### SOCKS5 over TLS

First start the TLS server from `../server`:

```sh
# Terminal 1: Start TLS SOCKS server
cd ../server
go run . -tls-addr :1081

# Terminal 2: Connect via TLS
cd ../client
go run . -proxy socks5+tls://localhost:1081 -url http://example.com
```

### SOCKS5 over WebSocket

```sh
# Terminal 1: Start WebSocket SOCKS server
cd ../server
go run . -ws-addr :1082

# Terminal 2: Connect via WebSocket
cd ../client
go run . -proxy socks5+ws://localhost:1082/ws -url http://example.com
```

### Tor Proxy

```sh
# Connect through Tor SOCKS proxy (default port 9050)
go run . -proxy socks5://localhost:9050 -url http://check.torproject.org
```

