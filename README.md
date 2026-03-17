# socksgo
[![Go Reference](https://pkg.go.dev/badge/github.com/asciimoth/socksgo.svg)](https://pkg.go.dev/github.com/asciimoth/socksgo) [![Coverage Status](https://coveralls.io/repos/github/asciimoth/socksgo/badge.svg?branch=master)](https://coveralls.io/github/asciimoth/socksgo?branch=master)  
The most complete, compatible, featured and extensible SOCKS library for Go.

## Features

### Complete
- **All versions**
    - [socks4](https://www.openssh.org/txt/socks4.protocol), 
    - [socks4a](https://www.openssh.org/txt/socks4a.protocol)
    - [socks5(h)](https://www.rfc-editor.org/rfc/rfc1928)
- **Both sides**: Client and server implementations
- **All standard auth methods**
    - NoAuth
    - [Username/Password](https://www.rfc-editor.org/rfc/rfc1929)
    - [GSSAPI](https://www.rfc-editor.org/rfc/rfc1961) (stub)
- **All commands**
    - CONNECT
    - BIND
    - UDP ASSOC
- **[IDENT](https://www.rfc-editor.org/rfc/rfc1413) support** (For socks4 server)

### Featured
- **[Tor extensions](https://spec.torproject.org/socks-extensions)**
    - Resolve
    - ResolvePtr
    - Stream Isolation
- **[Gost extensions](https://gost.run/en/tutorials/protocols/socks/)**
  - socks over TLS
  - socks over WebSocket
  - [MBIND](https://gost.run/en/tutorials/protocols/socks/#mbind-multiplex-bind) (Multiplexed Bind)
  - [UDP TUN](https://gost.run/en/tutorials/protocols/socks/#udp-tun-udp-over-tcp-tunnel) (UDP tunneling over TCP)
- **Flexible client configuration**
  - Explicit Client structure construction
  - Client from URL (full and safe variants)
  - Client from environment variables

### Extensible
- Address filtering (both client and server sides)
- [Custom commands](./examples/custom-cmd)
- [Custom auth methods](./examples/custom-auth)
- Hooks

### Well Tested
- [High test coverage](https://coveralls.io/github/asciimoth/socksgo)
- Compatibility tests for [curl](./compat_curl_test.go), [Tor](./compat_tor_test.go), and [Gost](./compat_gost_test.go)

## Installation

```sh
go get github.com/asciimoth/socksgo
```

## Quick Start

### Client
```go
import "github.com/asciimoth/socksgo"

// Simple SOCKS5 client
client, _ := socksgo.ClientFromURL("socks5://proxy:1080")
conn, _ := client.Dial(context.Background(), "tcp", "example.com:80")
```

### Server
```go
import "github.com/asciimoth/socksgo"

server := &socksgo.Server{
    Auth:     socksgo.DefaultAuthHandlers,
    Handlers: socksgo.DefaultCommandHandlers,
}

listener, _ := net.Listen("tcp", ":1080")
for {
    conn, _ := listener.Accept()
    go server.Accept(context.Background(), conn, false)
}
```

## Examples

See the [examples](./examples) directory for more usage patterns:
- [connect](./examples/connect) - Basic HTTP client through socks proxy
- [server](./examples/server) - TCP/TLS/WebSocket server example
- [bind](./examples/bind) - BIND/GOST MBIND commands usage
- [udpassoc](./examples/udpassoc) - UDP ASSOC/GOST UDP TUN commands usage
- [custom-auth](./examples/custom-auth) - Custom authentication method
- [gss-auth](./examples/gss-auth) - GSSAPI auth implementation example
- [custom-cmd](./examples/custom-cmd) - Custom command
- [client-chaining](./examples/client-chaining) - Chained proxy clients (aka [onion routing](https://en.wikipedia.org/wiki/Onion_routing))
- [server-chaining](./examples/server-chaining) - Chained proxy servers
- [interceptor](./examples/interceptor) - HTTP(S) interceptor proxy
- [tor-isolation](./examples/tor-isolation) - Tor streams isolation
- [resolve](./examples/resolve) - Tor Resolve extension
- [resolve-ptr](./examples/resolve-ptr) - Tor ResolvePtr extension


## TODO
- [ ] Add more tls options to client url scheme
- [ ] Implement UDP ASSOC fragmentation support
- [ ] Improve socks over WS perf

