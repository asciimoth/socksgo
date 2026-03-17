# socksgo
The most complete, compatible, featured and extensible SOCKS library for Go.

## Features

### Complete
- **All versions**
    - socks4, 
    - socks4a, 
    - socks5(h)
- **Both sides**: Client and server implementations
- **All standard auth methods**: 
    - NoAuth
    - Username/Password,
    - GSSAPI (stub)
- **All commands**: 
    - CONNECT
    - BIND
    - UDP ASSOC
- **IDENT support** (For socks4 server)

### Featured
- **Tor extensions**:
    - Resolve
    - ResolvePtr
    - Stream Isolation
- **Gost extensions**:
  - socks over TLS
  - socks over WebSocket
  - MBIND (Multiplexed Bind)
  - UDP TUN (UDP tunneling over TCP)
- **Flexible client configuration**:
  - Explicit Client structure construction
  - Client from URL (full and safe variants)
  - Client from environment variables

### Extensible
- Address filtering (both client and server sides)
- Custom commands
- Custom auth methods
- Hooks

### Well Tested
- High test coverage
- Compatibility tests for curl, Tor, and Gost

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
- [client-chaining](./examples/client-chaining) - Chained proxy clients
- [server-chaining](./examples/server-chaining) - Chained proxy servers
- [interceptor](./examples/interceptor) - HTTP(S) interceptor proxy
- [tor-isolation](./examples/tor-isolation) - Tor streams isolation
- [resolve](./examples/resolve) - Tor Resolve extension
- [resolve-ptr](./examples/resolve-ptr) - Tor ResolvePtr extension


## TODO
- [ ] More tls options in client url support
- [ ] UDP ASSOC fragmentation support
- [ ] socks over ws perf improve

