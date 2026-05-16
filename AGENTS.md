# Agent Guidelines for socksgo
## Project Overview
**socksgo** is a Go library implementing SOCKS proxy client and server (SOCKS4, SOCKS4a, SOCKS5) with extensions for Gost and Tor compatibility.

**Module:** `github.com/asciimoth/socksgo`  
**Go Version:** 1.25.5

## Key Architecture Concepts

### Package Structure

```
socksgo/
├── client.go              # Client configuration & high-level API
├── client4.go             # SOCKS4/4a client implementation
├── client5.go             # SOCKS5 client implementation
├── server.go              # Server accept & dispatch logic
├── server_handler_*.go    # Command handlers (connect, bind, assoc, etc.)
├── common.go              # Shared types (Filter, Dialer, PacketConn, etc.)
├── errors.go              # Error types
├── ws.go                  # WebSocket transport
├── protocol/              # Low-level protocol encoding/decoding
│   ├── addr.go            # Address type & conversions
│   ├── v4.go              # SOCKS4 protocol
│   ├── v5tcp.go           # SOCKS5 TCP protocol
│   ├── v5udp.go           # SOCKS5 UDP protocol
│   ├── v5auth*.go         # SOCKS5 authentication
│   ├── reply.go           # Reply status codes
│   └── pipe.go            # Connection piping utility
├── internal/              # Internal utilities
│   ├── helpers.go         # Common helpers
│   └── url.go             # URL parsing utilities
└── cmd/cmd.go             # CLI demo/test tool
```

### Core Types

#### Client
```go
type Client struct {
    SocksVersion string        // "4", "4a", "5", or ""
    ProxyAddr    string        // host:port
    Auth         *AuthMethods  // Authentication methods
    TLS          bool          // Enable TLS
    WebSocketURL string        // If not "", use WS/WSS
    Filter       Filter        // Address filter for direct connections
    // ... extensions: GostMbind, GostUDPTun, TorLookup
}
```

#### Server
```go
type Server struct {
    Auth       *AuthHandlers          // Server-side auth handlers
    Handlers   map[Cmd]CommandHandler // Command handlers
    PreCmd     func(...)              // Pre-command hook
    LaddrFilter, RaddrFilter Filter   // Address filters
    // ... UDP, timeout, resolver config
}
```

#### Protocol Types
- `protocol.Addr` - Address representation (IP4, IP6, FQDN)
- `protocol.Cmd` - Command codes (Connect, Bind, UDPAssoc, etc.)
- `protocol.ReplyStatus` - Reply status codes
- `protocol.AuthMethod/AuthHandler` - Client/Server auth interfaces

### Command Flow

**Client Request Flow:**
1. `Client.Dial()` / `Client.Listen()` / `Client.ListenPacket()`
2. `Client.Request()` → `Client.request{4,5}()`
3. `Client.Connect()` - establishes TCP/WS connection
4. Protocol-specific handshake (auth, request building)
5. Returns `net.Conn` or `PacketConn`

**Server Accept Flow:**
1. `Server.Accept()` reads version byte
2. Routes to `accept4()` or `accept5()`
3. Auth negotiation via `protocol.HandleAuth()`
4. Command dispatch to `CommandHandler`
5. Handler executes command (connect, bind, assoc, etc.)

### Extensions

| Extension | Flag | Description |
|-----------|------|-------------|
| Gost MBIND | `GostMbind` | Multiplexed bind using smux |
| Gost UDPTun | `GostUDPTun` | UDP tunneling over TCP |
| Tor Lookup | `TorLookup` | DNS resolve extensions |

## Development Guidelines

### Code Style

1. **Naming:**
   - Use descriptive names for protocol types
   - Suffix version-specific implementations: `request4`, `request5`
   - Handler vars: `DefaultConnectHandler`, `DefaultBindHandler`

2. **Error Handling:**
   - Return specific error types from `errors.go`
   - Use `protocol.ReplyStatus` for protocol errors
   - Wrap errors with context where helpful

3. **Buffer Management:**
   - Use `bufpool.Pool` for temporary buffers
   - Always call `defer bufpool.PutBuffer(pool, buf)` after use
   - Common buffer sizes in project: `MAX_SOCKS_TCP_HEADER_LEN`, `MAX_SOCKS_UDP_HEADER_LEN`

4. **Context Usage:**
   - All public APIs accept `context.Context`
   - Pass context to dialers, resolvers, handlers
   - Use context for cancellation and timeouts

### Testing Patterns

1. **Test Organization:**
   - `{unit}_test.go` - Unit tests for specific files
   - `compat_*_test.go` - Compatibility tests (gost, tor, curl)
   - `pair_client_server_test.go` - Client-server integration tests

2. **Test Structure:**
```go
func TestSomething(t *testing.T) {
    t.Parallel()
    t.Run("group", func(t *testing.T) {
        t.Run("case1", func(t *testing.T) {
            t.Parallel()
            // test code
        })
    })
}
```

### Common Pitfalls

1. **Buffer Reuse:** Never use a buffer after calling `PutBuffer`
2. **Address Types:** Always check `Addr.Type` before conversion
3. **Network Types:** `"tcp4"`, `"tcp6"` vs `"tcp"` - use `internal.NormalNet()`
4. **UDP Assoc:** Requires two connections (control TCP + data UDP)
5. **Gost UDPTun:** Uses TCP connection with custom header format

### Linting & Formatting

Run before committing:
```bash
go fmt ./...
go test ./...
golangci-lint run
```

Configuration in `.golangci.yml`:
- Max line length: 80
- Enabled: errcheck, govet, staticcheck, gocritic, etc.

## Documentation Guidelines

When adding documentation:

1. **Protocol Details:**
   - Reference RFC 1928 (SOCKS5), RFC 1929 (auth)
   - Document extension protocols (Gost, Tor)

## Refactoring Priorities

### Server Implementation (Potential Issues)

1. **Handler Consistency:**
   - Some handlers lack proper error-to-reply mapping

2. **UDP Handling:**
   - `DefaultUDPAssocHandler` - check reply codes
   - `DefaultGostUDPTUNHandler` - TLS compatibility flag is false

3. **Resource Cleanup:**
   - Verify all handlers properly close connections on error
   - Check for goroutine leaks in UDP proxy loops

4. **Concurrency:**
   - MBIND handler uses `sync.WaitGroup` - verify proper synchronization
   - UDP assoc spawns goroutines - ensure proper shutdown

### Test Coverage Gaps

Priority areas for additional tests:
- Error paths in server handlers
- WebSocket transport edge cases
- Authentication failure scenarios
- Filter behavior with edge cases

## Quick Reference

### Creating a Client
```go
// From URL
client, err := socksgo.ClientFromURL("socks5://user:pass@proxy:1080")

// No proxy (direct connections)
client := socksgo.ClientNoProxy()

// Custom configuration
client := &socksgo.Client{
    SocksVersion: "5",
    ProxyAddr:    "proxy:1080",
    Auth:         authMethods,
    Filter:       socksgo.BuildFilter("localhost,192.168.0.0/16"),
}
```

### Creating a Server
```go
server := &socksgo.Server{
    Auth:       authHandlers,
    Handlers:   socksgo.DefaultCommandHandlers,
    UDPTimeout: 2 * time.Minute,
}

// Accept connections
listener, _ := net.Listen("tcp", "127.0.0.1:1080")
for {
    conn, _ := listener.Accept()
    go server.Accept(ctx, conn, false)
}
```

### Protocol Constants
```go
MAX_HEADER_STR_LENGTH    = 255
MAX_SOCKS_TCP_HEADER_LEN = 262
MAX_SOCKS_UDP_HEADER_LEN = 262
GOST_UDP_FRAG_FLAG       = 255
```

### Reply Status Codes
- `SuccReply (0)` - Success
- `FailReply (1)` - General failure
- `DisallowReply (2)` - Connection not allowed
- `HostUnreachReply (4)` - Host unreachable
