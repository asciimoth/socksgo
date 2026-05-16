# Architecture Overview

High-level architecture documentation for socksgo.

## System Design

socksgo implements the SOCKS protocol suite (SOCKS4, SOCKS4a, SOCKS5) as both client and server, with extensions for Gost and Tor compatibility.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Application                              │
│  (uses net.Dialer, net.Listener interfaces via Client/Server)   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      socksgo.Client                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ Dial()      │  │ Listen()    │  │ ListenPacket()          │  │
│  │ LookupIP()  │  │ Request()   │  │ Connect()               │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Configuration                           │  │
│  │  Version │ Auth │ TLS │ WS │ Filter │ Extensions          │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                 │
              ▼                 ▼                 ▼
    ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐
    │  TCP Connection │ │   TLS       │ │  WebSocket      │
    │  (ProxyAddr)    │ │  Wrapper    │ │  (wsUrl)        │
    └─────────────────┘ └─────────────┘ └─────────────────┘
              │                 │                 │
              └─────────────────┼─────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   SOCKS Handshake     │
                    │  ┌─────────────────┐  │
                    │  │ Auth Negotiation│  │
                    │  │ - No Auth       │  │
                    │  │ - User/Pass     │  │
                    │  │ - GSS-API       │  │
                    │  └─────────────────┘  │
                    │  ┌─────────────────┐  │
                    │  │ Command Request │  │
                    │  │ - CONNECT       │  │
                    │  │ - BIND          │  │
                    │  │ - UDP ASSOC     │  │
                    │  │ - Extensions    │  │
                    │  └─────────────────┘  │
                    └───────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     socksgo.Server                               │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Accept Loop                             │  │
│  │  Read Version → Route to accept4/accept5                  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                  Command Handlers                          │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │  │
│  │  │ Connect  │ │  Bind    │ │ UDPAssoc │ │  Extensions  │  │  │
│  │  │ Handler  │ │ Handler  │ │ Handler  │ │  Handlers    │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                   Backend Operations                       │  │
│  │  Dialer │ Listener │ PacketDialer │ PacketListener       │  │
│  │  Resolver │ PreCmd │ Filters                              │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Target Server                                 │
│              (web server, DNS, any TCP/UDP service)             │
└─────────────────────────────────────────────────────────────────┘
```

## Protocol Layers

```
┌─────────────────────────────────────────────────────────────┐
│ Application Layer                                           │
│  HTTP, DNS, custom protocols over TCP/UDP                   │
├─────────────────────────────────────────────────────────────┤
│ SOCKS Protocol Layer                                        │
│  ┌─────────────┬─────────────┬─────────────┐                │
│  │  SOCKS4     │  SOCKS4a    │  SOCKS5     │                │
│  │  - CONNECT  │  - CONNECT  │  - CONNECT  │                │
│  │  - BIND     │  - BIND     │  - BIND     │                │
│  │             │             │  - UDP ASSOC│                │
│  └─────────────┴─────────────┴─────────────┘                │
├─────────────────────────────────────────────────────────────┤
│ Extensions Layer                                            │
│  ┌─────────────┬─────────────┬─────────────┐                │
│  │ Gost MBIND  │Gost UDPTun  │ Tor Resolve │                │
│  │ (smux)      │ (UDP over   │ (DNS lookup)│                │
│  │             │  TCP)       │             │                │
│  └─────────────┴─────────────┴─────────────┘                │
├─────────────────────────────────────────────────────────────┤
│ Transport Layer                                             │
│  ┌─────────────┬─────────────┬─────────────┐                │
│  │    TCP      │    TLS      │ WebSocket   │                │
│  └─────────────┴─────────────┴─────────────┘                │
├─────────────────────────────────────────────────────────────┤
│ Network Layer                                               │
│  IPv4 / IPv6                                                │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### Client Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         Client                                │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                   Public API                            │  │
│  │  Dial(ctx, network, address) net.Conn                   │  │
│  │  Listen(ctx, network, address) net.Listener             │  │
│  │  ListenPacket(ctx, network, address) PacketConn         │  │
│  │  LookupIP(ctx, network, address) []net.IP               │  │
│  │  LookupAddr(ctx, address) []string                      │  │
│  └────────────────────────────────────────────────────────┘  │
│                           │                                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                  Request Routing                       │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │ DoFilter(network, address) → bool                │  │  │
│  │  │  - true: use direct dialer/listener              │  │  │
│  │  │  - false: use proxy                              │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  │                           │                             │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │ Request(ctx, cmd, address)                       │  │  │
│  │  │  ↓                                               │  │  │
│  │  │ request{4,4a,5}(ctx, cmd, address)               │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
│                           │                                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │               Connection Establishment                 │  │
│  │  Connect(ctx) → net.Conn                              │  │
│  │    │                                                   │  │
│  │    ├─→ TCP: Dialer(ctx, "tcp", ProxyAddr)             │  │
│  │    ├─→ TLS: tls.Dial(...)                             │  │
│  │    └─→ WS: websocket.Dial(WebSocketURL)               │  │
│  └────────────────────────────────────────────────────────┘  │
│                           │                                   │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              Protocol Implementation                   │  │
│  │  SOCKS4: client4.go                                   │  │
│  │    - request4(): Build request, send, read reply      │  │
│  │    - clientListener4: BIND command handling           │  │
│  │                                                       │  │
│  │  SOCKS5: client5.go                                   │  │
│  │    - request5(): Auth + request + reply               │  │
│  │    - dialPacket5(): UDP ASSOC                         │  │
│  │    - setupUDPTun5(): Gost UDP Tunnel                  │  │
│  │    - clientListener5: BIND command                    │  │
│  │    - clientListener5mux: Gost MBIND                   │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Server Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Server                                 │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │                   Accept Entry                         │  │
│  │  Accept(ctx, conn, isTLS) error                        │  │
│  │  AcceptWS(ctx, wsConn, isTLS) error                    │  │
│  │         │                                              │  │
│  │         ↓                                              │  │
│  │  Read version byte                                     │  │
│  │         │                                              │  │
│  │    ┌────┴────┐                                         │  │
│  │    │         │                                         │  │
│  │    v         v                                         │  │
│  │  accept4   accept5                                     │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              SOCKS4 Handler (accept4)                  │  │
│  │  1. Read request (ReadSocks4TCPRequest)                │  │
│  │  2. Optional: IDENT lookup (UseIDENT)                  │  │
│  │  3. Check: PreCmd hook                                 │  │
│  │  4. Check: Command allowed for version                 │  │
│  │  5. Check: Address filters (LaddrFilter/RaddrFilter)   │  │
│  │  6. Execute: CommandHandler.Handler()                  │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              SOCKS5 Handler (accept5)                  │  │
│  │  1. Auth negotiation (HandleAuth)                      │  │
│  │     - Read methods from client                         │  │
│  │     - Select compatible method                         │  │
│  │     - Execute auth handshake                           │  │
│  │  2. Read request (ReadSocks5TCPRequest)                │  │
│  │  3. Check: PreCmd hook                                 │  │
│  │  4. Check: Command allowed for version/TLS             │  │
│  │  5. Check: Address filters                             │  │
│  │  6. Execute: CommandHandler.Handler()                  │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │               Command Handlers                         │  │
│  │                                                        │  │
│  │  Connect  → Dial target, pipe connections             │  │
│  │  Bind     → Listen, accept incoming, pipe             │  │
│  │  UDPAssoc → Setup UDP proxy (control + data)          │  │
│  │  MBIND    → smux session for multiplexed connections  │  │
│  │  UDPTun   → Gost UDP over TCP tunnel                  │  │
│  │  Resolve  → DNS lookup, return IP                     │  │
│  │  ResolvePtr → Reverse DNS lookup                      │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Protocol Package Structure

```
protocol/
├── addr.go           # Addr type, conversions, network helpers
├── cmd.go            # Command codes and string representations
├── const.go          # Protocol constants (sizes, flags)
├── errors.go         # Protocol-specific errors
├── reply.go          # Reply status codes and conversions
│
├── v4.go             # SOCKS4/4a protocol
│   ├── BuildSocsk4TCPRequest()
│   ├── ReadSocks4TCPRequest()
│   ├── BuildSocks4TCPReply()
│   └── ReadSocks4TCPReply()
│
├── v5tcp.go          # SOCKS5 TCP protocol
│   ├── BuildSocks5TCPRequest()
│   ├── ReadSocks5TCPRequest()
│   ├── BuildSocks5TCPReply()
│   └── ReadSocks5TCPReply()
│
├── v5udp.go          # SOCKS5 UDP protocol
│   ├── Socks5UDPClient (interface)
│   ├── Socks5UDPClientAssoc (standard UDP ASSOC)
│   ├── Socks5UDPClientTUN (Gost UDP tunnel)
│   ├── AppendSocks5UDPHeader()
│   ├── ReadSocks5AssocUDPPacket()
│   ├── ReadSocks5TunUDPPacket()
│   ├── ProxySocks5UDPAssoc()
│   └── ProxySocks5UDPTun()
│
├── v5auth.go         # Auth negotiation
│   ├── AuthMethod (client interface)
│   ├── AuthHandler (server interface)
│   ├── AuthMethods (client-side collection)
│   ├── AuthHandlers (server-side collection)
│   ├── RunAuth()     # Client-side auth execution
│   └── HandleAuth()  # Server-side auth handling
│
├── v5auth_pass.go    # Username/password auth
│   ├── PassAuthMethod
│   └── PassAuthHandler
│
├── v5auth_gss.go     # GSS-API auth (stub)
│   └── GSSAuthMethod
│
└── pipe.go           # Connection piping utility
    └── PipeConn()
```

## Data Flow

### CONNECT Command Flow

```
Client                          Server                        Target
  │                               │                             │
  ├────────── TCP Connect ───────►│                             │
  │                               │                             │
  │                               │                             │
  │                               │                             │
  │◄──────── Auth Methods ────────┤                             │
  │  (NoAuth, PassAuth)           │                             │
  │                               │                             │
  │────────── Auth Request ──────►│                             │
  │   (if PassAuth selected)      │                             │
  │◄──────── Auth Result ─────────┤                             │
  │                               │                             │
  │────────── CONNECT ───────────►│                             │
  │   (cmd=01, addr=example.com)  │                             │
  │                               │                             │
  │                               ├─────── TCP Connect ───────►│
  │                               │      (example.com:80)       │
  │                               │                             │
  │◄──────── SUCCESS ─────────────┤                             │
  │   (bound addr)                │                             │
  │                               │                             │
  │◄══════════════════════════════════════════════════════════►│
  │                    Bidirectional pipe                        │
  │◄══════════════════════════════════════════════════════════►│
```

### UDP ASSOC Flow

```
Client                          Server                        UDP Target
  │                               │                             │
  ├────────── TCP Connect ───────►│                             │
  │  (control connection)         │                             │
  │                               │                             │
  │────────── UDP ASSOC ─────────►│                             │
  │   (cmd=03, addr=0.0.0.0:0)    │                             │
  │                               │                             │
  │                               │        Create UDP Socket    │
  │                               │        (bind to port X)     │
  │                               │                             │
  │◄──────── SUCCESS ─────────────┤                             │
  │   (bound addr: server:X)      │                             │
  │                               │                             │
  │                               │                             │
  │─── UDP Packet ──────────────►│                             │
  │   (to server:X, with header)  │                             │
  │                               │                             │
  │                               ├──── UDP Packet ───────────►│
  │                               │   (to target, no header)    │
  │                               │                             │
  │                               │◄──── UDP Response ─────────│
  │                               │                             │
  │◄── UDP Response ──────────────┤                             │
  │   (from server:X, with header)│                             │
  │                               │                             │
  │         (repeat packets)      │                             │
```

### Gost MBIND Flow

```
Client                          Server                        Targets
  │                               │                             │
  ├────────── TCP Connect ───────►│                             │
  │                               │                             │
  │────────── MBIND ─────────────►│                             │
  │   (cmd=0xF2, addr=0.0.0.0:0)  │                             │
  │                               │                             │
  │                               │        Start Listener       │
  │                               │        (bind to port X)     │
  │                               │                             │
  │◄──────── SUCCESS ─────────────┤                             │
  │   (bound addr: server:X)      │                             │
  │                               │                             │
  │──── smux Session ────────────►│                             │
  │   (upgrade TCP to smux)       │                             │
  │                               │                             │
  │         [external client connects to server:X]               │
  │                               │                             │
  │◄──── smux AcceptStream ───────┤                             │
  │   (new stream for connection) │                             │
  │                               │                             │
  │◄══════════════════════════════════════════════════════════►│
  │                    Stream pipe                               │
  │◄══════════════════════════════════════════════════════════►│
```

## Extension Details

### Gost MBIND (Multiplexed Bind)

Uses smux library for connection multiplexing over a single TCP connection.

**Use Case:** Multiple incoming connections through a single SOCKS BIND

**Protocol:**
1. Client sends MBIND command (0xF2)
2. Server creates listener, returns bound address
3. Client upgrades TCP to smux session
4. Server accepts incoming connections as smux streams
5. Each stream represents one incoming connection

**Configuration:**
```go
client.GostMbind = true
client.Smux = &smux.Config{
    MaxFrameSize: 65535,
    MaxReceiveBuffer: 4194304,
}
```

### Gost UDPTun (UDP Tunnel)

Encapsulates UDP packets over TCP connection.

**Use Case:** UDP through firewalls that block UDP, or when UDP association is problematic

**Packet Format:**
```
+------+------+------+------+-----+------+
|  RSV (16b)     | FRAG | ATYP | DST  |
+------+------+------+------+-----+------+
|  Payload (variable length)            |
+---------------------------------------+
```

- RSV: Payload length (uint16 big-endian)
- FRAG: Always 0xFF (255) for Gost
- ATYP: Address type (IP4=0x01, IP6=0x04, FQDN=0x03)
- DST: Destination address
- Payload: UDP data

**Configuration:**
```go
client.GostUDPTun = true
```

### Tor Resolve Extensions

DNS resolution through Tor SOCKS extension.

**Commands:**
- `CmdTorResolve (0xF0)`: Forward DNS lookup
- `CmdTorResolvePtr (0xF1)`: Reverse DNS lookup

**Usage:**
```go
client.TorLookup = true
ips, err := client.LookupIP(ctx, "ip", "example.com")
```

## Thread Safety

### Client
- **Safe:** Read operations (Version, IsNoProxy, etc.)
- **Safe:** Multiple concurrent Dial/Listen calls
- **Unsafe:** Modifying fields after creation

### Server
- **Safe:** Concurrent Accept calls
- **Safe:** Handler execution (each connection is independent)
- **Unsafe:** Modifying Handlers map after starting

### Protocol Functions
- All protocol encoding/decoding functions are stateless and thread-safe
- Buffer pools require proper Get/Put pairing per goroutine

## Error Handling Strategy

### Client Side

```
Error Type                    │ Handling
──────────────────────────────┼────────────────────────────────
Network error (dial)          │ Return to caller
Auth failure                  │ Return with ErrClientAuthFailed
Protocol error                │ Return with specific error type
Server rejection              │ Wrap in RejectdError
Timeout                       │ Context deadline exceeded
```

### Server Side

```
Error Type                    │ Reply Status
──────────────────────────────┼────────────────────────────────
Auth failure                  │ Send failure, close connection
Address filter rejection      │ DisallowReply (0x02)
Dial failure                  │ HostUnreachReply (0x04)
Listen failure                │ FailReply (0x01)
Protocol error                │ Close connection
Handler error                 │ Translate to appropriate status
```

## Memory Management

### Buffer Pooling

All temporary buffers use `bufpool.Pool`:

```go
buf := bufpool.GetBuffer(pool, size)
defer bufpool.PutBuffer(pool, buf)
// use buf
```

**Benefits:**
- Reduces GC pressure
- Reuses memory across requests
- Configurable pool per Client/Server

### Common buffer Sizes

```go
MAX_HEADER_STR_LENGTH    = 255  // Max FQDN length
MAX_SOCKS_TCP_HEADER_LEN = 262  // Max TCP request/reply size
MAX_SOCKS_UDP_HEADER_LEN = 262  // Max UDP header size
```

## Configuration Patterns

### URL-Based Configuration

```
socks5://[user[:pass]@]host[:port][?options]

Options:
  secure      - Enable TLS verification (default: false)
  insecureudp - Allow plaintext UDP when control TCP connection runs over TLS
                Doesn't have effect for socks over plain TCP connections
  assocprob   - Enable UDP assoc probber that watch control TCP conn and close
                UDP transport if control connection closes.
  gost        - Enable Gost extensions (MBIND, UDPTun)
  tor         - Enable Tor lookup extensions
```

### Programmatic Configuration

```go
// Client
client := &socksgo.Client{
    SocksVersion: "5",
    ProxyAddr:    "proxy:1080",
    Auth:         (&socksgo.AuthMethods{}).Add(&protocol.PassAuthMethod{
        User: "user",
        Pass: "pass",
    }),
    Filter: socksgo.BuildFilter("localhost,192.168.0.0/16"),
    TLS:    true,
    TLSConfig: &tls.Config{
        InsecureSkipVerify: false,
    },
}

// Server
server := &socksgo.Server{
    Auth: (&socksgo.AuthHandlers{}).Add(&protocol.PassAuthHandler{
        Verify: func(user, pass string) bool {
            return user == "admin" && pass == "secret"
        },
    }),
    LaddrFilter: func(addr *protocol.Addr) bool {
        return !addr.IsUnspecified()
    },
    UDPTimeout: 5 * time.Minute,
}
```

## Security Considerations

### Authentication

- SOCKS4: Optional username (no password in base protocol)
- SOCKS5: Multiple auth methods supported
  - No Auth (0x00) - plaintext, no credentials
  - User/Pass (0x02) - plaintext credentials
  - GSS-API (0x01) - encrypted (stub implementation)

### TLS

- Encrypts entire SOCKS session
- Certificate verification disabled by default (`InsecureSkipVerify: true`)
- Enable verification with `secure` URL parameter

### Address Filters

Always use filters in production:
```go
client.Filter = socksgo.BuildFilter("localhost,10.0.0.0/8")
server.RaddrFilter = func(addr *protocol.Addr) bool {
    // Reject internal addresses
    ip := addr.ToIP()
    return ip != nil && !ip.IsPrivate()
}
```

