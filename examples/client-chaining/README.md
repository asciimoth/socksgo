# SOCKS Proxy Chaining Example

A client example demonstrating how to chain multiple SOCKS proxies together. The outer proxy uses the inner proxy as its dialer, creating a proxy chain.

## Usage

```sh
go run . [options]
```

### Options

- `-proxy1`: First (inner) SOCKS proxy URL (default: `socks5://127.0.0.1:1080`)
- `-proxy2`: Second (outer) SOCKS proxy URL (default: `socks5://127.0.0.1:1090`)
- `-url`: Target URL to fetch (default: `http://example.com`)
- `-timeout`: Request timeout (default: `30s`)

## How It Works

The client chaining works by setting the `Dialer` field of the outer proxy client to use the inner proxy's `Dial` method:

```go
proxy2.Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
    return proxy1.Dial(ctx, network, address)
}
```

When `proxy2.Dial()` is called:
1. proxy2 uses its Dialer (which calls proxy1.Dial)
2. proxy1 establishes connection to its ProxyAddr (proxy2)
3. proxy1 sends SOCKS CONNECT to proxy2 for the target
4. proxy2 connects to the target
5. Data flows: client → proxy1 → proxy2 → target

## Examples

### Basic Two-Proxy Chain

```sh
go run . -proxy1 socks5://localhost:1080 -proxy2 socks5://localhost:1081 -url http://example.com
```

### Chain with Authentication

```sh
go run . -proxy1 socks5://user1:pass1@localhost:1080 -proxy2 socks5://user2:pass2@localhost:1081 -url http://httpbin.org/ip
```

### Three-Proxy Chain

You can chain more proxies by extending the pattern:

```go
proxy1 := ClientFromURL("socks5://proxy1:1080")
proxy2 := ClientFromURL("socks5://proxy2:1081")
proxy2.Dialer = proxy1.Dial

proxy3 := ClientFromURL("socks5://proxy3:1082")
proxy3.Dialer = proxy2.Dial

conn, err := proxy3.Dial(ctx, "tcp", target)
```

