# SOCKS Server Chaining Example

A server example demonstrating how to chain multiple SOCKS servers together. Server A uses a Client that connects to Server B as its dialer, creating a server chain.

## Usage

```sh
go run . [options]
```

### Options

- `-server-a`: Listen address for Server A (front server) (default: `127.0.0.1:1080`)
- `-server-b`: Listen address for Server B (back server) (default: `127.0.0.1:1081`)
- `-user`: Username for authentication (optional)
- `-pass`: Password for authentication (optional)

## How It Works

Server chaining works by setting the `Dialer` field of Server A to use a Client's `Dial` method:

```go
clientB := ClientFromURL("socks5://127.0.0.1:1081")
serverA := &socksgo.Server{
    Dialer: clientB.Dial,
}
```

When a client connects to Server A:
1. Server A receives the SOCKS request
2. Server A uses its Dialer (which calls clientB.Dial)
3. Client B connects to Server B
4. Client B sends SOCKS CONNECT to Server B for the target
5. Server B connects to the actual destination
6. Data flows: client → Server A → Client B → Server B → destination

## Examples

### Basic Server Chain

```sh
# Run the example with default settings
go run .

# In another terminal, test the chain
curl -4 --proxy socks5://localhost:1080 http://example.com
```

### Server Chain with Authentication

```sh
# Run with authentication
go run . -user admin -pass secret

# Test with authentication
curl -4 --proxy socks5://admin:secret@localhost:1080 http://example.com
```

### Custom Server Addresses

```sh
# Use custom addresses
go run . -server-a 0.0.0.0:9000 -server-b 0.0.0.0:9001

# Test
curl -4 --proxy socks5://localhost:9000 http://example.com
```


### Multiple Backend Servers

You can create Server A that distributes requests to multiple Server B instances:

```go
serverA := &socksgo.Server{
    Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
        // Load balance between multiple backend servers
        backendAddr := selectBackendServer()
        client := ClientFromURL(fmt.Sprintf("socks5://%s", backendAddr))
        return client.Dial(ctx, network, address)
    },
}
```

### Conditional Routing

Route requests based on destination:

```go
serverA := &socksgo.Server{
    Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
        if shouldRouteDirectly(address) {
            return net.Dialer{}.DialContext(ctx, network, address)
        }
        return clientB.Dial(ctx, network, address)
    },
}
```

