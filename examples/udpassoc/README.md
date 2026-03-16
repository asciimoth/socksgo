# SOCKS UDP Dial Client Example

A simple CLI client example demonstrating how to use socksgo to perform DNS lookups through a SOCKS proxy using the UDP ASSOC.

This example uses a custom `net.Resolver` that routes DNS queries through the proxy.

## Usage

```sh
go run . [options]
```

### Options

- `-proxy`: SOCKS proxy URL (default: `socks5://127.0.0.1:1080`)
- `-host`: Hostname to resolve (default: `example.com`)
- `-timeout`: Operation timeout (default: `30s`)

## Examples

### Basic SOCKS5 UDP Dial

```sh
# Resolve hostname through local SOCKS5 proxy
go run . -proxy socks5://localhost:1080 -host google.com
```

### With Authentication

```sh
go run . -proxy socks5://user:pass@localhost:1080 -host github.com
```

### With gost
To use gost's "UDP TUN" extension add gost url option (must be supported by server):
```sh
go run . -proxy socks5://localhost:1080?gost
```

