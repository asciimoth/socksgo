# SOCKS Proxy GSS-API Authentication Example

A complete client-server example demonstrating SOCKS5 proxy with GSS-API authentication using a mock GSS implementation.

## Overview

This example demonstrates:
- SOCKS5 server with GSS-API authentication
- SOCKS5 client with GSS-API authentication
- Mock GSS implementations for demonstration purposes
- Token exchange mechanism between client and server

## Usage

```sh
go run . [options]
```

### Options

- `-addr`: SOCKS server listen address (default: `127.0.0.1:1080`)
- `-target`: Target URL to fetch (default: `http://example.com`)
- `-rounds`: Number of GSS token exchange rounds (default: `2`)

## Examples

### Basic GSS Auth

```sh
# Default settings: 2 rounds of token exchange
go run .

# Specify different number of rounds
go run . -rounds 3

# Connect to a custom target
go run . -target http://httpbin.org/ip
```

### Custom Server Address

```sh
# Run server on custom port
go run . -addr :8080 -target http://example.com
```

## GSS-API Authentication Protocol

GSS-API authentication uses a token exchange mechanism:

1. Client sends method selection including GSS auth (0x01)
2. Server selects GSS-API authentication
3. Multiple token exchanges occur:
   - Client → Server: GSS token (framed with 4-byte header)
   - Server → Client: GSS token (framed with 4-byte header)
4. When complete, authentication succeeds

### Token Frame Format

```
+----+----+-----+-----+----------+
|VER |MTYP| LEN | ... |  TOKEN   |
+----+----+-----+-----+----------+
| 1  | 1  |  2  |     | Variable |
+----+----+-----+-----+----------+
```

Where:
- **VER**: Version (0x01)
- **MTYP**: Message type (0x01 for authentication)
- **LEN**: Token length (big-endian uint16)
- **TOKEN**: GSS-API token

## Mock Implementation

This example uses mock GSS implementations for demonstration:

### MockGSSClient

Simulates a GSS-API client by exchanging tokens with the server:
- Initial call: produces first client token (`c:1`)
- Subsequent calls: processes server tokens and produces next client token
- Completes after configured number of rounds

### MockGSSServer

Simulates a GSS-API server by processing client tokens:
- Processes client tokens and produces response tokens (`s:N`)
- Returns the authenticated principal name on completion
- Requires the same number of rounds as the client

## Production Usage

For production use with real GSS-API replace mock implementations with actual GSS-API library

## References

- [RFC 1961](https://datatracker.ietf.org/doc/html/rfc1961): GSS-API Authentication Method for SOCKS Version 5
- [RFC 2743](https://datatracker.ietf.org/doc/html/rfc2743): Generic Security Service API Version 2

