# SOCKS Proxy Custom Authentication Example

A complete client-server example demonstrating SOCKS5 proxy with custom authentication using a simple token-based authentication method.

## Overview

This example demonstrates:
- Custom AuthMethod implementation (client-side)
- Custom AuthHandler implementation (server-side)
- Private authentication method code (0x80)

## Usage

```sh
go run . [options]
```

### Options

- `-addr`: SOCKS server listen address (default: `127.0.0.1:1080`)
- `-target`: Target URL to fetch (default: `http://example.com`)
- `-token`: Shared authentication token (default: `secret-token`)

## Examples

```sh
# Default settings
go run .

# Use a custom token
go run . -token my-secret-token

# Connect to a custom target
go run . -target http://httpbin.org/ip
```

## Custom Authentication Protocol

This example implements a simple token-based authentication method:

1. Client sends method selection including custom auth (0x80)
2. Server selects custom authentication
3. Client sends token:
   - 1 byte: token length
   - N bytes: token (SHA-256 hash of shared secret)
4. Server validates token and sends response:
   - 1 byte: 0x00 (success) or 0x01 (failure)

### Token Frame Format (Client → Server)

```
+--------+---------+
| LEN    | TOKEN   |
+--------+---------+
| 1 byte | N bytes |
+--------+---------+
```

Where:
- **LEN**: Token length (1 byte)
- **TOKEN**: SHA-256 hash of the shared secret

### Response Format (Server → Client)

```
+--------+
| STATUS |
+--------+
| 1 byte |
+--------+
```

Where:
- **STATUS**: 0x00 (success) or 0x01 (failure)

## Authentication Method Codes

SOCKS5 defines the following standard method codes:
- `0x00`: No authentication required
- `0x01`: GSS-API authentication
- `0x02`: Username/password authentication
- `0x03-0x7F`: IANA assigned methods
- `0x80-0xFE`: Private methods (used by this example)
- `0xFF`: No acceptable methods

This example uses `0x80` for the custom token-based authentication method.

