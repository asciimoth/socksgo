# SOCKS Proxy Interceptor Example

A SOCKS5 proxy server that intercepts and modifies HTTP/HTTPS connections, serving mock responses instead of forwarding to real destinations.

## Features

- **Protocol Detection**: Automatically detects HTTP vs TLS traffic
- **Dynamic TLS**: Generates TLS certificates on-the-fly using the provided CA
- **Custom Handlers**: Demonstrates how to implement custom command handlers
- **Connection Interception**: Serves mock HTTP responses

## Prerequisites

Generate a CA certificate and key:

```sh
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt -subj "/CN=MyTestCA/O=MyOrg/C=US"
```

## Usage

```sh
go run .
```

Default listen address: `127.0.0.1:1080`

### Options

- `-tcp-addr`: TCP listen address (default: `127.0.0.1:1080`)
- `-crt`: CA certificate file (default: `./ca.crt`)
- `-key`: CA private key file (default: `./ca.key`)

## Examples

### Intercept HTTP Traffic

```sh
curl -4 --proxy socks5h://localhost:1080 http://example.com/
```

### Intercept HTTPS Traffic

```sh
# Use the CA certificate to trust the dynamically generated TLS certificate
curl --cacert ca.crt -4 --proxy socks5h://localhost:1080 https://example.com/
```

## How It Works

1. **Accept Connection**: SOCKS server accepts incoming connections
2. **Pre-Command Hook**: Logs client info, auth method, command, and target address
3. **Command Handler**: For CONNECT commands, replies with success
4. **Protocol Detection**: Peeks at first few bytes to detect HTTP vs TLS
5. **Interception**:
   - HTTP: Directly serves mock response
   - TLS: Generates certificate for target host, performs TLS handshake, serves mock response
6. **Mock Response**: Returns a response showing intercepted request details

