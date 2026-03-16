# SOCKS Proxy Server Example

A comprehensive SOCKS5 proxy server example demonstrating TCP, TLS, and WebSocket transports with logging.

Run with defaults:
```sh
go run .
```

This starts:
- TCP listener on `127.0.0.1:1080`
- TLS listener on `127.0.0.1:1081` (self signed certificates)
- WebSocket listener on `127.0.0.1:1082` at `/ws`

## Curl
```sh
# No auth
curl -4 --proxy socks5://localhost:1080 http://example.com

# Pass auth
curl -4 --proxy socks5://myuser:mypass@localhost:1080 http://example.com
```

## Gost
```sh 
# Run chain socks -> socks+tls
gost -L socks5://:1090 -F socks5+tls://localhost:1081

# Run chain socks -> socks+ws
gost -L socks5://:1090 -F socks5+ws://localhost:1082
```

Then use curl as usual
```sh
curl -4 --proxy socks5://localhost:1090 http://example.com
```

