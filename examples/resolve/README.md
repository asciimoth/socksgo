# SOCKS Proxy DNS Resolve Example

A simple CLI example demonstrating how to use socksgo to perform forward DNS lookups (hostname → IP address) through a SOCKS proxy using Tor's SOCKS extension.

## Usage

```sh
go run . [options]
```

### Options

- `-proxy`: SOCKS proxy URL (default: `socks5://127.0.0.1:1080?tor`)
- `-host`: Hostname to resolve (default: `example.com`)
- `-timeout`: Operation timeout (default: `30s`)

## Examples

### Basic Forward Lookup

```sh
# Resolve hostname to any IP (IPv4 or IPv6)
go run . -proxy socks5://localhost:1080?tor -host example.com
```

### With Authentication

```sh
# Use SOCKS proxy with authentication
go run . -proxy socks5://user:pass@localhost:1080?tor -host google.com
```

### Tor Proxy

```sh
# Resolve through Tor daemon SOCKS proxy (default port 9050)
go run . -proxy socks5://localhost:9050?tor -host check.torproject.org
```

## Notes

The `?tor` URL option is required to enable Tor's SOCKS extension for DNS resolution. Without it, the `LookupIP` method will return an error.

