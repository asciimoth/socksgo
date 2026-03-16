# SOCKS Proxy DNS Reverse Lookup Example

A simple CLI example demonstrating how to use socksgo to perform reverse DNS lookups (IP address → hostname) through a SOCKS proxy using Tor's SOCKS extension.

## Usage

```sh
go run . [options]
```

### Options

- `-proxy`: SOCKS proxy URL with `?tor` option (default: `socks5://127.0.0.1:1080?tor`)
- `-ip`: IP address to reverse lookup (default: `8.8.8.8`)
- `-timeout`: Operation timeout (default: `30s`)

## Examples

### Basic Reverse Lookup

```sh
# Reverse lookup for Google's DNS server
go run . -proxy socks5://localhost:1080?tor -ip 8.8.8.8

# Reverse lookup for Cloudflare's DNS server
go run . -proxy socks5://localhost:1080?tor -ip 1.1.1.1
```

### With Authentication

```sh
# Use SOCKS proxy with authentication
go run . -proxy socks5://user:pass@localhost:1080?tor -ip 8.8.8.8
```

### Tor Proxy

```sh
# Reverse lookup through Tor daemon SOCKS proxy (default port 9050)
go run . -proxy socks5://localhost:9050?tor -ip 8.8.8.8
```


## Notes

The `?tor` URL option is required to enable Tor's SOCKS extension for DNS resolution. Without it, the `LookupAddr` method will return an error.

Not all IP addresses have reverse DNS records. Some addresses may return an empty list of hostnames.

