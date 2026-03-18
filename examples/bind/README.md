# SOCKS BIND Client Example

A simple CLI client example demonstrating how to use socksgo's BIND command to create a listening port through a SOCKS proxy.

## Usage

```sh
go run . [options]
```

### Options

- `-proxy`: SOCKS proxy URL (default: `socks5://127.0.0.1:1080`)

## Examples

### Basic SOCKS5 BIND

```sh
# Start a listener through local SOCKS5 proxy
go run . -proxy socks5://localhost:1080
```

Then in another terminal:
```sh
curl http://<listener-address>
```

### With Authentication

```sh
go run . -proxy socks5://user:pass@localhost:1080
```

