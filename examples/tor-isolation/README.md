# Tor Stream Isolation Example

A CLI example demonstrating how to use Tor's SOCKS stream isolation extension to create multiple isolated streams through Tor using socksgo's `Client.WithTorIsolation()` method.

Tor stream isolation ensures that different connections use separate Tor circuits.

## Usage

```sh
go run . [options]
```

### Options

- `-proxy`: Tor SOCKS proxy URL (default: `socks5://127.0.0.1:9050`)
- `-streams`: Number of isolated streams to test (default: `3`)
- `-url`: URL to check IP address (default: `https://api.ipify.org?format=json`)
- `-timeout`: Request timeout per stream (default: `30s`)
- `-dedicated`: Use dedicated isolation IDs for each stream (default: `false`, use random IDs)

## Examples

### Basic Isolation Test (Random IDs)

```sh
# Test with 3 random isolated streams
go run . -proxy socks5://localhost:9050 -streams 3
```

### Dedicated Isolation IDs

```sh
# Use dedicated isolation IDs for predictable behavior
go run . -proxy socks5://localhost:9050 -streams 5 -dedicated
```

### Custom Target URL

```sh
# Use a different IP check service
go run . -proxy socks5://localhost:9050 -url "https://ifconfig.me/all.json"
```

## How It Works

1. **Creates base client**: Connects to Tor SOCKS proxy
2. **Creates isolated clients**: Uses `WithTorIsolation()` to create copies with different isolation IDs
3. **Makes parallel requests**: Each isolated client makes a request to check its visible IP
4. **Compares results**: Shows whether different streams have different exit IPs

### Random vs Dedicated IDs

- **Random IDs** (default): Each call to `WithTorIsolation(nil)` generates a random 32-char hex ID
  ```go
  isolatedClient := client.WithTorIsolation(nil)  // Random ID
  ```

- **Dedicated IDs**: You can specify a specific isolation ID for predictable behavior
  ```go
  id := "user-session-123"
  isolatedClient := client.WithTorIsolation(&id)  // Specific ID
  ```

Streams with the same isolation ID may share a Tor circuit. Streams with different IDs will use separate circuits.

## Sample Output

```
2026/03/17 04:12:04 testing Tor stream isolation via socks5://127.0.0.1:9050
2026/03/17 04:12:04 making 3 isolated requests to https://api.ipify.org?format=json
2026/03/17 04:12:04 stream 2: using random isolation ID
2026/03/17 04:12:04 stream 0: using random isolation ID
2026/03/17 04:12:04 stream 1: using random isolation ID
2026/03/17 04:12:05 stream 0: IP = 46.232.251.191
2026/03/17 04:12:05 stream 2: IP = 192.42.116.99
2026/03/17 04:12:05 stream 1: IP = 185.129.61.9
2026/03/17 04:12:05 
=== Results ===
2026/03/17 04:12:05 Unique IPs: 3
2026/03/17 04:12:05 Total successful requests: 3
2026/03/17 04:12:05 Streams resolved to different IPs (isolation is working)
2026/03/17 04:12:05   Stream 0: 46.232.251.191
2026/03/17 04:12:05   Stream 1: 192.42.116.99
2026/03/17 04:12:05   Stream 2: 185.129.61.9
```

## Notes

- This example requires a running Tor SOCKS proxy (default: `127.0.0.1:9050`)
- Tor stream isolation is a Tor-specific extension; it won't work with standard SOCKS proxies
- The actual exit IPs depend on Tor's circuit selection and can change over time
- Using dedicated IDs with the same value will result in streams sharing a circuit

## See Also

- [Tor SOCKS Extensions](https://spec.torproject.org/socks-extensions.html#extended-auth)
- [`examples/resolve`](../resolve/): DNS resolution through Tor
- [`examples/resolve-ptr`](../resolve-ptr/): Reverse DNS through Tor

