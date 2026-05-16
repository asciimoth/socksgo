# Testing Guide

Comprehensive testing documentation for socksgo.

## Commands

Tag `compattest` needed to run all tests.

```bash
go test ./... -tags=compattest
```

### Test Hooks Build Tag

The `testhooks` build tag enables test hooks for improved coverage of error paths:

```bash
# Run tests with test hooks enabled
go test ./... -tags="compattest testhooks"

# Run tests with race detector and test hooks
go test -race -tags="compattest testhooks" ./...
```

The test hooks allow testing of error paths that are difficult to trigger through normal API usage, such as:
- `LookupIP` with FQDN response (triggers `ErrWrongAddrInLookupResponse`)
- `Listen` with smux server errors
- Connection close behavior on error paths

Test hooks are only compiled when the `testhooks` tag is used and have zero impact on production builds.

### Coverage Reports

Internal test files and test hook code are excluded from coverage reports to avoid
inflating coverage metrics with test-only code that is not part of the production build.

**Excluded files:**
- `*_internal_test.go` - Internal test files for package-private functions
- `client_testhooks.go` - Test hooks for error path testing (build tag `testhooks`)

**Generate coverage report (excluding internal tests):**

```bash
# Generate coverage profile
go test ./... -tags="compattest testhooks" -coverprofile=coverage.out -coverpkg=./...

# Filter using the helper script
./scripts/filter_coverage.sh

# Or manually:
grep -v "client_testhooks.go" coverage.out | \
  grep -v "_internal_test.go" > coverage_filtered.out && \
  mv coverage_filtered.out coverage.out

# View coverage report
go tool cover -func=coverage.out

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html
```

**CI automatically filters** internal test files and testhooks from coverage before
submitting to Coveralls.

**Example usage in tests:**

```go
//go:build testhooks

package socksgo_test

import (
    "testing"
    "github.com/asciimoth/socksgo"
    "github.com/asciimoth/socksgo/protocol"
)

func TestLookupIPErrorPath(t *testing.T) {
    // Set up hook to simulate FQDN response
    oldHook := socksgo.GetTestLookupIPHook()
    socksgo.SetTestLookupIPHook(func(addr protocol.Addr) protocol.Addr {
        return protocol.AddrFromFQDN("example.com", 80, "tcp")
    })
    defer socksgo.SetTestLookupIPHook(oldHook)
    
    // ... test code ...
}
```

Available hooks:
- `SetTestLookupIPHook(hook)` / `GetTestLookupIPHook()`
- `SetTestLookupAddrHook(hook)` / `GetTestLookupAddrHook()`
- `SetTestListenSmuxHook(hook)` / `GetTestListenSmuxHook()`
- `SetTestListenCloseHook(hook)` / `GetTestListenCloseHook()`
- `ResetTestHooks()` - Reset all hooks to defaults

## Test File Organization

```
socksgo/
├── client_config_test.go       # Client configuration tests
├── client_test.go              # Client operation tests
├── common_test.go              # Shared test utilities
├── compat_curl_test.go         # curl compatibility tests
├── compat_gost_test.go         # gost compatibility tests
├── compat_tor_test.go          # Tor compatibility tests
├── compat_test.go              # General compatibility tests
├── errors_test.go              # Error type tests
├── pair_client_server_test.go  # Client-server integration tests
├── server_config_test.go       # Server configuration tests
├── server_handler_*_test.go    # Individual handler tests
│   ├── server_handler_assoc_test.go
│   ├── server_handler_bind_test.go
│   ├── server_handler_connect_test.go
│   ├── server_handler_mbind_test.go
│   ├── server_handler_resolve_test.go
│   ├── server_handler_resolveptr_test.go
│   └── server_handler_tun_test.go
├── server_handlers_test.go     # Handler registry tests
├── server_test.go              # Server operation tests
│
└── protocol/                   # Protocol layer tests
    ├── addr_test.go
    ├── cmd_test.go
    ├── errors_test.go
    ├── helpers_test.go
    ├── pipe_test.go
    ├── reply_test.go
    ├── v4_test.go
    ├── v5auth_gss_test.go
    ├── v5auth_pass_test.go
    ├── v5auth_test.go
    ├── v5tcp_test.go
    └── v5udp_test.go
```

## Test Categories

### 1. Unit Tests

Test individual functions and methods in isolation.

**Example:**
```go
func TestBuildFilter_HostsAndWildcards(t *testing.T) {
    t.Parallel()
    
    filter := socksgo.BuildFilter("*.example.com,192.168.1.1")
    
    tests := []struct {
        address  string
        expected bool
    }{
        {"test.example.com:80", true},
        {"192.168.1.1:80", true},
        {"google.com:80", false},
    }
    
    for _, tt := range tests {
        t.Run(tt.address, func(t *testing.T) {
            result := filter("", tt.address)
            if result != tt.expected {
                t.Errorf("got %v, want %v", result, tt.expected)
            }
        })
    }
}
```

### 2. Integration Tests

Test client-server interactions with actual network connections.

**Example:**
```go
func TestClientServerConnect(t *testing.T) {
    t.Parallel()
    
    // Start test server
    listener := startTestServer(t)
    defer listener.Close()
    
    // Create client
    client := &socksgo.Client{
        ProxyAddr: listener.Addr().String(),
    }
    
    // Test CONNECT through proxy
    conn, err := client.Dial(context.Background(), "tcp", "example.com:80")
    if err != nil {
        t.Fatal(err)
    }
    defer conn.Close()
    
    // Verify connection works
    _, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
    if err != nil {
        t.Fatal(err)
    }
}
```

### 3. Compatibility Tests

Test with external SOCKS implementations.

**Example:**
```go
func TestCompatGost(t *testing.T) {
    t.Parallel()
    
    // Start gost server
    gostCmd := startGostServer(t)
    defer gostCmd.Process.Kill()
    
    // Test our client against gost server
    client := &socksgo.Client{
        ProxyAddr: "127.0.0.1:1080",
        GostMbind: true,
    }
    
    conn, err := client.Dial(context.Background(), "tcp", "example.com:80")
    if err != nil {
        t.Fatal(err)
    }
    conn.Close()
}
```

### 4. Table-Driven Tests

Use table-driven tests for multiple scenarios.

**Example:**
```go
func TestClient_Version_GetNet_GetAddr(t *testing.T) {
    t.Parallel()
    
    tests := []struct {
        name           string
        client         *socksgo.Client
        expectedVer    string
        expectedNet    string
        expectedAddr   string
    }{
        {
            name:           "default",
            client:         &socksgo.Client{},
            expectedVer:    "5",
            expectedNet:    "tcp",
            expectedAddr:   "",
        },
        {
            name: "socks4",
            client: &socksgo.Client{
                SocksVersion: "4",
                ProxyAddr:    "127.0.0.1:1080",
            },
            expectedVer:    "4",
            expectedNet:    "tcp",
            expectedAddr:   "127.0.0.1:1080",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()
            
            if got := tt.client.Version(); got != tt.expectedVer {
                t.Errorf("Version() = %v, want %v", got, tt.expectedVer)
            }
        })
    }
}
```

## Current Test Coverage

### Well-Covered Areas ✅

1. **Client Configuration**
   - `ClientFromURL`, `ClientFromURLObjSafe`
   - Filter building and matching
   - Version detection

2. **Protocol Encoding/Decoding**
   - SOCKS4 request/reply
   - SOCKS5 request/reply
   - Address type conversions
   - Auth method negotiation

3. **Basic Client-Server Operations**
   - CONNECT command (all SOCKS versions)
   - TLS transport
   - WebSocket transport
   - Username/password auth

4. **Error Types**
   - All error type string formatting
   - Error wrapping and unwrapping

### Partially Covered Areas ⚠️

1. **Server Handlers**
   - Happy path tested
   - Error paths need more coverage
   - Edge cases (timeouts, cancellations)

2. **UDP Operations**
   - Basic UDP ASSOC tested
   - Gost UDPTun needs more tests
   - UDP timeout behavior

3. **Extensions**
   - MBIND basic functionality
   - Tor resolve commands
   - Extension flag interactions

### Coverage Gaps ❌

1. **Server Error Handling**
   - `PreCmd` hook rejection scenarios
   - Address filter rejections
   - Auth failure handling in server
   - Resource cleanup on errors

2. **Concurrency**
   - Race conditions in UDP proxy
   - MBIND session management
   - Concurrent handler execution

3. **Timeout Scenarios**
   - Handshake timeout
   - UDP assoc timeout
   - Context cancellation propagation

4. **Gost Extension Details**
   - UDPTun fragmentation handling
   - MBIND stream errors
   - Extension negotiation

## Running Tests
