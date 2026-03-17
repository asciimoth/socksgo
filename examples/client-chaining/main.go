// nolint
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/asciimoth/socksgo"
)

var (
	proxy1URL = flag.String("proxy1",
		"socks5://127.0.0.1:1080", "First SOCKS proxy URL")
	proxy2URL = flag.String("proxy2",
		"socks5://127.0.0.1:1090", "Second SOCKS proxy URL")
	targetURL = flag.String("url",
		"http://example.com", "Target URL to fetch")
	timeout = flag.Duration("timeout",
		30*time.Second, "Request timeout")
)

func main() {
	flag.Parse()

	// Create first (inner) proxy client
	proxy1, err := socksgo.ClientFromURL(*proxy1URL)
	if err != nil {
		log.Fatalf("failed to parse proxy1 URL: %v", err)
	}

	// Create second (outer) proxy client
	proxy2, err := socksgo.ClientFromURL(*proxy2URL)
	if err != nil {
		log.Fatalf("failed to parse proxy2 URL: %v", err)
	}

	// Extract host and port from target URL
	targetHost, targetPort, err := parseTargetURL(*targetURL)
	if err != nil {
		log.Fatalf("failed to parse target URL: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(),
		*timeout)
	defer cancel()

	// Chain proxies: proxy2 uses proxy1 as its dialer
	proxy2.Dialer = func(ctx context.Context,
		network, address string) (net.Conn, error) {
		return proxy1.Dial(ctx, network, address)
	}

	proxy1.Filter = socksgo.PassAllFilter
	proxy2.Filter = socksgo.PassAllFilter

	// Connect to target through proxy chain
	addr := net.JoinHostPort(targetHost, targetPort)
	log.Printf("connecting to %s via %s via %s",
		addr, *proxy2URL, *proxy1URL)

	conn, err := proxy2.Dial(ctx, "tcp", addr)
	if err != nil {
		log.Fatalf("failed to connect through proxy chain: %v",
			err)
	}
	defer func() { _ = conn.Close() }()

	// Send HTTP request through proxy chain
	log.Printf("connected successfully, sending HTTP request...")

	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n"+
		"Connection: close\r\n\r\n",
		*targetURL, targetHost)
	if _, err := conn.Write([]byte(request)); err != nil {
		log.Fatalf("failed to send request: %v", err)
	}

	// Read and print response
	response, err := io.ReadAll(conn)
	if err != nil {
		log.Fatalf("failed to read response: %v", err)
	}

	fmt.Println(string(response))
	log.Printf("request completed successfully")
}

// parseTargetURL extracts host and port from a URL.
// Supports http:// and https:// schemes.
func parseTargetURL(url string) (host, port string, err error) {
	if url == "" {
		return "", "", fmt.Errorf("empty URL")
	}

	// Remove scheme
	schemePrefix := "http://"
	if len(url) > 8 && url[:7] == "https://" {
		schemePrefix = "https://"
		port = "443"
	} else {
		port = "80"
	}

	hostPart := url[len(schemePrefix):]
	if hostPart == "" {
		return "", "", fmt.Errorf("invalid URL: missing host")
	}

	// Remove path if present
	if idx := strings.Index(hostPart, "/"); idx != -1 {
		hostPart = hostPart[:idx]
	}

	// Check if port is explicitly specified
	if h, p, err := net.SplitHostPort(hostPart); err == nil {
		return h, p, nil
	}

	return hostPart, port, nil
}
