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
	proxyURL  = flag.String("proxy", "socks5://127.0.0.1:1080", "SOCKS proxy URL")
	targetURL = flag.String("url", "http://example.com", "Target URL to fetch")
	timeout   = flag.Duration("timeout", 30*time.Second, "Request timeout")
)

func main() {
	flag.Parse()

	// Parse proxy URL to create Client
	client, err := socksgo.ClientFromURL(*proxyURL)
	if err != nil {
		log.Fatalf("failed to parse proxy URL: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Dial to target host through SOCKS proxy
	// Extract host and port from target URL
	targetHost, targetPort, err := parseTargetURL(*targetURL)
	if err != nil {
		log.Fatalf("failed to parse target URL: %v", err)
	}

	addr := net.JoinHostPort(targetHost, targetPort)
	log.Printf("connecting to %s via %s", addr, *proxyURL)

	// Use Dial to establish connection through proxy
	conn, err := client.Dial(ctx, "tcp", addr)
	if err != nil {
		log.Fatalf("failed to connect through proxy: %v", err)
	}
	defer conn.Close()

	log.Printf("connected successfully, sending HTTP request...")

	// Send HTTP request
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", *targetURL, targetHost)
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
