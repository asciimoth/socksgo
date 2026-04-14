// nolint
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/asciimoth/socksgo"
)

var (
	proxyURL = flag.String(
		"proxy",
		"socks5://127.0.0.1:1080?tor",
		"SOCKS proxy URL",
	)
	hostname = flag.String("host", "example.com", "Hostname to resolve")
	timeout  = flag.Duration("timeout", 30*time.Second, "Operation timeout")
)

func main() {
	flag.Parse()

	url := *proxyURL
	if !containsQuery(url) {
		url += "?tor"
	}

	client, err := socksgo.ClientFromURL(url)
	if err != nil {
		log.Fatalf("failed to parse proxy URL: %v", err)
	}

	if !client.TorLookup {
		log.Fatal("tor option not enabled - add ?tor to proxy URL")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	log.Printf("resolving %s via SOCKS proxy %s", *hostname, url)

	start := time.Now()
	ips, err := client.LookupIP(ctx, "ip", *hostname)
	elapsed := time.Since(start)
	if err != nil {
		log.Fatalf("failed to resolve hostname: %v", err)
	}

	log.Printf("resolved %s in %v:", *hostname, elapsed)
	for _, ip := range ips {
		log.Printf("  - %s", ip)
	}

	log.Println("DNS resolution completed successfully")
}

func containsQuery(url string) bool {
	return len(url) > 0 && url[len(url)-1] == '?' || contains(url, "?")
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
