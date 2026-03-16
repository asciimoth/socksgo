// nolint
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"time"

	"github.com/asciimoth/socksgo"
)

var (
	proxyURL = flag.String("proxy", "socks5://127.0.0.1:1080", "SOCKS proxy URL")
	hostname = flag.String("host", "example.com", "Hostname to resolve")
	timeout  = flag.Duration("timeout", 30*time.Second, "Operation timeout")
)

func main() {
	flag.Parse()

	client, err := socksgo.ClientFromURL(*proxyURL)
	if err != nil {
		log.Fatalf("failed to parse proxy URL: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			log.Printf("dialing %s %s through proxy", network, addr)
			c, err := client.Dial(dialCtx, network, addr)
			if err != nil {
				log.Printf("dial error: %v", err)
			}
			return c, err
		},
	}

	log.Printf("resolving %s via SOCKS proxy %s", *hostname, *proxyURL)
	log.Println("using TCP DNS through proxy (UDP dial pattern)")

	start := time.Now()
	ips, err := resolver.LookupHost(ctx, *hostname)
	elapsed := time.Since(start)
	if err != nil {
		log.Fatalf("failed to resolve hostname: %v", err)
	}

	log.Printf("resolved %s in %v:", *hostname, elapsed)
	for _, ip := range ips {
		log.Printf("  - %s", ip)
	}

	log.Println("resolving both IPv4 and IPv6...")
	ipv4s, err := resolver.LookupIPAddr(ctx, *hostname)
	if err != nil {
		log.Printf("failed to lookup IP addresses: %v", err)
	} else {
		for _, ipAddr := range ipv4s {
			log.Printf("  - %s (%s)", ipAddr.IP, ipAddr.Zone)
		}
	}

	log.Println("DNS resolution completed successfully")
}
