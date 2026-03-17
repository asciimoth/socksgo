// nolint
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"github.com/asciimoth/socksgo"
)

var (
	proxy1URL = flag.String("proxy1",
		"socks5://127.0.0.1:1080", "First SOCKS proxy URL")
	proxy2URL = flag.String("proxy2",
		"socks5://127.0.0.1:1090", "Second SOCKS proxy URL")
	targetURL = flag.String("url",
		"http://example.com", "Target URL to fetch")
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

	// Chain proxies: proxy2 uses proxy1 as its dialer
	proxy2.Dialer = func(ctx context.Context,
		network, address string) (net.Conn, error) {
		return proxy1.Dial(ctx, network, address)
	}

	proxy1.Filter = socksgo.PassAllFilter
	proxy2.Filter = socksgo.PassAllFilter

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				return proxy2.Dial(dialCtx, network, addr)
			},
		},
	}

	resp, err := httpClient.Get(*targetURL)

	// Dial to target host through SOCKS proxy
	if err != nil {
		log.Fatalf("failed run request: %v", err)
	}

	response, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed read body: %v", err)
	}

	fmt.Println(string(response))
	log.Printf("request completed successfully")
}
