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
	proxyURL = flag.String(
		"proxy",
		"socks5://127.0.0.1:1080",
		"SOCKS proxy URL",
	)
	targetURL = flag.String("url", "http://example.com", "Target URL to fetch")
)

func main() {
	flag.Parse()

	// Parse proxy URL to create Client
	client, err := socksgo.ClientFromURL(*proxyURL)
	if err != nil {
		log.Fatalf("failed to parse proxy URL: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				return client.Dial(dialCtx, network, addr)
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
