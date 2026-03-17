// nolint
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/asciimoth/socksgo"
)

var (
	proxyURL     = flag.String("proxy", "socks5://127.0.0.1:9050", "Tor SOCKS proxy URL")
	numStreams   = flag.Int("streams", 3, "Number of isolated streams to test")
	targetURL    = flag.String("url", "https://api.ipify.org?format=json", "URL to check IP address")
	timeout      = flag.Duration("timeout", 30*time.Second, "Request timeout per stream")
	dedicatedIDs = flag.Bool("dedicated", false, "Use dedicated isolation IDs for each stream (vs random)")
)

type IPResponse struct {
	IP string `json:"ip"`
}

func main() {
	flag.Parse()

	client, err := socksgo.ClientFromURL(*proxyURL)
	if err != nil {
		log.Fatalf("failed to parse proxy URL: %v", err)
	}

	log.Printf("testing Tor stream isolation via %s", *proxyURL)
	log.Printf("making %d isolated requests to %s", *numStreams, *targetURL)

	var wg sync.WaitGroup
	results := make(chan IPResponse, *numStreams)
	errors := make(chan error, *numStreams)

	for i := 0; i < *numStreams; i++ {
		wg.Add(1)

		go func(streamID int) {
			defer wg.Done()

			var isolationID *string
			if *dedicatedIDs {
				id := fmt.Sprintf("stream-%d", streamID)
				isolationID = &id
				log.Printf("stream %d: using dedicated isolation ID: %s", streamID, id)
			} else {
				log.Printf("stream %d: using random isolation ID", streamID)
			}

			isolatedClient := client.WithTorIsolation(isolationID)
			if isolatedClient == nil {
				errors <- fmt.Errorf("stream %d: failed to create isolated client", streamID)
				return
			}

			ip, err := fetchIP(isolatedClient, *targetURL, *timeout)
			if err != nil {
				errors <- fmt.Errorf("stream %d: %w", streamID, err)
				return
			}

			results <- IPResponse{IP: ip}
			log.Printf("stream %d: IP = %s", streamID, ip)
		}(i)
	}

	wg.Wait()
	close(results)
	close(errors)

	var ips []string
	for result := range results {
		ips = append(ips, result.IP)
	}

	if len(errors) > 0 {
		for err := range errors {
			log.Printf("error: %v", err)
		}
	}

	if len(ips) == 0 {
		log.Fatal("no successful requests")
	}

	log.Println("\n=== Results ===")
	log.Printf("Unique IPs: %d", uniqueCount(ips))
	log.Printf("Total successful requests: %d", len(ips))

	allSame := true
	for i := 1; i < len(ips); i++ {
		if ips[i] != ips[0] {
			allSame = false
			break
		}
	}

	if allSame {
		log.Println("All streams resolved to the same IP (isolation may not be working)")
	} else {
		log.Println("Streams resolved to different IPs (isolation is working)")
	}

	for i, ip := range ips {
		log.Printf("  Stream %d: %s", i, ip)
	}
}

func fetchIP(client *socksgo.Client, targetURL string, timeout time.Duration) (string, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				return client.Dial(dialCtx, network, addr)
			},
		},
	}

	resp, err := httpClient.Get(targetURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var ipResp IPResponse
	if err := json.NewDecoder(resp.Body).Decode(&ipResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if ipResp.IP == "" {
		return "", fmt.Errorf("no IP in response")
	}

	return ipResp.IP, nil
}

func uniqueCount(ips []string) int {
	seen := make(map[string]bool)
	count := 0
	for _, ip := range ips {
		if !seen[ip] {
			seen[ip] = true
			count++
		}
	}
	return count
}
