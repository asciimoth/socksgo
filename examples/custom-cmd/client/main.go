// nolint
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"time"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

const (
	CmdHelloWorld protocol.Cmd = 0xF4
)

var (
	proxyURL = flag.String("proxy", "socks5://127.0.0.1:1080", "SOCKS proxy URL")
	payload  = flag.String("payload", "custom message", "Message to send with the command")
)

func main() {
	flag.Parse()

	log.Printf("HelloWorld client connecting to %s", *proxyURL)

	client, err := socksgo.ClientFromURL(*proxyURL)
	if err != nil {
		log.Fatalf("failed to parse proxy URL: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	addr := protocol.AddrFromFQDN(*payload, 0, "")

	log.Printf("Sending HelloWorld command (0xF4) with payload: %s", *payload)

	proxyConn, replyAddr, err := client.Request(ctx, CmdHelloWorld, addr)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer proxyConn.Close()

	log.Printf("Command succeeded! Server replied with address: %s", replyAddr)

	response, err := io.ReadAll(proxyConn)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	log.Printf("Response: %s", string(response))

	log.Println("HelloWorld command completed successfully")
}
