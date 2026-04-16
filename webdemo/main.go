//go:build js

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"syscall/js"

	"github.com/asciimoth/socksgo"
)

var (
	document      = js.Global().Get("document")
	resultElement js.Value
	statusElement js.Value
)

func log(message string) {
	fmt.Println("[WASM]: ", message)
}

func updateStatus(status string) {
	statusElement.Set("textContent", status)
	log(status)
}

func updateStatusClass(status string) {
	statusElement.Set("className", status)
	log(status)
}

func updateResult(content string) {
	resultElement.Set("textContent", content)
}

func makeRequest(wsURL, targetURL string) {
	log("Starting request...")
	log("WebSocket URL: " + wsURL)
	log("Target URL: " + targetURL)

	updateStatus("Connecting to proxy...")

	// Create SOCKS client over WebSocket
	client, err := socksgo.ClientFromURL(wsURL)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to create client: %v", err)
		updateStatus(errorMsg)
		updateResult(errorMsg)
		return
	}

	// Create HTTP client with SOCKS transport
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				log("Dialing " + network + ":" + addr + " ...")
				return client.Dial(dialCtx, network, addr)
			},
		},
	}

	updateStatus("Making HTTP request...")

	// Make request
	resp, err := httpClient.Get(targetURL)
	if err != nil {
		errorMsg := fmt.Sprintf("Request failed: %v", err)
		updateStatus(errorMsg)
		updateResult(errorMsg)
		return
	}
	defer resp.Body.Close()

	updateStatus("Reading response...")

	// Read body
	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil && err.Error() != "EOF" {
		errorMsg := fmt.Sprintf("Failed to read response: %v", err)
		updateStatus(errorMsg)
		updateResult(errorMsg)
		return
	}

	updateStatus("Request completed successfully")
	updateStatusClass("status ready")
	updateResult(string(buf[:n]))
}

func main() {
	log("SOCKS WebSocket WASM Demo initializing...")

	// Get DOM elements
	resultElement = document.Call("getElementById", "result")
	statusElement = document.Call("getElementById", "status")

	// Create makeRequest function for JavaScript
	jsFunc := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 2 {
			return "Error: Expected 2 arguments (wsURL, targetURL)"
		}

		wsURL := args[0].String()
		targetURL := args[1].String()

		go makeRequest(wsURL, targetURL)
		return nil
	})

	// Expose function to global scope
	js.Global().Set("makeSocksRequest", jsFunc)

	log("WASM initialized successfully")
	updateStatus("Ready. Enter WebSocket URL and Target URL, then click 'Make Request'")

	// Keep the program running
	select {}
}
