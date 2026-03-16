// nolint
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/asciimoth/socksgo"
)

var (
	proxyURL = flag.String("proxy", "socks5://127.0.0.1:1080", "SOCKS proxy URL")
)

func main() {
	flag.Parse()

	// Parse proxy URL to create Client
	client, err := socksgo.ClientFromURL(*proxyURL)
	if err != nil {
		log.Fatalf("failed to parse proxy URL: %v", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l, err := client.Listen(context.Background(), "tcp", "0.0.0.0:0")
	if err != nil {
		log.Fatalf("failed to start listener: %v", err)
	}
	log.Printf("listening at %s", l.Addr())
	log.Printf("run curl http://%s", l.Addr())

	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	var wg sync.WaitGroup

	wg.Go(func() {
		startListener(l)
	})

	// Wait for shutdown signal or error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("received signal %v, shutting down...", sig)
	cancel()

	wg.Wait()

	log.Println("server stopped")
}

func startListener(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		log.Printf("Incoming conn %s %s", conn.LocalAddr(), conn.RemoteAddr())
		handler(conn)
	}
}

func handler(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	text := "Hello world!\n"

	response := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		len(text), text,
	)

	_, err := conn.Write([]byte(response))
	if err != nil {
		log.Printf("Error while responding %s", err)
	}

	log.Print("Response written")

	time.Sleep(time.Second * 1)
}
