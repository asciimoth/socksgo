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

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

var (
	serverAAddr = flag.String("server-a", "127.0.0.1:1080",
		"Listen address for Server A (front server)")
	serverBAddr = flag.String("server-b", "127.0.0.1:1081",
		"Listen address for Server B (back server)")
	username = flag.String("user", "", "Username for authentication")
	password = flag.String("pass", "", "Password for authentication")
)

func main() {
	flag.Parse()

	// Create Server B (back server) - connects directly to targets
	// This server handles actual connections to the internet
	serverB := &socksgo.Server{
		PreCmd:   preCmdLogger("ServerB"),
		Handlers: socksgo.DefaultCommandHandlers,
	}

	// Create Server A (front server) - chains to Server B
	// First create a client that connects to Server B
	clientB, err := socksgo.ClientFromURL(
		fmt.Sprintf("socks5://%s", *serverBAddr),
	)
	if err != nil {
		log.Fatalf("failed to create client for Server B: %v", err)
	}

	// Configure client to pass all traffic through Server B
	clientB.Filter = gonnect.FalseFilter

	// Set up authentication for both servers if credentials provided
	var auth *protocol.AuthHandlers = nil
	if username != nil && password != nil && *username != "" &&
		*password != "" {
		auth = (&protocol.AuthHandlers{}).
			Add(&protocol.NoAuthHandler{}).
			Add(&protocol.PassAuthHandler{
				VerifyFn: func(user, pass string) bool {
					return user == *username && pass == *password
				},
			})

		// Update both servers with auth
		serverB.Auth = auth
		clientB.Auth = (&protocol.AuthMethods{}).
			Add(&protocol.PassAuthMethod{
				User: *username,
				Pass: *password,
			})
	}

	// Create Server A with the client as its dialer
	// When Server A receives a CONNECT request, it uses clientB.Dial
	// to forward the request to Server B
	serverA := &socksgo.Server{
		PreCmd:   preCmdLogger("ServerA"),
		Auth:     auth,
		Handlers: socksgo.DefaultCommandHandlers,
		Dialer:   clientB.Dial,
	}

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel to collect errors from listeners
	errCh := make(chan error, 2)

	// WaitGroup to track listener goroutines
	var wg sync.WaitGroup

	// Start Server B (back server)
	wg.Go(func() {
		startListener(ctx, serverB, *serverBAddr, "ServerB", errCh)
	})

	// Start Server A (front server)
	wg.Go(func() {
		startListener(ctx, serverA, *serverAAddr, "ServerA", errCh)
	})

	log.Printf("Server chaining started:")
	log.Printf("  Server B (back):  %s -> direct connection", *serverBAddr)
	log.Printf("  Server A (front): %s -> Server B -> target", *serverAAddr)

	// Wait for shutdown signal or error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received signal %v, shutting down...", sig)
	case err := <-errCh:
		if err != nil {
			log.Printf("listener error: %v", err)
		}
	}

	cancel()

	// Wait for all listeners to finish
	wg.Wait()

	log.Println("server chaining stopped")
}

// preCmdLogger logs all commands for a specific server instance.
func preCmdLogger(serverName string) func(
	ctx context.Context,
	conn net.Conn,
	ver string,
	info protocol.AuthInfo,
	cmd protocol.Cmd,
	addr protocol.Addr,
) (protocol.ReplyStatus, error) {
	return func(
		ctx context.Context,
		conn net.Conn,
		ver string,
		info protocol.AuthInfo,
		cmd protocol.Cmd,
		addr protocol.Addr,
	) (protocol.ReplyStatus, error) {
		clientAddr := conn.RemoteAddr().String()

		var authInfo string
		switch info.Code {
		case protocol.NoAuthCode:
			authInfo = "no-auth"
		case protocol.PassAuthCode:
			if user, ok := info.Info["user"].(string); ok {
				authInfo = fmt.Sprintf("user=%s", user)
			} else {
				authInfo = "password-auth"
			}
		default:
			authInfo = fmt.Sprintf("auth-code=%d", info.Code)
		}

		log.Printf("[%s] %s %s %s %s -> %s",
			serverName,
			clientAddr,
			ver,
			authInfo,
			cmd.String(),
			addr.String(),
		)

		return 0, nil
	}
}

// startListener starts a SOCKS server on the given address.
func startListener(
	ctx context.Context,
	server *socksgo.Server,
	addr string,
	serverName string,
	errCh chan<- error,
) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		errCh <- fmt.Errorf("%s listener failed: %w", serverName, err)
		return
	}

	log.Printf("%s listening on %s", serverName, addr)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}

		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			log.Printf("%s connection from %s", serverName, c.RemoteAddr())
			if err := server.Accept(ctx, c, false); err != nil {
				log.Printf("%s connection from %s closed with error: %v",
					serverName, c.RemoteAddr(), err)
			} else {
				log.Printf("%s connection from %s closed normally",
					serverName, c.RemoteAddr())
			}
		}(conn)
	}
}
