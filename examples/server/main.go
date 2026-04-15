// nolint
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
	"github.com/coder/websocket"
)

var (
	tcpAddr = flag.String("tcp-addr", "127.0.0.1:1080", "TCP listen address")
	tlsAddr = flag.String("tls-addr", "127.0.0.1:1081", "TLS listen address")
	wsAddr  = flag.String(
		"ws-addr",
		"127.0.0.1:1082",
		"WebSocket listen address",
	)
	username = flag.String("user", "", "Username for authentication")
	password = flag.String("pass", "", "Password for authentication")
)

func main() {
	flag.Parse()

	var auth *protocol.AuthHandlers = nil
	if username != nil && password != nil && *username != "" &&
		*password != "" {
		(&protocol.AuthHandlers{}).
			Add(&protocol.NoAuthHandler{}).
			Add(&protocol.PassAuthHandler{
				VerifyFn: func(user, pass string) bool {
					return user == *username && pass == *password
				},
			})
	}

	// Create server with default handlers
	server := &socksgo.Server{
		// Use PreCmd hook for logging all commands
		PreCmd: preCmdLogger,
		// Set up authentication
		Auth: auth,
		// Use default command handlers
		Handlers: socksgo.DefaultCommandHandlers,
	}

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel to collect errors from listeners (only errors, not success signals)
	errCh := make(chan error, 4)

	// WaitGroup to track listener goroutines
	var wg sync.WaitGroup

	wg.Go(func() {
		startTCPListener(ctx, server, *tcpAddr, errCh)
	})

	wg.Go(func() {
		startTLSListener(ctx, server, *tlsAddr, errCh)
	})

	wg.Go(func() {
		startWSListener(ctx, server, *wsAddr, errCh)
	})

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

	log.Println("server stopped")
}

// preCmdLogger is a PreCmd hook that logs all SOCKS commands.
// It demonstrates how to use the PreCmd hook for logging, auditing,
// or custom validation before executing any command.
func preCmdLogger(
	ctx context.Context,
	conn net.Conn,
	ver string,
	info protocol.AuthInfo,
	cmd protocol.Cmd,
	addr protocol.Addr,
) (protocol.ReplyStatus, error) {
	// Extract client address
	clientAddr := conn.RemoteAddr().String()

	// Extract authentication info
	var authInfo string
	switch info.Code { //nolint:exhaustive
	case protocol.NoAuthCode:
		authInfo = "no-auth"
	case protocol.PassAuthCode:
		if user, ok := info.Info["user"].(string); ok {
			pass, _ := info.Info["pass"].(string)
			authInfo = fmt.Sprintf("user=%s pass=%s", user, pass)
		} else {
			authInfo = "password-auth"
		}
	default:
		authInfo = fmt.Sprintf("auth-code=%d", info.Code)
	}

	// Log the command
	log.Printf("[%s] %s %s %s -> %s",
		clientAddr,
		ver,
		authInfo,
		cmd.String(),
		addr.String(),
	)

	// Allow the command (return 0 status and nil error)
	return 0, nil
}

func startTCPListener(
	ctx context.Context,
	server *socksgo.Server,
	addr string,
	errCh chan<- error,
) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		errCh <- fmt.Errorf("TCP listener failed: %w", err)
		return
	}

	log.Printf("TCP SOCKS server listening on %s", addr)

	// Monitor context cancellation to force close listener
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener was closed (by context cancellation or error)
			return
		}

		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			log.Printf("TCP connection from %s", c.RemoteAddr())
			if err := server.Accept(ctx, c, false); err != nil {
				log.Printf(
					"TCP connection from %s closed with error: %v",
					c.RemoteAddr(),
					err,
				)
			} else {
				log.Printf(
					"TCP connection from %s closed normally",
					c.RemoteAddr(),
				)
			}
		}(conn)
	}
}

// startTLSListener starts a TLS-encrypted SOCKS server.
func startTLSListener(
	ctx context.Context,
	server *socksgo.Server,
	addr string,
	errCh chan<- error,
) {
	// Generate self-signed certificate for demo if not provided
	cert, err := generateSelfSignedCert()
	if err != nil {
		errCh <- fmt.Errorf("TLS cert generation failed: %w", err)
		return
	}
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	netListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		errCh <- fmt.Errorf("TLS listener failed: %w", err)
		return
	}
	listener := tls.NewListener(netListener, &tlsConfig)

	log.Printf("TLS SOCKS server listening on %s", addr)

	// Monitor context cancellation to force close listener
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener was closed (by context cancellation or error)
			return
		}

		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			log.Printf("TLS connection from %s", c.RemoteAddr())
			if err := server.Accept(ctx, c, true); err != nil {
				log.Printf(
					"TLS connection from %s closed with error: %v",
					c.RemoteAddr(),
					err,
				)
			} else {
				log.Printf(
					"TLS connection from %s closed normally",
					c.RemoteAddr(),
				)
			}
		}(conn)
	}
}

func startWSListener(
	ctx context.Context,
	server *socksgo.Server,
	addr string,
	errCh chan<- error,
) {
	// Create HTTP server for WebSocket upgrade
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		handleWS(ctx, server, w, r, false)
	})

	// Create listener first so we can close it explicitly
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		errCh <- fmt.Errorf("WebSocket listener failed: %w", err)
		return
	}

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("WebSocket SOCKS server listening on %s/ws", addr)

		if err := httpServer.Serve(listener); err != http.ErrServerClosed {
			log.Printf("WebSocket server error: %v", err)
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	// Shutdown HTTP server gracefully
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)

	// Force close listener to release port immediately
	_ = listener.Close()
}

func handleWS(
	ctx context.Context,
	server *socksgo.Server,
	w http.ResponseWriter,
	r *http.Request,
	isTLS bool,
) {
	opts := &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	}

	conn, err := websocket.Accept(w, r, opts)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "")

	log.Printf("WebSocket connection from %s", r.RemoteAddr)
	if err := server.AcceptWS(ctx, conn, isTLS); err != nil {
		log.Printf(
			"WebSocket connection from %s closed with error: %v",
			r.RemoteAddr,
			err,
		)
	} else {
		log.Printf(
			"WebSocket connection from %s closed normally",
			r.RemoteAddr,
		)
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	// Generate ECDSA private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("key generation failed: %w", err)
	}

	// Certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumber, err := rand.Int(
		rand.Reader,
		new(big.Int).Lsh(big.NewInt(1), 128),
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"serial generation failed: %w",
			err,
		)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SOCKS Server Demo"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
		DNSNames: []string{"localhost"},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf(
			"certificate creation failed: %w",
			err,
		)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// Encode private key to PEM
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("key marshaling failed: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	// Create tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("keypair creation failed: %w", err)
	}

	log.Println("generated self-signed certificate (for demo use only)")
	return cert, nil
}
