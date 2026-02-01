package socksgo_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/asciimoth/socksgo"
	"github.com/gorilla/websocket"
)

func connID(conn net.Conn) string {
	id := ""
	if conn.LocalAddr() != nil {
		id += conn.LocalAddr().Network() + ":" + conn.LocalAddr().String()
	} else {
		id += "nil"
	}
	id += "//"
	if conn.RemoteAddr() != nil {
		id += conn.RemoteAddr().Network() + ":" + conn.RemoteAddr().String()
	} else {
		id += "nil"
	}
	return id
}

func runWSServer(
	server *socksgo.Server,
	host string,
	isTLS bool,
) (func(), net.Addr, error) {
	ctx, ctx_cancel := context.WithCancel(context.Background())

	upgrader := websocket.Upgrader{}

	var wg sync.WaitGroup
	stopped := false
	var mu sync.Mutex
	sessions := map[string]*websocket.Conn{}
	addSession := func(conn *websocket.Conn) {
		sessions[connID(conn.NetConn())] = conn
	}
	rmSession := func(conn *websocket.Conn) {
		mu.Lock()
		defer mu.Unlock()
		delete(sessions, connID(conn.NetConn()))
	}
	cancel := func() {
		mu.Lock()
		defer mu.Unlock()
		stopped = true
		ctx_cancel()
		for _, v := range sessions {
			_ = v.Close()
		}
		sessions = map[string]*websocket.Conn{}
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		mu.Lock()
		if stopped {
			mu.Unlock()
			return
		}
		addSession(c)
		defer rmSession(c)
		wg.Add(1)
		defer wg.Done()
		mu.Unlock()
		_ = server.AcceptWS(ctx, c, isTLS)
	})

	stop, addr, err := runHTTPServer(handler, host, isTLS)
	if err != nil {
		ctx_cancel()
		return nil, nil, err
	}

	return func() {
		stop()
		cancel()
		wg.Wait()
	}, addr, nil
}

func runTLSServer(
	server *socksgo.Server,
	host string,
) (func(), net.Addr, error) {
	// Generate ephemeral self-signed cert
	cert, err := generateSelfSignedCert(host)
	if err != nil {
		return nil, nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	srv, err := tls.Listen("tcp", net.JoinHostPort(host, ""), tlsConfig)
	if err != nil {
		return nil, nil, err
	}
	cancel := runServer(server, srv, true)
	return cancel, srv.Addr(), nil
}

func runTCPServer(
	server *socksgo.Server,
	host string,
) (func(), net.Addr, error) {
	srv, err := net.Listen("tcp", net.JoinHostPort(host, "")) //nolint noctx
	if err != nil {
		return nil, nil, err
	}
	cancel := runServer(server, srv, false)
	return cancel, srv.Addr(), nil
}

func runServer(
	server *socksgo.Server,
	listener net.Listener,
	isTLS bool,
) func() {
	ctx, ctx_cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup

	stopped := false
	var mu sync.Mutex
	sessions := map[string]net.Conn{}
	addSession := func(conn net.Conn) {
		sessions[connID(conn)] = conn
	}
	rmSession := func(conn net.Conn) {
		mu.Lock()
		defer mu.Unlock()
		delete(sessions, connID(conn))
	}

	cancel := func() {
		mu.Lock()
		defer mu.Unlock()
		stopped = true
		ctx_cancel()
		_ = listener.Close()
		for _, v := range sessions {
			_ = v.Close()
		}
		sessions = map[string]net.Conn{}
	}

	wg.Go(func() {
		defer cancel()
		for {
			conn, err := listener.Accept()
			if err != nil {
				break
			}
			wg.Go(func() {
				mu.Lock()
				if stopped {
					mu.Unlock()
					return
				}
				addSession(conn)
				mu.Unlock()
				defer rmSession(conn)
				_ = server.Accept(ctx, conn, isTLS)
			})
		}
	})
	return func() {
		cancel()
		wg.Wait()
	}
}

// generateSelfSignedCert creates an in-memory RSA key + self-signed cert valid for 1 hour.
func generateSelfSignedCert(host string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&tmpl,
		&tmpl,
		&priv.PublicKey,
		priv,
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: derBytes},
	)
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("x509 key pair: %w", err)
	}
	return tlsCert, nil
}

func runHTTPServer(
	handler http.Handler,
	host string,
	isTLS bool,
) (stop func(), addr net.Addr, err error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "")) //nolint noctx
	if err != nil {
		return nil, nil, err
	}

	var tlsCfg *tls.Config
	if isTLS {
		cert, err := generateSelfSignedCert(host)
		if err != nil {
			_ = ln.Close()
			return nil, nil, err
		}

		tlsCfg := tls.Config{ //nolint
			Certificates: []tls.Certificate{cert},
		}

		ln = tls.NewListener(ln, &tlsCfg)
	}

	srv := &http.Server{ //nolint
		Handler:   handler,
		TLSConfig: tlsCfg,
	}

	serveErr := make(chan error, 1)
	go func() {
		// Serve will return http.ErrServerClosed after Shutdown
		serveErr <- srv.Serve(ln)
	}()

	stop = func() {
		// Give the server a short grace period to finish active requests.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		// Wait for Serve goroutine to exit to avoid goroutine leak.
		<-serveErr
	}

	return stop, ln.Addr(), nil
}
