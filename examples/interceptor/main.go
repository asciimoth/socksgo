// nolint
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/asciimoth/putback"
	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

var (
	tcpAddr = flag.String("tcp-addr", "127.0.0.1:1080", "TCP listen address")
	crtFile = flag.String("crt", "./ca.crt", "CA file")
	keyFile = flag.String("key", "./ca.key", "CA secret key")
)

func main() {
	flag.Parse()

	listener := &Listener{ch: make(chan net.Conn)}
	defer listener.Close()

	crtFile, err := filepath.Abs(*crtFile)
	if err != nil {
		log.Println(err)
		return
	}
	keyFile, err := filepath.Abs(*keyFile)
	if err != nil {
		log.Println(err)
		return
	}

	// Generate CA with:
	// - openssl genrsa -out ca.key 2048
	// - openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.crt -subj "/CN=MyTestCA/O=MyOrg/C=US"
	ca, err := LoadCA(crtFile, keyFile)
	if err != nil {
		log.Println("failed to load CA:", err)
		return
	}

	server := &socksgo.Server{
		PreCmd:              preCmdLogger,
		Handlers:            buildHandler(listener, ca),
		DanglingConnections: true,
	}

	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wg.Go(func() {
		startHttpServer(listener)
	})

	wg.Go(func() {
		startTCPListener(ctx, server, *tcpAddr)
	})

	// Wait for shutdown signal or error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf(
		"Try with: curl --cacert %s -4 --proxy socks5h://%s https://example.com/\n",
		crtFile,
		*tcpAddr,
	)

	sig := <-sigCh
	log.Printf("received signal %v, shutting down...", sig)

	cancel()
	_ = listener.Close()

	// Wait for all listeners to finish
	wg.Wait()

	log.Println("server stopped")
}

func startHttpServer(l net.Listener) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		resp := "========== Intercepted ==========\n\n"
		resp += fmt.Sprintf("This is definitely not '%s%s'\n", r.Host, r.URL)
		resp += fmt.Sprintf("Proto: %s\n", r.Proto)
		resp += fmt.Sprintf("Agent: %s\n", r.UserAgent())
		resp += "\n========== Intercepted ==========\n"
		fmt.Fprintln(w, resp)
	})

	// Start the HTTP server using the custom listener
	log.Println("starting http server")
	err := http.Serve(l, nil)
	log.Println(err)
	log.Println("stopping http server")
}

func buildHandler(
	l *Listener,
	ca *CertAuthority,
) map[protocol.Cmd]socksgo.CommandHandler {
	handler := socksgo.CommandHandler{
		Socks4:    true,
		Socks5:    true,
		TLSCompat: true,
		Handler: func(
			ctx context.Context,
			server *socksgo.Server,
			conn net.Conn,
			ver string,
			info protocol.AuthInfo,
			cmd protocol.Cmd,
			addr protocol.Addr,
		) error {
			pool := server.GetPool()
			err := server.CheckRaddr(&addr)
			if err != nil {
				protocol.Reject(ver, conn, protocol.DisallowReply, pool)
				return err
			}
			err = protocol.Reply(
				ver,
				conn,
				protocol.SuccReply,
				addr,
				pool,
			)
			var proto string
			conn, proto, err = guessProto(conn)
			if err != nil {
				return err
			}
			log.Printf("incoming %s connection", proto)
			if proto == "http" {
				l.Send(conn)
				return nil
			}
			if proto == "tls" {
				tls, err := ca.Accept(conn, addr)
				if err != nil {
					return err
				}
				l.Send(tls)
				return nil
			}
			return fmt.Errorf("wrong protocol")
		},
	}
	return map[protocol.Cmd]socksgo.CommandHandler{
		protocol.CmdConnect: handler,
	}
}

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
) {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		log.Printf("TCP listener failed: %v", err)
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
			log.Printf("TCP connection from %s", c.RemoteAddr())
			if err := server.Accept(ctx, c, false); err != nil {
				log.Printf(
					"TCP connection from %s closed with error: %v",
					c.RemoteAddr(),
					err,
				)
			}
		}(conn)
	}
}

type CertAuthority struct {
	cert   tls.Certificate
	caCert *x509.Certificate
}

func (ca *CertAuthority) Accept(
	conn net.Conn,
	addr protocol.Addr,
) (*tls.Conn, error) {
	host := addr.ToFQDN()
	cert, err := ca.gen(host)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}

	tlsConn := tls.Server(conn, tlsConfig)
	return tlsConn, tlsConn.Handshake()
}

func (ca *CertAuthority) gen(host string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	certBytes, _ := x509.CreateCertificate(
		rand.Reader,
		&template,
		ca.caCert,
		&priv.PublicKey,
		ca.cert.PrivateKey,
	)
	return &tls.Certificate{
		Certificate: [][]byte{certBytes, ca.caCert.Raw},
		PrivateKey:  priv,
	}, nil
}

func LoadCA(crtFile string, keyFile string) (*CertAuthority, error) {
	certPEM, err := os.ReadFile(crtFile) // ca.crt
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile) // ca.key
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return &CertAuthority{
		cert:   cert,
		caCert: caCert,
	}, nil
}

type Listener struct {
	ch   chan net.Conn
	addr net.Addr
}

func (l *Listener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if ok {
		return c, nil
	}
	return nil, fmt.Errorf("mock listener closed")
}

func (l *Listener) Close() error {
	// Bad practice; Suitable only for example code
	defer func() {
		_ = recover()
	}()
	close(l.ch)
	return nil
}

func (l *Listener) Addr() net.Addr {
	return l.addr
}

func (l *Listener) Send(c net.Conn) (closed bool) {
	// Bad practice; Suitable only for example code
	defer func() {
		err := recover()
		if err != nil {
			log.Println(err)
			closed = true
		}
	}()
	l.ch <- c
	return
}

func guessProto(conn net.Conn) (net.Conn, string, error) {
	var header [3]byte
	_, err := io.ReadFull(conn, header[:])
	if err != nil {
		_ = conn.Close()
		return conn, "", err
	}

	wrapped := putback.WrapConn(conn, header[:], nil)
	typ := "unknown"

	lower := strings.ToLower(string(header[:]))

	if slices.Contains([]string{
		"get", "head", "post", "put", "delete",
		"connect", "options", "trace", "patch",
		"pri", "http",
	}, lower) {
		typ = "http"
	} else if header[0] == 0x16 {
		typ = "tls"
	}

	return wrapped, typ, nil
}
