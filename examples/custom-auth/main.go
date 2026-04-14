// nolint
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/asciimoth/bufpool"
	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

var (
	serverAddr = flag.String(
		"addr",
		"127.0.0.1:1080",
		"SOCKS server listen address",
	)
	targetURL = flag.String(
		"target",
		"http://example.com",
		"Target URL to fetch",
	)
	authToken = flag.String(
		"token",
		"secret-token",
		"Shared authentication token",
	)
)

const (
	customAuthMethodCode = 0x80
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	wg.Go(func() {
		runServer(ctx, *serverAddr, *authToken)
	})

	time.Sleep(500 * time.Millisecond)

	wg.Go(func() {
		runClient(*serverAddr, *targetURL, *authToken)
	})

	wg.Wait()
}

func runServer(ctx context.Context, addr, token string) {
	log.Printf("Starting SOCKS5 server with custom auth on %s", addr)

	authHandlers := (&protocol.AuthHandlers{}).Add(&CustomAuthHandler{
		ExpectedToken: hashToken(token),
	})

	server := &socksgo.Server{
		Auth:     authHandlers,
		Handlers: socksgo.DefaultCommandHandlers,
		PreCmd:   preCmdLogger,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Server failed to listen: %v", err)
	}
	defer listener.Close()

	log.Printf("Server listening on %s", addr)

	for {
		select {
		case <-ctx.Done():
			log.Println("Server shutting down...")
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("Accept error: %v", err)
				continue
			}
			go handleConnection(ctx, server, conn)
		}
	}
}

func handleConnection(
	ctx context.Context,
	server *socksgo.Server,
	conn net.Conn,
) {
	defer conn.Close()

	log.Printf("New connection from %s", conn.RemoteAddr())

	if err := server.Accept(ctx, conn, false); err != nil {
		log.Printf(
			"Connection from %s closed with error: %v",
			conn.RemoteAddr(),
			err,
		)
	} else {
		log.Printf("Connection from %s closed normally", conn.RemoteAddr())
	}
}

func preCmdLogger(
	_ context.Context,
	conn net.Conn,
	ver string,
	info protocol.AuthInfo,
	cmd protocol.Cmd,
	addr protocol.Addr,
) (protocol.ReplyStatus, error) {
	clientAddr := conn.RemoteAddr().String()
	authInfo := fmt.Sprintf("auth-code=%d", info.Code)
	if info.Name != "" {
		authInfo = fmt.Sprintf("method=%s", info.Name)
	}

	log.Printf("[%s] %s %s %s -> %s",
		clientAddr, ver, authInfo, cmd.String(), addr.String())

	return 0, nil
}

func runClient(proxyAddr, targetURL, token string) {
	log.Printf("Connecting via SOCKS5 with custom auth to %s", proxyAddr)

	authMethods := (&protocol.AuthMethods{}).Add(&CustomAuthMethod{
		Token: hashToken(token),
	})

	client := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    proxyAddr,
		Auth:         authMethods,
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				return client.Dial(dialCtx, network, addr)
			},
		},
	}

	resp, err := httpClient.Get(targetURL)

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

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

type CustomAuthMethod struct {
	Token string
}

func (m *CustomAuthMethod) Name() string {
	return "custom-token-auth"
}

func (m *CustomAuthMethod) Code() protocol.AuthMethodCode {
	return customAuthMethodCode
}

func (m *CustomAuthMethod) RunAuth(
	conn net.Conn,
	pool bufpool.Pool,
) (net.Conn, protocol.AuthInfo, error) {
	info := protocol.AuthInfo{
		Code: m.Code(),
		Name: m.Name(),
		Info: map[string]any{"token": m.Token},
	}

	buf := make([]byte, 1+len(m.Token))
	buf[0] = byte(len(m.Token))
	copy(buf[1:], m.Token)

	if _, err := io.Copy(conn, bytes.NewReader(buf)); err != nil {
		return conn, info, err
	}

	resp := make([]byte, 1)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return conn, info, err
	}

	if resp[0] != 0 {
		return conn, info, fmt.Errorf("authentication failed")
	}

	return conn, info, nil
}

type CustomAuthHandler struct {
	ExpectedToken string
}

func (h *CustomAuthHandler) Name() string {
	return "custom-token-auth"
}

func (h *CustomAuthHandler) Code() protocol.AuthMethodCode {
	return customAuthMethodCode
}

func (h *CustomAuthHandler) HandleAuth(
	conn net.Conn,
	pool bufpool.Pool,
) (net.Conn, protocol.AuthInfo, error) {
	info := protocol.AuthInfo{
		Code: h.Code(),
		Name: h.Name(),
	}

	header := make([]byte, 1)
	if _, err := io.ReadFull(conn, header); err != nil {
		return conn, info, err
	}

	tokenLen := int(header[0])
	buf := make([]byte, tokenLen)

	if _, err := io.ReadFull(conn, buf); err != nil {
		return conn, info, err
	}

	clientToken := string(buf)
	resp := []byte{0}
	if clientToken != h.ExpectedToken {
		resp[0] = 1
	}

	if _, err := io.Copy(conn, bytes.NewReader(resp)); err != nil {
		return conn, info, err
	}

	if resp[0] != 0 {
		return conn, info, fmt.Errorf("invalid token")
	}

	info.Info = map[string]any{"token": clientToken}
	return conn, info, nil
}
