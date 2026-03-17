// nolint
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

var (
	serverAddr = flag.String("addr", "127.0.0.1:1080", "SOCKS server listen address")
	targetURL  = flag.String("target", "http://example.com", "Target URL to fetch")
	rounds     = flag.Int("rounds", 2, "Number of GSS token exchange rounds")
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		runServer(ctx, *serverAddr)
	}()

	time.Sleep(500 * time.Millisecond)

	wg.Add(1)
	go func() {
		defer wg.Done()
		runClient(ctx, *serverAddr, *targetURL)
	}()

	wg.Wait()
}

func runServer(ctx context.Context, addr string) {
	log.Printf("Starting SOCKS5 server with GSS auth on %s", addr)

	mockGSS := &MockGSSServer{
		Rounds:    *rounds,
		Principal: "client@mockrealm",
	}

	authHandlers := (&protocol.AuthHandlers{}).Add(&protocol.GSSAuthHandler{
		Server: mockGSS,
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

func handleConnection(ctx context.Context, server *socksgo.Server, conn net.Conn) {
	defer conn.Close()

	log.Printf("New connection from %s", conn.RemoteAddr())

	if err := server.Accept(ctx, conn, false); err != nil {
		log.Printf("Connection from %s closed with error: %v", conn.RemoteAddr(), err)
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
		authInfo = fmt.Sprintf("principal=%s", info.Name)
	}

	log.Printf("[%s] %s %s %s -> %s",
		clientAddr, ver, authInfo, cmd.String(), addr.String())

	return 0, nil
}

func runClient(ctx context.Context, proxyAddr, targetURL string) {
	log.Printf("Connecting via SOCKS5 with GSS auth to %s", proxyAddr)

	mockGSS := &MockGSSClient{Rounds: *rounds}

	authMethods := (&protocol.AuthMethods{}).Add(&protocol.GSSAuthMethod{
		Client:     mockGSS,
		TargetName: "socks/server@mockrealm",
	})

	client := &socksgo.Client{
		SocksVersion: "5",
		ProxyAddr:    proxyAddr,
		Auth:         authMethods,
	}

	targetHost, targetPort, err := parseTargetURL(targetURL)
	if err != nil {
		log.Fatalf("Failed to parse target URL: %v", err)
	}

	addr := net.JoinHostPort(targetHost, targetPort)
	log.Printf("Connecting to %s via GSS-authenticated SOCKS proxy", addr)

	conn, err := client.Dial(ctx, "tcp", addr)
	if err != nil {
		log.Fatalf("Failed to connect through proxy: %v", err)
	}
	defer conn.Close()

	log.Printf("GSS authentication successful, sending HTTP request...")

	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetURL, targetHost)
	if _, err := conn.Write([]byte(request)); err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}

	response, err := io.ReadAll(conn)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	fmt.Println(string(response))
	log.Printf("Request completed successfully")
}

func parseTargetURL(url string) (host, port string, err error) {
	if url == "" {
		return "", "", fmt.Errorf("empty URL")
	}

	schemePrefix := "http://"
	if len(url) > 8 && url[:7] == "https://" {
		schemePrefix = "https://"
		port = "443"
	} else {
		port = "80"
	}

	hostPart := url[len(schemePrefix):]
	if hostPart == "" {
		return "", "", fmt.Errorf("invalid URL: missing host")
	}

	if idx := strings.Index(hostPart, "/"); idx != -1 {
		hostPart = hostPart[:idx]
	}

	if h, p, err := net.SplitHostPort(hostPart); err == nil {
		return h, p, nil
	}

	return hostPart, port, nil
}

type MockGSSClient struct {
	Rounds int
	step   int
}

func (m *MockGSSClient) InitSecContext(
	targetName string,
	token []byte,
) ([]byte, bool, error) {
	if len(token) > 0 {
		log.Println("client token receive:", string(token))
	}
	if m.Rounds <= 0 {
		return nil, false, nil
	}
	if token == nil {
		m.step = 1
		out := fmt.Appendf(nil, "c:%d", m.step)
		need := m.step < m.Rounds
		return out, need, nil
	}
	m.step++
	if m.step > m.Rounds {
		return nil, false, nil
	}
	out := fmt.Appendf(nil, "c:%d", m.step)
	need := m.step < m.Rounds
	return out, need, nil
}

func (m *MockGSSClient) DeleteSecContext() error {
	m.step = 0
	return nil
}

type MockGSSServer struct {
	Rounds    int
	Principal string
	step      int
}

func (m *MockGSSServer) AcceptSecContext(
	token []byte,
) ([]byte, string, bool, error) {
	if len(token) > 0 {
		log.Println("server token receive:", string(token))
	}
	m.step++
	if m.step > m.Rounds {
		return nil, "", false, fmt.Errorf("unexpected extra token")
	}
	out := fmt.Appendf(nil, "s:%d", m.step)
	need := m.step < m.Rounds
	src := ""
	if !need {
		src = m.Principal
	}
	return out, src, need, nil
}

func (m *MockGSSServer) DeleteSecContext() error {
	m.step = 0
	return nil
}
