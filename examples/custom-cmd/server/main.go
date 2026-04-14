// nolint
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/asciimoth/socksgo"
	"github.com/asciimoth/socksgo/protocol"
)

const (
	CmdHelloWorld protocol.Cmd = 0xF4
)

var (
	addr = flag.String("addr", "127.0.0.1:1080", "Server listen address")
)

func main() {
	flag.Parse()

	log.Printf("HelloWorld SOCKS server starting on %s", *addr)

	server := &socksgo.Server{
		PreCmd: func(
			ctx context.Context,
			conn net.Conn,
			ver string,
			info protocol.AuthInfo,
			cmd protocol.Cmd,
			addr protocol.Addr,
		) (protocol.ReplyStatus, error) {
			log.Printf("[%s] %s %s %s", conn.RemoteAddr(), ver, cmd, addr)
			return 0, nil
		},
		Handlers: customCommandHandlers(),
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	log.Printf("Listening on %s", *addr)
	log.Printf("Custom command 0xF4 (HelloWorld) registered")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			log.Printf("Connection from %s", c.RemoteAddr())
			if err := server.Accept(
				context.Background(),
				c,
				false,
			); err != nil {
				log.Printf(
					"Connection from %s closed with error: %v",
					c.RemoteAddr(),
					err,
				)
			} else {
				log.Printf("Connection from %s closed normally", c.RemoteAddr())
			}
		}(conn)
	}
}

func customCommandHandlers() map[protocol.Cmd]socksgo.CommandHandler {
	handlers := make(map[protocol.Cmd]socksgo.CommandHandler)

	for k, v := range socksgo.DefaultCommandHandlers {
		handlers[k] = v
	}

	handlers[CmdHelloWorld] = socksgo.CommandHandler{
		Socks4:    false,
		Socks5:    true,
		TLSCompat: true,
		Handler:   helloWorldHandler,
	}

	return handlers
}

func helloWorldHandler(
	ctx context.Context,
	server *socksgo.Server,
	conn net.Conn,
	ver string,
	info protocol.AuthInfo,
	cmd protocol.Cmd,
	addr protocol.Addr,
) error {
	pool := server.GetPool()

	response := "Hello, World!"
	if len(addr.Host) > 0 {
		response += fmt.Sprintf(" You sent: %s", string(addr.Host))
	}

	replyAddr := protocol.AddrFromFQDN("hello", 0, "")
	err := protocol.Reply(ver, conn, protocol.SuccReply, replyAddr, pool)
	if err != nil {
		return fmt.Errorf("failed to send reply: %w", err)
	}

	log.Printf("HelloWorld: responding to %s", conn.RemoteAddr())

	_, err = io.WriteString(conn, response+"\n")
	if err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	time.Sleep(100 * time.Millisecond)

	return nil
}
