package socksgo

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/putback"
	"github.com/asciimoth/socksgo/protocol"
)

// DefaultBindHandler handles the BIND command.
//
// DefaultBindHandler creates a TCP listener on the proxy server
// that forwards incoming connections to the client.
//
// # Protocol Support
//
//   - SOCKS4: Yes
//   - SOCKS4a: Yes
//   - SOCKS5: Yes
//   - TLS: Yes
//
// # Behavior
//
//  1. Applies default listen host if address is unspecified
//  2. Validates local address against LaddrFilter
//  3. Creates TCP listener on requested address
//  4. Sends first reply with bound address (listener.Addr())
//  5. Waits for single incoming connection
//  6. Sends second reply with remote address (incoming client)
//  7. Pipes data bidirectionally
//
// # Two-Reply Protocol
//
// BIND uses a two-reply protocol:
//
//  1. First reply: Contains the address where the client should
//     direct the peer to connect (listener address)
//  2. Second reply: Contains the address of the incoming
//     connection (after Accept returns)
//
// # Use Cases
//
// BIND is used for protocols that require reverse connections:
//   - FTP passive mode
//   - Remote debugging
//   - Any protocol requiring server-to-client connections
//
// # Reply
//
// Sends success reply (0x00) with:
//   - First reply: Listener address
//   - Second reply: Incoming connection's remote address
//
// # Errors
//
// Returns error and sends appropriate reply status:
//   - DisallowReply (0x02): Address filtered
//   - FailReply (0x01): Listen failed
//
// # Examples
//
//	// Default handler is used automatically
//	server := &socksgo.Server{
//	    Handlers: socksgo.DefaultCommandHandlers,
//	}
//
// # See Also
//
//   - RFC 1928: SOCKS5 Protocol (Section 4)
//   - protocol.PipeConn: Connection piping implementation
//   - server_handler_mbind.go: Gost multiplexed BIND
var DefaultBindHandler = CommandHandler{
	Socks4:    true,
	Socks5:    true,
	TLSCompat: true,
	Handler: func(
		ctx context.Context,
		server *Server,
		conn net.Conn,
		ver string,
		info protocol.AuthInfo,
		cmd protocol.Cmd,
		addr protocol.Addr) error {
		pool := server.GetPool()
		addr = addr.WithDefaultHost(server.GetDefaultListenHost())

		if err := server.CheckLaddr(&addr); err != nil {
			protocol.Reject(ver, conn, protocol.DisallowReply, pool)
			return err
		}

		tcp := "tcp"
		if ver == "4" || ver == "4a" {
			tcp = "tcp4"
		}

		listener, err := server.GetListener()(ctx, tcp, addr.ToHostPort())
		if err != nil {
			protocol.Reject(ver, conn, socksBindErrorToReplyStatus(err), pool)
			return err
		}

		closeListener := sync.OnceFunc(func() {
			_ = listener.Close()
		})
		defer closeListener()

		err = protocol.Reply(
			ver,
			conn,
			protocol.SuccReply,
			protocol.AddrFromNetAddr(listener.Addr()),
			pool,
		)
		if err != nil {
			return err
		}

		var stopWatchControl func() []byte
		if _, ok := conn.(*wsCoderConn); ok {
			stopWatch := closeSocksBindOnContextDone(ctx, closeListener)
			stopWatchControl = func() []byte {
				stopWatch()
				return nil
			}
		} else {
			stopWatchControl = watchSocksBindControl(ctx, conn, closeListener)
		}
		proxy, err := listener.Accept()
		putBack := stopWatchControl()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return err
		}

		closeListener()
		defer func() {
			_ = proxy.Close()
		}()

		err = protocol.Reply(
			ver,
			conn,
			protocol.SuccReply,
			protocol.AddrFromNetAddr(proxy.RemoteAddr()),
			pool,
		)
		if err != nil {
			return err
		}
		if len(putBack) > 0 {
			conn = putback.WrapConn(conn, putBack, pool)
		}

		stopWatchPipe := closeSocksBindOnContextDone(ctx, func() {
			_ = conn.Close()
			_ = proxy.Close()
		})
		defer stopWatchPipe()

		err = gonnect.PipeConn(conn, proxy)
		return err
	},
}

func watchSocksBindControl(
	ctx context.Context,
	conn net.Conn,
	closeFn func(),
) func() []byte {
	done := make(chan struct{})
	result := make(chan []byte, 1)
	var once sync.Once

	go func() {
		defer close(result)
		buf := []byte{0}
		for {
			select {
			case <-ctx.Done():
				closeFn()
				return
			case <-done:
				return
			default:
			}

			err := conn.SetReadDeadline(
				time.Now().Add(50 * time.Millisecond),
			)
			if err != nil {
				return
			}
			n, err := conn.Read(buf)
			if n > 0 {
				result <- append([]byte(nil), buf[:n]...)
				return
			}
			if err == nil {
				continue
			}
			if isTimeout(err) {
				continue
			}
			closeFn()
			return
		}
	}()

	return func() []byte {
		once.Do(func() {
			close(done)
			_ = conn.SetReadDeadline(time.Now())
		})
		putBack := <-result
		_ = conn.SetReadDeadline(time.Time{})
		return putBack
	}
}

func closeSocksBindOnContextDone(ctx context.Context, closeFn func()) func() {
	done := make(chan struct{})
	var once sync.Once

	go func() {
		select {
		case <-ctx.Done():
			closeFn()
		case <-done:
		}
	}()

	return func() {
		once.Do(func() {
			close(done)
		})
	}
}

func socksBindErrorToReplyStatus(err error) protocol.ReplyStatus {
	if err == nil {
		return protocol.SuccReply
	}

	var unwrapped = err
	for {
		u := errors.Unwrap(unwrapped)
		if u == nil {
			break
		}
		unwrapped = u
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		unwrapped = opErr.Err
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return protocol.HostUnreachReply
	}

	errStr := strings.ToLower(unwrapped.Error())
	if strings.Contains(errStr, "connection refused") {
		return protocol.ConnRefusedReply
	}
	if strings.Contains(errStr, "network unreachable") {
		return protocol.NetUnreachReply
	}
	if strings.Contains(errStr, "host unreachable") {
		return protocol.HostUnreachReply
	}
	if strings.Contains(errStr, "connection timed out") ||
		strings.Contains(errStr, "i/o timeout") {
		return protocol.TTLExpiredReply
	}
	if strings.Contains(errStr, "permission denied") {
		return protocol.DisallowReply
	}

	return protocol.FailReply
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
