package socksgo

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/asciimoth/gonnect"
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
		err := server.CheckLaddr(&addr)
		if err != nil {
			protocol.Reject(ver, conn, protocol.DisallowReply, pool)
			return err
		}
		tcp := "tcp"
		if ver == "4" || ver == "4a" {
			tcp = "tcp4"
		}
		listener, err := server.GetListener()(ctx, tcp, addr.ToHostPort())
		if err != nil {
			protocol.Reject(ver, conn, errorToReplyStatus(err), pool)
			return err
		}
		closeListener := sync.OnceFunc(func() {
			_ = listener.Close()
		})
		defer closeListener()
		// Send first reply with laddr
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
		stopWatchControl := watchBindControlConn(ctx, conn, closeListener)
		proxy, err := listener.Accept()
		stopWatchControl()
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
		// Send second reply with raddr
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
		stopWatchPipe := closeOnContextDone(ctx, func() {
			_ = conn.Close()
			_ = proxy.Close()
		})
		defer stopWatchPipe()
		return gonnect.PipeConn(conn, proxy)
	},
}

func watchBindControlConn(
	ctx context.Context,
	conn net.Conn,
	closeListener func(),
) func() {
	if _, ok := conn.(*wsCoderConn); ok {
		return closeOnContextDone(ctx, closeListener)
	}

	done := make(chan struct{})
	ready := make(chan struct{})
	var once sync.Once
	rawConn, ok := conn.(syscall.Conn)
	if !ok {
		return watchBindControlConnRead(ctx, conn, closeListener)
	}
	raw, err := rawConn.SyscallConn()
	if err != nil {
		return watchBindControlConnRead(ctx, conn, closeListener)
	}

	stop := func() {
		once.Do(func() {
			close(done)
			<-ready
		})
	}

	go func() {
		defer close(ready)
		var buf [1]byte
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				closeListener()
				return
			case <-done:
				return
			case <-ticker.C:
				closed, err := controlConnClosed(raw, buf[:])
				if err != nil || closed {
					closeListener()
					return
				}
			}
		}
	}()

	return stop
}

func watchBindControlConnRead(
	ctx context.Context,
	conn net.Conn,
	closeListener func(),
) func() {
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return closeOnContextDone(ctx, closeListener)
	}

	done := make(chan struct{})
	ready := make(chan struct{})
	var once sync.Once

	stop := func() {
		once.Do(func() {
			close(done)
			<-ready
			_ = conn.SetReadDeadline(time.Time{})
		})
	}

	go func() {
		defer close(ready)
		var buf [1]byte
		for {
			select {
			case <-ctx.Done():
				closeListener()
				return
			case <-done:
				return
			default:
			}

			if err := conn.SetReadDeadline(
				time.Now().Add(100 * time.Millisecond),
			); err != nil {
				closeListener()
				return
			}

			n, err := conn.Read(buf[:])
			if n > 0 || err == nil {
				closeListener()
				return
			}
			if isTimeoutErr(err) {
				continue
			}
			closeListener()
			return
		}
	}()

	return stop
}

func isTimeoutErr(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func controlConnClosed(raw syscall.RawConn, buf []byte) (bool, error) {
	var (
		n       int
		recvErr error
		rawErr  error
	)
	err := raw.Control(func(fd uintptr) {
		n, _, recvErr = syscall.Recvfrom(int(fd), buf, syscall.MSG_PEEK)
	})
	if err != nil {
		return false, err
	}
	if recvErr == nil {
		return n == 0, nil
	}
	if errors.Is(recvErr, syscall.EAGAIN) ||
		errors.Is(recvErr, syscall.EWOULDBLOCK) {
		return false, nil
	}
	if errors.Is(recvErr, syscall.ECONNRESET) ||
		errors.Is(recvErr, syscall.ENOTCONN) {
		return true, nil
	}
	rawErr = gonnect.ClosedNetworkErrToNil(recvErr)
	return rawErr == nil, rawErr
}
