package protocol

// Connection piping utilities.
//
// This file provides helper functions for bidirectional data copying
// between network connections, commonly used in proxy implementations.

import (
	"io"
	"net"

	"github.com/asciimoth/socksgo/internal"
)

// PipeConn copies data bidirectionally between two connections.
//
// This function establishes a full-duplex pipe between two connections,
// copying data from inc->out and out->inc concurrently. It blocks until
// both directions complete or an error occurs.
//
// # Behavior
//
// 1. Spawns a goroutine to copy data from out->inc
// 2. Copies data from inc->out in the main goroutine
// 3. Closes both connections when either direction completes
// 4. Returns the first error encountered (if any)
//
// # Parameters
//
//   - inc: Incoming connection (typically from client)
//   - out: Outgoing connection (typically to target server)
//
// # Returns
//
// Error if any copy operation fails. Closed connection errors are
// converted to nil.
//
// # Thread Safety
//
// This function spawns a goroutine and blocks until completion.
// Both connections are closed when the function returns.
//
// # Examples
//
//	// After establishing connection to target
//	targetConn, _ := net.Dial("tcp", "example.com:80")
//
//	// Pipe client and target connections
//	err := protocol.PipeConn(clientConn, targetConn)
//	if err != nil {
//	    // Handle error (typically connection closed)
//	}
func PipeConn(inc, out net.Conn) (err error) {
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(inc, out)
		_ = inc.Close()
		_ = out.Close()
		done <- internal.ClosedNetworkErrToNil(err)
	}()

	_, err = io.Copy(out, inc)
	_ = inc.Close()
	_ = out.Close()

	return internal.JoinNetErrors(err, <-done)
}
