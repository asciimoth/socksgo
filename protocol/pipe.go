package protocol

import (
	"io"
	"net"

	"github.com/asciimoth/socksgo/internal"
)

// Pipe copy data between two connections.
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
