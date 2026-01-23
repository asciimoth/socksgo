package protocol

import (
	"io"
	"net"

	"github.com/asciimoth/socksgo/internal"
)

func PipeConn(inc, out net.Conn) (err error) {
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(inc, out)
		inc.Close()
		out.Close()
		done <- internal.ClosedNetworkErrToNil(err)
	}()

	_, err = io.Copy(out, inc)
	inc.Close()
	out.Close()

	return internal.JoinNetErrors(err, <-done)
}
