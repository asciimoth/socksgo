package protocol_test

import (
	"net"
	"sync"
	"testing"

	"github.com/asciimoth/socksgo/protocol"
)

func TestPipeHelper(t *testing.T) {
	const DATASTR = "data"

	a, b := net.Pipe()
	c, d := net.Pipe()

	errch := make(chan error, 1)
	go func() {
		errch <- protocol.PipeConn(b, c)
	}()

	var wg sync.WaitGroup

	wg.Go(func() {
		defer func() { _ = a.Close() }()
		data := []byte(DATASTR)
		for {
			if len(data) == 0 {
				return
			}
			n, err := a.Write(data)
			if err != nil {
				return
			}
			data = data[n:]
		}
	})

	wg.Go(func() {
		defer func() { _ = d.Close() }()
		data := []byte{}
		buf := make([]byte, 1024)
		for {
			n, err := d.Read(buf)
			if err != nil {
				break
			}
			data = append(data, buf[:n]...)
		}
		if string(data) != DATASTR {
			t.Fatalf("got %s while expecting %s", data, DATASTR)
		}
	})

	wg.Wait()
	err := <-errch
	if err != nil {
		t.Fatalf("got %v %T error while expected nil", err, err)
	}
}
