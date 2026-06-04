package socksgo

import (
	"errors"
	"net"
	"testing"
)

func TestIsTimeoutRecognizesNetOpErrorIOTimeout(t *testing.T) {
	t.Parallel()

	err := &net.OpError{
		Op:  "read",
		Net: "tcp4",
		Err: errors.New("i/o timeout"),
	}

	if !isTimeout(err) {
		t.Fatal("expected net.OpError i/o timeout to be recognized")
	}
}
