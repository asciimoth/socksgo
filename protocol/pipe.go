package protocol

import (
	"errors"

	"github.com/asciimoth/gonnect"
)

// joinNetErrors joins two errors, treating closed network connection errors as nil.
func JoinNetErrors(a, b error) (err error) {
	a = gonnect.ClosedNetworkErrToNil(a)
	b = gonnect.ClosedNetworkErrToNil(b)
	switch {
	case a != nil && b == nil:
		err = a
	case b != nil && a == nil:
		err = b
	case a != nil && b != nil:
		err = errors.Join(a, b)
	}
	return
}
