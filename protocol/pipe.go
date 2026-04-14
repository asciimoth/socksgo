package protocol

import (
	"errors"

	"github.com/asciimoth/gonnect/helpers"
)

// joinNetErrors joins two errors, treating closed network connection errors as nil.
func JoinNetErrors(a, b error) (err error) {
	a = helpers.ClosedNetworkErrToNil(a)
	b = helpers.ClosedNetworkErrToNil(b)
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
