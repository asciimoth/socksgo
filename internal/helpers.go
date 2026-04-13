package internal

import (
	"context"
	"errors"
	"net"
)

func DialBlock(ctx context.Context, _, _ string) (net.Conn, error) {
	return nil, errors.New("BLOCKED")
}

var ErrTooLongString = errors.New("string is too long")

func FirstNonNil(objs ...any) (obj any) {
	for _, obj = range objs {
		if obj != nil {
			return
		}
	}
	return
}
