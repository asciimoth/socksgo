package internal_test

import (
	"context"
	"testing"

	"github.com/asciimoth/socksgo/internal"
)

func TestDialBlock(t *testing.T) {
	_, err := internal.DialBlock(context.Background(), "a", "b")
	if err.Error() != "BLOCKED" {
		t.Fatalf("got %s while BLOCKED expected", err)
	}
}

func TestFirstNonNil(t *testing.T) {
	a := internal.FirstNonNil(nil, nil, nil)
	b := internal.FirstNonNil()
	numA := 1
	numB := 2
	c := internal.FirstNonNil(nil, &numA, &numB)
	if a != nil {
		t.Error(a)
	}
	if b != nil {
		t.Error(b)
	}
	if c == nil {
		t.Error("c must be 1")
	} else if *(c.(*int)) != 1 { //nolint
		t.Error("c must be 1")
	}
}
