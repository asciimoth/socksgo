package socksgo

import (
	"context"
	"sync"
)

func closeOnContextDone(ctx context.Context, closeFn func()) func() {
	done := make(chan struct{})
	var once sync.Once

	go func() {
		select {
		case <-ctx.Done():
			closeFn()
		case <-done:
		}
	}()

	return func() {
		once.Do(func() {
			close(done)
		})
	}
}
