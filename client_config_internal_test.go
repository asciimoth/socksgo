//go:build compattest

package socksgo

import (
	"reflect"
	"testing"

	"github.com/asciimoth/bufpool"
)

// Test wsBufferPoolAdapter.Get with nil pool
func TestWsBufferPoolAdapter_Get_NilPool(t *testing.T) {
	t.Parallel()

	adapter := &wsBufferPoolAdapter{pool: nil}
	result := adapter.Get()
	if result != nil {
		t.Fatalf("Get() with nil pool expected nil, got %v", result)
	}
}

// Test wsBufferPoolAdapter.Get with non-nil pool
func TestWsBufferPoolAdapter_Get_NonNilPool(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	adapter := &wsBufferPoolAdapter{pool: pool}
	result := adapter.Get()
	if result == nil {
		t.Fatalf("Get() with non-nil pool expected non-nil buffer")
	}
	buf, ok := result.([]byte)
	if !ok {
		t.Fatalf("Get() expected []byte, got %T", result)
	}
	if len(buf) != 0 {
		t.Fatalf("Get() expected buffer with len 0, got %d", len(buf))
	}
	// Clean up
	bufpool.PutBuffer(pool, buf)
}

// Test wsBufferPoolAdapter.Put with nil pool
func TestWsBufferPoolAdapter_Put_NilPool(t *testing.T) {
	t.Parallel()

	adapter := &wsBufferPoolAdapter{pool: nil}
	// Should not panic
	adapter.Put([]byte("test"))
}

// Test wsBufferPoolAdapter.Put with non-[]byte type
func TestWsBufferPoolAdapter_Put_NonByteSlice(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	adapter := &wsBufferPoolAdapter{pool: pool}

	// Call Put with non-[]byte type - should not panic, should return early
	adapter.Put("not a byte slice")
	adapter.Put(123)
	adapter.Put(nil)
	adapter.Put([]string{"test"})
}

// Test wsBufferPoolAdapter.Put with []byte type
func TestWsBufferPoolAdapter_Put_ByteSlice(t *testing.T) {
	t.Parallel()

	pool := bufpool.NewTestDebugPool(t)
	pool.OnLog = nil // Too verbose
	defer pool.Close()

	adapter := &wsBufferPoolAdapter{pool: pool}

	// Call Put with []byte type - should work normally
	buf := bufpool.GetBuffer(pool, 100)
	adapter.Put(buf)
}

// Test WebSocketConfig methods with non-nil receiver
func TestWebSocketConfigMethods_NonNilReceiver(t *testing.T) {
	t.Parallel()

	cfg := &WebSocketConfig{
		Subprotocols:      []string{"a", "b"},
		EnableCompression: true,
	}

	if got := cfg.subprotocols(); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("subprotocols() expected [a, b], got %v", got)
	}

	if got := cfg.enableCompression(); !got {
		t.Fatalf("enableCompression() expected true")
	}
}
