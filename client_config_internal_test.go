//go:build compattest

package socksgo

import (
	"reflect"
	"testing"

	"github.com/asciimoth/bufpool"
	"github.com/gorilla/websocket"
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

// Test WebSocketConfig methods with nil receiver
func TestWebSocketConfigMethods_NilReceiver(t *testing.T) {
	t.Parallel()

	var cfg *WebSocketConfig

	// jar() with nil receiver should return websocket.DefaultDialer.Jar
	if got := cfg.jar(); got != websocket.DefaultDialer.Jar {
		t.Fatalf("jar() with nil receiver expected DefaultDialer.Jar")
	}

	// readBufferSize() with nil receiver should return DefaultDialer.ReadBufferSize
	if got := cfg.readBufferSize(); got != websocket.DefaultDialer.ReadBufferSize {
		t.Fatalf(
			"readBufferSize() with nil receiver expected DefaultDialer.ReadBufferSize, got %d",
			got,
		)
	}

	// subprotocols() with nil receiver should return DefaultDialer.Subprotocols
	if got := cfg.subprotocols(); !reflect.DeepEqual(
		got,
		websocket.DefaultDialer.Subprotocols,
	) {
		t.Fatalf(
			"subprotocols() with nil receiver expected DefaultDialer.Subprotocols, got %v",
			got,
		)
	}

	// enableCompression() with nil receiver should return DefaultDialer.EnableCompression
	if got := cfg.enableCompression(); got != websocket.DefaultDialer.EnableCompression {
		t.Fatalf(
			"enableCompression() with nil receiver expected DefaultDialer.EnableCompression",
		)
	}
}

// Test WebSocketConfig methods with non-nil receiver
func TestWebSocketConfigMethods_NonNilReceiver(t *testing.T) {
	t.Parallel()

	cfg := &WebSocketConfig{
		ReadBufferSize:    12345,
		Subprotocols:      []string{"a", "b"},
		EnableCompression: true,
	}

	if got := cfg.readBufferSize(); got != 12345 {
		t.Fatalf("readBufferSize() expected 12345, got %d", got)
	}

	if got := cfg.subprotocols(); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("subprotocols() expected [a, b], got %v", got)
	}

	if got := cfg.enableCompression(); !got {
		t.Fatalf("enableCompression() expected true")
	}
}
