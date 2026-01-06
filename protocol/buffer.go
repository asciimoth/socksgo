package protocol

type BufferPool interface {
	// GetBuffer retrieves a buffer of exact provided length and arbitrary capacity
	// from the buffer pool or allocates a new one.
	GetBuffer(length int) []byte
	// PutBuffer returns a buffer to the pool or just drop it.
	PutBuffer(buf []byte)
}
