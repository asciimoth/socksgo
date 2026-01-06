package internal

// Same for protocol.BufferPool for preventing circular deps.
type BufferPool interface {
	GetBuffer(length int) []byte
	PutBuffer(buf []byte)
}

func GetBuffer(pool BufferPool, size int) []byte {
	if pool == nil {
		return make([]byte, size)
	}
	return pool.GetBuffer(size)
}

func PutBuffer(pool BufferPool, buf []byte) {
	if pool == nil {
		return
	}
	pool.PutBuffer(buf)
}
