package socks_test

import (
	"math"
	"math/bits"
	"sync"

	"github.com/asciimoth/socks/protocol"
)

var (
	GlobalTestPool                     = &TestPool{}
	_              protocol.BufferPool = &TestPool{}
)

func next(v uint32) uint32 {
	return uint32(bits.Len32(v - 1))
}

func prev(num uint32) uint32 {
	next := next(num)
	if num == (1 << uint32(next)) {
		return next
	}
	return next - 1
}

type TestPool struct {
	pools [32]sync.Pool
}

func (p *TestPool) GetBuffer(length int) []byte {
	if length == 0 {
		return nil
	}
	if length > math.MaxInt32 || length < 0 {
		return make([]byte, length)
	}
	idx := next(uint32(length))
	if ptr := p.pools[idx].Get(); ptr != nil {
		buf := (ptr.([]byte))[:length]
		return buf
	}
	return make([]byte, 1<<idx)[:uint32(length)]
}

func (p *TestPool) PutBuffer(buf []byte) {
	capacity := cap(buf)
	if capacity == 0 || capacity > math.MaxInt32 {
		return
	}
	idx := prev(uint32(capacity))
	p.pools[idx].Put(buf)
}
