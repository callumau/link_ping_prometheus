package prober

import "sync"

// bufPool reduces GC pressure by reusing probe-sized buffers across
// server connections and client reader goroutines.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, PayloadSize)
		return &b
	},
}
