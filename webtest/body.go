package webtest

import (
	"io"
	"sync"
	"sync/atomic"
)

// CountingReader counts bytes read through it and is safe for concurrent use.
// In-process the count is exactly what the handler read. Over a connection it
// counts what the client pulled from the source, which may include bytes
// buffered or sent but never read by the handler.
type CountingReader struct {
	mu sync.Mutex
	r  io.Reader
	n  atomic.Int64
}

// NewCountingReader wraps r without reading it.
func NewCountingReader(r io.Reader) *CountingReader {
	return &CountingReader{r: r}
}

// Read reads from the underlying reader and counts even bytes returned with
// an error.
func (c *CountingReader) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// N returns the total bytes read so far.
func (c *CountingReader) N() int64 { return c.n.Load() }

// Filler returns n bytes of 'x' without allocating the whole body. Use
// Streamed when sending it as a request body of unknown length.
func Filler(n int64) io.Reader {
	return io.LimitReader(filler{}, n)
}

type filler struct{}

func (filler) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
