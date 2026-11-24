package webtest

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
)

func TestCountingReaderConcurrentReads(t *testing.T) {
	// Each read except the last returns one byte. The last returns a byte
	// with EOF, which still counts.
	body := NewCountingReader(iotest.OneByteReader(iotest.DataErrReader(strings.NewReader("abc"))))
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			var p [1]byte
			if n, err := body.Read(p[:]); n != 1 || (err != nil && err != io.EOF) {
				t.Errorf("Read = %d, %v; want one byte", n, err)
			}
			if n := body.N(); n < 1 || n > 3 {
				t.Errorf("intermediate count = %d; want 1 to 3", n)
			}
		})
	}
	wg.Wait()
	if n := body.N(); n != 3 {
		t.Errorf("count = %d; want 3", n)
	}
}

func TestCountingReaderInProcessLimit(t *testing.T) {
	for _, want := range []int64{0, 17} {
		body := NewCountingReader(Filler(128))
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if want > 0 {
				if _, err := io.CopyN(io.Discard, r.Body, want); err != nil {
					t.Error(err)
				}
			}
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		})
		c := New(t, h, testOrigin)
		c.Do(c.NewRequest(http.MethodPost, "/", body), Streamed()).WantStatus(http.StatusRequestEntityTooLarge)
		if got := body.N(); got != want {
			t.Errorf("count = %d; want %d", got, want)
		}
	}
}

func TestFillerStreamed(t *testing.T) {
	const size = 32<<10 + 1
	for _, mode := range []string{"in-process", "server"} {
		t.Run(mode, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ContentLength != -1 {
					t.Errorf("ContentLength = %d; want -1", r.ContentLength)
				}
				p, err := io.ReadAll(r.Body)
				if err != nil || string(p) != strings.Repeat("x", size) {
					t.Errorf("read %d filler bytes, error %v; want %d 'x' bytes", len(p), err, size)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			c := testClient(t, h, mode)
			body := NewCountingReader(Filler(size))
			c.Do(c.NewRequest(http.MethodPost, "/", body), Streamed()).WantStatus(http.StatusNoContent)
			if n := body.N(); n != size {
				t.Errorf("count = %d; want %d", n, size)
			}
		})
	}
	if p, err := io.ReadAll(Filler(0)); err != nil || len(p) != 0 {
		t.Errorf("empty filler = %q, %v", p, err)
	}
}
