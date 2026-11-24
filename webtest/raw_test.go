package webtest

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestRawWritesWholeRequest(t *testing.T) {
	const size = 1 << 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil || n != size {
			t.Errorf("read %d bytes, error %v; want %d bytes", n, err, size)
		}
		w.Header().Set("Location", "/done")
		w.Header().Set("Content-Length", "7")
		w.WriteHeader(http.StatusSeeOther)
		io.WriteString(w, "receipt")
	}))
	t.Cleanup(srv.Close)
	head := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\nContent-Length: %d\r\n\r\n", size)
	req := io.MultiReader(strings.NewReader(head), Filler(size))
	r := Raw(t, srv.Listener.Addr().String(), req)
	if r.Status != http.StatusSeeOther || r.StatusLine != "HTTP/1.1 303 See Other" ||
		!slices.Equal(r.Values("Location"), []string{"/done"}) || string(r.Body) != "receipt" {
		t.Errorf("raw response = %q, %d, %q, %q; want 303 to /done with a receipt",
			r.StatusLine, r.Status, r.Values("Location"), r.Body)
	}
}

func TestRawChunkedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusEarlyHints)
		io.WriteString(w, "first")
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
		}
		io.WriteString(w, "second")
	}))
	t.Cleanup(srv.Close)
	r := Raw(t, srv.Listener.Addr().String(), rawGet())
	if r.Status != http.StatusOK || string(r.Body) != "firstsecond" ||
		!slices.Equal(r.Values("Transfer-Encoding"), []string{"chunked"}) {
		t.Errorf("status = %d, body = %q, headers = %q; want a decoded chunked 200 response", r.Status, r.Body, r.Headers)
	}
}

func TestRawHeaderOrderAndEOF(t *testing.T) {
	srv := rawFixture(t, "HTTP/1.0 303 See Other\nLocation: /\x00x:part \nloCAtion:\t/next\nodd line\n\nbody")
	r := Raw(t, srv.Listener.Addr().String(), rawGet())
	want := [][2]string{{"Location", " /\x00x:part "}, {"loCAtion", "\t/next"}, {"odd line", ""}}
	if !slices.Equal(r.Headers, want) || !slices.Equal(r.Values("Location"), []string{"/\x00x:part ", "/next"}) ||
		r.Values("Missing") != nil || string(r.Body) != "body" {
		t.Errorf("headers = %q, Location = %q, body = %q; want ordered headers %q and an EOF-delimited body",
			r.Headers, r.Values("Location"), r.Body, want)
	}
}

func TestRawFailures(t *testing.T) {
	for _, tt := range []struct{ name, wire, wantMsg string }{
		{"invalid status", "HTTP/1.1 nope\r\n\r\n", "invalid status"},
		{"truncated body", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\na", "got 1 body bytes, Content-Length promised 4"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := rawFixture(t, tt.wire)
			checkFailure(t, func(t testing.TB) {
				Raw(t, srv.Listener.Addr().String(), rawGet())
			}, true, tt.wantMsg)
		})
	}
}

func rawGet() io.Reader {
	return strings.NewReader("GET / HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n")
}

func rawFixture(t *testing.T, wire string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if _, err := buf.WriteString(wire); err != nil {
			t.Error(err)
			return
		}
		if err := buf.Flush(); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}
