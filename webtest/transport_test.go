package webtest

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestLocationByTransport(t *testing.T) {
	for _, tt := range []struct {
		name      string
		emitted   string
		wire      string
		clientErr string
		wireErr   string
	}{
		{"tab", "/\t/item", "/\t/item", "failed to parse Location", ""},
		{"control", "/\x01item", "/\x01item", "malformed MIME header line", "malformed MIME header line"},
		{"del", "/\x7f", "/\x7f", "malformed MIME header line", "malformed MIME header line"},
		{"nul", "/\x00x", "/\x00x", "malformed MIME header line", "malformed MIME header line"},
		{"crlf", "/\r\nX-Note: 1", "/  X-Note: 1", "", ""},
		{"space", "/a b", "/a b", "", ""},
		{"utf8", "/café", "/café", "", ""},
		{"backslash", `/\item`, `/\item`, "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", tt.emitted)
				w.WriteHeader(http.StatusSeeOther)
			})
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)
			t.Run("http client", func(t *testing.T) {
				calls := 0
				client := http.Client{
					Transport: srv.Client().Transport,
					CheckRedirect: func(*http.Request, []*http.Request) error {
						calls++
						return http.ErrUseLastResponse
					},
				}
				r, err := client.Get(srv.URL)
				if r != nil {
					defer r.Body.Close()
				}
				if tt.clientErr != "" {
					if err == nil || !strings.Contains(err.Error(), tt.clientErr) || calls != 0 {
						t.Fatalf("error = %v, CheckRedirect called %d times; want %q and no calls", err, calls, tt.clientErr)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if got := r.Header.Get("Location"); got != tt.wire || calls != 1 {
					t.Errorf("Location = %q, CheckRedirect called %d times; want %q and one call", got, calls, tt.wire)
				}
			})
			t.Run("round trip", func(t *testing.T) {
				checkFailure(t, func(t testing.TB) {
					r := NewServer(t, srv).Get("/")
					r.WantRedirect(http.StatusSeeOther, tt.wire)
					if got := r.Header.Get("Location"); got != tt.wire {
						t.Errorf("raw header = %q; want %q", got, tt.wire)
					}
				}, tt.wireErr != "", tt.wireErr)
			})
			t.Run("in-process", func(t *testing.T) {
				r := New(t, h, testOrigin).Get("/")
				r.WantRedirect(http.StatusSeeOther, tt.emitted)
				if got := r.Header.Get("Location"); got != tt.emitted {
					t.Errorf("raw header = %q; want %q", got, tt.emitted)
				}
			})
			t.Run("raw connection", func(t *testing.T) {
				// Verify which bytes reached the wire, independently of Go's header reader.
				r := Raw(t, srv.Listener.Addr().String(), rawGet())
				if got := r.Values("location"); !slices.Equal(got, []string{tt.wire}) {
					t.Errorf("Location values = %q; want [%q]", got, tt.wire)
				}
			})
		})
	}
}
