package webtest

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
				if got := rawLocationLine(t, srv.Listener.Addr().String()); got != "Location: "+tt.wire+"\r\n" {
					t.Errorf("Location line = %q; want %q", got, "Location: "+tt.wire+"\r\n")
				}
			})
		})
	}
}

func rawLocationLine(t *testing.T, addr string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" || strings.HasPrefix(line, "Location: ") {
			return line
		}
	}
}
