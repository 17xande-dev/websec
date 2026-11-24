package webtest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

const testOrigin = "https://app.example"

func TestRedirectNotFollowed(t *testing.T) {
	for _, mode := range []string{"in-process", "server", "TLS server"} {
		t.Run(mode, func(t *testing.T) {
			var followed atomic.Bool
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/start" {
					followed.Store(true)
					w.WriteHeader(http.StatusTeapot)
					return
				}
				w.Header().Set("Location", "/end")
				w.WriteHeader(http.StatusSeeOther)
				io.WriteString(w, "redirect body")
			})
			r := testClient(t, h, mode).Get("/start")
			r.WantRedirect(http.StatusSeeOther, "/end")
			if r.Body != "redirect body" {
				t.Errorf("body = %q; want the original redirect body", r.Body)
			}
			if followed.Load() {
				t.Error("redirect target was requested")
			}
		})
	}
}

func TestRequestOptions(t *testing.T) {
	for _, tt := range []struct {
		name, method string
		defaults     []Option
		opts         []Option
		want         [4]string
	}{
		{name: "get", method: http.MethodGet},
		{name: "head", method: http.MethodHead},
		{name: "options", method: http.MethodOptions},
		{name: "trace", method: http.MethodTrace},
		{name: "post", method: http.MethodPost, want: [4]string{testOrigin}},
		{name: "put", method: http.MethodPut, want: [4]string{testOrigin}},
		{name: "patch", method: http.MethodPatch, want: [4]string{testOrigin}},
		{name: "delete", method: http.MethodDelete, want: [4]string{testOrigin}},
		{name: "extension method", method: "UPDATE", want: [4]string{testOrigin}},
		{
			name: "constructor defaults", method: http.MethodPost,
			defaults: []Option{WithOrigin(testOrigin + ":8443"), SecFetchSite("cross-site"), Header("X-Note", "default")},
			want:     [4]string{testOrigin + ":8443", "cross-site", "", "default"},
		},
		{
			name: "per-request options win", method: http.MethodPost,
			defaults: []Option{NoOrigin(), SecFetchSite("same-origin"), Header("X-Note", "default")},
			opts:     []Option{WithOrigin(testOrigin + ":8443"), SecFetchSite("cross-site"), HTMX(), Header("X-Note", "request")},
			want:     [4]string{testOrigin + ":8443", "cross-site", "true", "request"},
		},
		{
			name: "remove origin", method: http.MethodPost,
			defaults: []Option{WithOrigin(testOrigin)}, opts: []Option{NoOrigin()},
		},
		{
			name: "explicit origin on safe method", method: http.MethodGet,
			opts: []Option{WithOrigin(testOrigin)}, want: [4]string{testOrigin},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for i, name := range []string{"Origin", "Sec-Fetch-Site", "HX-Request", "X-Note"} {
					if got := r.Header.Values(name); (tt.want[i] == "" && len(got) != 0) ||
						(tt.want[i] != "" && !slices.Equal(got, []string{tt.want[i]})) {
						t.Errorf("%s: %s = %q; want %q", r.Method, name, got, tt.want[i])
					}
				}
				if got := r.Header.Values("Referer"); len(got) != 0 {
					t.Errorf("Referer = %q; want absent", got)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			c := New(t, h, testOrigin, tt.defaults...)
			c.Do(c.NewRequest(tt.method, "/", nil), tt.opts...).WantStatus(http.StatusNoContent)
		})
	}
}

func TestWrongOriginRefused(t *testing.T) {
	// The stdlib checker has the same same-origin shortcut. Using it keeps
	// this test independent of the middleware consumers may use webtest to test.
	guard := http.NewCrossOriginProtection().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	c := New(t, guard, testOrigin, WithOrigin(testOrigin+":8443"))
	t.Run("wrong origin", func(t *testing.T) {
		r := c.PostForm("/", nil)
		if r.Status != http.StatusForbidden {
			t.Errorf("wrong origin got status %d; want 403", r.Status)
		}
	})
	t.Run("matching origin", func(t *testing.T) {
		c.PostForm("/", nil, WithOrigin(testOrigin)).WantStatus(http.StatusNoContent)
	})
	t.Run("explicit fetch metadata takes precedence", func(t *testing.T) {
		c.PostForm("/", nil, SecFetchSite("same-origin")).WantStatus(http.StatusNoContent)
	})
}

func TestServerOrigin(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("Origin"))
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	if got := NewServer(t, srv).PostForm("/", nil).Body; got != srv.URL {
		t.Errorf("default Origin = %q; want %q", got, srv.URL)
	}
	if got := NewServer(t, srv, WithOrigin(testOrigin)).PostForm("/", nil).Body; got != testOrigin {
		t.Errorf("configured Origin = %q; want %q", got, testOrigin)
	}
}

func TestInProcessRequestShape(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI != "/items/a%2Fb?q=a%20b" || r.URL.Path != "/items/a/b" ||
					r.Host != "app.example" || r.RemoteAddr != "192.0.2.1:1234" || r.Proto != "HTTP/1.1" {
					t.Errorf("handler got unexpected request: %+v", r)
				}
				if (r.TLS != nil) != (scheme == "https") || (r.TLS != nil && (!r.TLS.HandshakeComplete || r.TLS.ServerName != "app.example")) {
					t.Errorf("%s handler TLS = %+v", scheme, r.TLS)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			c := New(t, h, scheme+"://app.example")
			c.Get("items/a%2Fb?q=a%20b").WantStatus(http.StatusNoContent)
		})
	}
}

func TestPostForm(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if media := r.Header.Get("Content-Type"); media != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", media)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "item=a+b&item=x%2By" {
			t.Errorf("body = %q, read error = %v; want exactly the supplied fields", body, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	New(t, h, testOrigin).PostForm("/", url.Values{"item": {"a b", "x+y"}}).WantStatus(http.StatusNoContent)
}

func TestStreamed(t *testing.T) {
	for _, mode := range []string{"in-process", "server"} {
		t.Run(mode, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ContentLength != -1 || len(r.Header.Values("Content-Length")) != 0 ||
					!slices.Equal(r.TransferEncoding, []string{"chunked"}) {
					t.Errorf("length = %d, header = %q, encoding = %q; want unknown length and chunked",
						r.ContentLength, r.Header.Values("Content-Length"), r.TransferEncoding)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "data" {
					t.Errorf("body = %q, read error = %v", body, err)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			c := testClient(t, h, mode)
			req := c.NewRequest(http.MethodPost, "/", strings.NewReader("data"))
			req.Header.Set("Content-Length", "4")
			c.Do(req, Streamed()).WantStatus(http.StatusNoContent)
			if req.ContentLength != 4 || req.Header.Get("Content-Length") != "4" || len(req.TransferEncoding) != 0 {
				t.Error("options changed the original request")
			}
		})
	}
}

func TestCookieJar(t *testing.T) {
	for _, tt := range []struct {
		mode       string
		wantSecure bool
	}{
		{"in-process HTTPS", true},
		{"in-process HTTP", false},
		{"server", true}, // The standard jar treats loopback as secure even over HTTP.
		{"TLS server", true},
	} {
		t.Run(tt.mode, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/issue" {
					http.SetCookie(w, &http.Cookie{Name: "secure", Value: "kept", Path: "/", Secure: true})
					http.SetCookie(w, &http.Cookie{Name: "scoped", Value: "kept", Path: "/area"})
					return
				}
				io.WriteString(w, r.Header.Get("Cookie"))
			})
			var c *Client
			switch tt.mode {
			case "in-process HTTPS":
				c = New(t, h, testOrigin)
			case "in-process HTTP":
				c = New(t, h, "http://app.example")
			default:
				c = testClient(t, h, tt.mode)
			}
			c.Get("/issue").WantStatus(http.StatusOK)
			if got, ok := c.Cookie("secure"); ok != tt.wantSecure || (ok && got != "kept") {
				t.Errorf("secure cookie at base = %q, %v; want present = %v", got, ok, tt.wantSecure)
			}
			if _, ok := c.Cookie("scoped"); ok {
				t.Error("scoped cookie unexpectedly present at /")
			}
			c.SetCookie(&http.Cookie{Name: "seeded", Value: "value", Path: "/"})
			if got, ok := c.Cookie("seeded"); !ok || got != "value" {
				t.Errorf("seeded cookie at base = %q, %v", got, ok)
			}
			for _, path := range []string{"/", "/area/detail", "/areas"} {
				r := c.Get(path)
				r.WantStatus(http.StatusOK)
				want := map[string]bool{"secure=kept": tt.wantSecure, "scoped=kept": path == "/area/detail", "seeded=value": true}
				got := strings.Split(r.Body, "; ")
				n := 0
				for pair, wanted := range want {
					if wanted {
						n++
					}
					if slices.Contains(got, pair) != wanted {
						t.Errorf("%s: Cookie = %q; want %q present = %v", path, r.Body, pair, wanted)
					}
				}
				if len(got) != n {
					t.Errorf("%s: Cookie = %q; want %d pairs", path, r.Body, n)
				}
			}
		})
	}
}

func TestFollow(t *testing.T) {
	for _, location := range []string{"next?q=1", "https://app.example/area/next?q=1"} {
		t.Run(location, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/area/start" {
					http.SetCookie(w, &http.Cookie{Name: "visit", Value: "one", Path: "/"})
					w.Header().Set("Location", location)
					w.WriteHeader(http.StatusSeeOther)
					return
				}
				if r.Method != http.MethodGet || r.RequestURI != "/area/next?q=1" || r.Header.Get("Cookie") != "visit=one" {
					t.Errorf("follow sent %s %q with Cookie %q", r.Method, r.RequestURI, r.Header.Get("Cookie"))
				}
				w.WriteHeader(http.StatusNoContent)
			})
			c := New(t, h, testOrigin)
			c.Follow(c.PostForm("/area/start", nil)).WantStatus(http.StatusNoContent)
		})
	}
}

func TestRequestFailures(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler unexpectedly called")
	})
	for _, tt := range []struct {
		name     string
		setup    func(testing.TB)
		wantFail bool
		wantMsg  string
	}{
		{"missing scheme", func(t testing.TB) { New(t, h, "app.example") }, true, "invalid origin"},
		{"invalid origin", func(t testing.TB) { New(t, h, "https://app.example:%") }, true, "invalid origin"},
		{"URL is not an origin", func(t testing.TB) { New(t, h, testOrigin+"/items") }, true, "want an HTTP or HTTPS origin"},
		{"invalid request URL", func(t testing.TB) { New(t, h, testOrigin).Get("/%") }, true, "GET \"/%\": resolve request URL"},
		{"invalid request method", func(t testing.TB) { New(t, h, testOrigin).NewRequest("NOT VALID", "/", nil) }, true, "create request"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checkFailure(t, tt.setup, tt.wantFail, tt.wantMsg)
		})
	}
}

func TestTruncatedResponseFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "4")
		io.WriteString(w, "a")
	}))
	t.Cleanup(srv.Close)
	checkFailure(t, func(t testing.TB) {
		NewServer(t, srv).Get("/items")
	}, true, "GET /items: read response body: unexpected EOF")
}

func testClient(t *testing.T, h http.Handler, mode string) *Client {
	t.Helper()
	var srv *httptest.Server
	switch mode {
	case "in-process":
		return New(t, h, testOrigin)
	case "server":
		srv = httptest.NewServer(h)
	case "TLS server":
		srv = httptest.NewTLSServer(h)
	default:
		t.Fatalf("unknown test transport: %q", mode)
	}
	t.Cleanup(srv.Close)
	return NewServer(t, srv)
}
