package webtest

import (
	"fmt"
	"net/http"
	"testing"
)

// Response is the result of one request, with its body read in full.
type Response struct {
	// Request is the outgoing request, including applied options.
	Request *http.Request
	// Status is the HTTP status code.
	Status int
	// Header holds the response headers as received from the transport.
	Header http.Header
	// Body is the response body.
	Body string

	t testing.TB
}

// Location returns the raw Location header, or "" if absent. It fails the
// test if the response contains multiple Location values.
func (r *Response) Location() string {
	r.t.Helper()
	values := r.Header.Values("Location")
	switch len(values) {
	case 0:
		return ""
	case 1:
		return values[0]
	default:
		r.t.Fatalf("%s: multiple Location values: %q", r.summary(), values)
		return ""
	}
}

// WantStatus fails the test unless the response status equals code.
func (r *Response) WantStatus(code int) {
	r.t.Helper()
	if r.Status != code {
		r.t.Fatalf("%s: want status %d", r.summary(), code)
	}
}

// WantRedirect checks both the status and the exact, unparsed Location value.
func (r *Response) WantRedirect(code int, location string) {
	r.t.Helper()
	got := r.Location()
	if r.Status != code || got != location {
		r.t.Fatalf("%s: Location %q; want status %d and Location %q", r.summary(), got, code, location)
	}
}

// SetCookie returns the response cookie named name. It fails the test if no
// parsed Set-Cookie or more than one parsed Set-Cookie matches the name.
func (r *Response) SetCookie(name string) *http.Cookie {
	r.t.Helper()
	res := http.Response{Header: r.Header}
	var found *http.Cookie
	for _, ck := range res.Cookies() {
		if ck.Name != name {
			continue
		}
		if found != nil {
			r.t.Fatalf("%s: multiple Set-Cookie values named %q", r.summary(), name)
		}
		found = ck
	}
	if found == nil {
		r.t.Fatalf("%s: no Set-Cookie named %q", r.summary(), name)
	}
	return found
}

func (r *Response) summary() string {
	body := r.Body
	suffix := ""
	if len(body) > 300 {
		body = body[:300]
		suffix = "…"
	}
	return fmt.Sprintf("%s %s: status %d, body %q%s", r.Request.Method, r.Request.URL.RequestURI(), r.Status, body, suffix)
}
