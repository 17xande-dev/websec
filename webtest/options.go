package webtest

import "net/http"

// Option adjusts one request, or every request when passed to a constructor.
type Option func(*http.Request)

// WithOrigin sets the Origin header without changing the request URL.
// As a constructor option it sets the header on every request, even on
// safe methods that would not otherwise send Origin.
func WithOrigin(origin string) Option { return Header("Origin", origin) }

// NoOrigin removes the Origin header.
func NoOrigin() Option {
	return func(r *http.Request) { r.Header.Del("Origin") }
}

// SecFetchSite sets Sec-Fetch-Site. The client does not send it by default
// because "same-origin" can make CSRF middleware skip the Origin check.
func SecFetchSite(v string) Option { return Header("Sec-Fetch-Site", v) }

// HTMX marks the request with HX-Request: true.
func HTMX() Option { return Header("HX-Request", "true") }

// Header sets a request header, replacing any previous values for name.
func Header(name, value string) Option {
	return func(r *http.Request) { r.Header.Set(name, value) }
}

// Streamed marks the request body as having unknown length and requests
// chunked transfer encoding over HTTP/1.1.
func Streamed() Option {
	return func(r *http.Request) {
		r.ContentLength = -1
		r.Header.Del("Content-Length")
		r.TransferEncoding = []string{"chunked"}
	}
}
