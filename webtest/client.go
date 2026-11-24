package webtest

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Client sends HTTP requests with a cookie jar and an Origin on unsafe
// methods by default. It does not follow redirects or parse Location headers.
// Build it inside the test that makes assertions; never share it across
// t.Run subtests. Assertions report to the testing.TB given at construction.
type Client struct {
	t         testing.TB
	base      *url.URL
	origin    string
	jar       *cookiejar.Jar
	transport http.RoundTripper
	defaults  []Option
}

// New serves requests in-process through h. The origin (for example,
// "https://app.example") is the base URL for requests; an HTTPS origin
// simulates TLS. Response headers include bytes that the HTTP reader rejects.
// The jar does not send Secure cookies to non-loopback HTTP origins. Use
// HTTPS in-process and httptest.NewTLSServer with NewServer to test production
// cookie settings. The jar does not enforce cookie prefixes; use WantCookie.
func New(t testing.TB, h http.Handler, origin string, opts ...Option) *Client {
	t.Helper()
	return newClient(t, origin, handlerTransport{h}, opts)
}

// NewServer sends requests over a real connection using srv's transport,
// including its TLS configuration. Its default Origin is srv.URL.
func NewServer(t testing.TB, srv *httptest.Server, opts ...Option) *Client {
	t.Helper()
	return newClient(t, srv.URL, srv.Client().Transport, opts)
}

func newClient(t testing.TB, origin string, transport http.RoundTripper, opts []Option) *Client {
	t.Helper()
	base, err := url.Parse(origin)
	if err != nil {
		t.Fatalf("invalid origin %q: %v", origin, err)
	}
	if (base.Scheme != "http" && base.Scheme != "https") || base.Hostname() == "" || base.User != nil ||
		(base.EscapedPath() != "" && base.EscapedPath() != "/") || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" {
		t.Fatalf("invalid origin %q: want an HTTP or HTTPS origin", origin)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	return &Client{
		t: t, base: base, origin: base.Scheme + "://" + base.Host, jar: jar,
		transport: transport, defaults: slices.Clone(opts),
	}
}

// Get sends a GET request for path.
func (c *Client) Get(path string, opts ...Option) *Response {
	c.t.Helper()
	return c.Do(c.NewRequest(http.MethodGet, path, nil), opts...)
}

// PostForm sends form as a URL-encoded POST, without adding any fields.
func (c *Client) PostForm(path string, form url.Values, opts ...Option) *Response {
	c.t.Helper()
	req := c.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.Do(req, opts...)
}

// NewRequest builds a request for Do, resolving path against the client's
// base URL.
func (c *Client) NewRequest(method, path string, body io.Reader) *http.Request {
	c.t.Helper()
	target, err := c.base.Parse(path)
	if err != nil {
		c.t.Fatalf("%s %q: resolve request URL: %v", method, path, err)
	}
	req, err := http.NewRequestWithContext(c.t.Context(), method, target.String(), body)
	if err != nil {
		c.t.Fatalf("%s %q: create request: %v", method, path, err)
	}
	return req
}

// Do sends req, applying client defaults and then per-request options. It
// sends and stores cookies using the request URL. Do takes ownership of the
// request body and closes it, but does not modify the original headers.
func (c *Client) Do(req *http.Request, opts ...Option) *Response {
	c.t.Helper()
	req = req.Clone(req.Context())
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
	default:
		if len(req.Header.Values("Origin")) == 0 {
			req.Header.Set("Origin", c.origin)
		}
	}
	for _, opt := range c.defaults {
		opt(req)
	}
	for _, opt := range opts {
		opt(req)
	}
	for _, ck := range c.jar.Cookies(req.URL) {
		req.AddCookie(ck)
	}

	// http.Client parses Location before calling CheckRedirect, even if
	// CheckRedirect would return ErrUseLastResponse.
	res, err := c.transport.RoundTrip(req)
	if err != nil {
		c.t.Fatalf("%s %s: round trip: %v", req.Method, req.URL.RequestURI(), err)
	}
	defer res.Body.Close()
	c.jar.SetCookies(req.URL, res.Cookies())
	body, err := io.ReadAll(res.Body)
	if err != nil {
		c.t.Fatalf("%s %s: read response body: %v", req.Method, req.URL.RequestURI(), err)
	}
	return &Response{Request: req, Status: res.StatusCode, Header: res.Header, Body: string(body), t: c.t, client: c}
}

// Follow explicitly sends a GET to a 3xx response's Location, resolved
// against the original request URL. It fails if Location is missing, cannot
// be parsed, or leaves the client's origin.
func (c *Client) Follow(r *Response) *Response {
	c.t.Helper()
	if r.Status < 300 || r.Status >= 400 {
		c.t.Fatalf("%s: cannot follow a non-3xx response", r.summary())
	}
	location := r.Location()
	if location == "" {
		c.t.Fatalf("%s: cannot follow without a Location", r.summary())
	}
	target, err := r.Request.URL.Parse(location)
	if err != nil {
		c.t.Fatalf("%s: cannot follow Location %q: %v; assert on Location() instead", r.summary(), location, err)
	}
	if target.Scheme != c.base.Scheme || target.Host != c.base.Host {
		c.t.Fatalf("%s: Location %q leaves %s; assert on Location() instead", r.summary(), location, c.origin)
	}
	return c.Get(target.String())
}

// SetCookie seeds the client's jar with ck and fails if the jar would not
// send that name and value to the client's base URL.
func (c *Client) SetCookie(ck *http.Cookie) {
	c.t.Helper()
	if ck == nil {
		c.t.Fatal("SetCookie: nil cookie")
	}
	c.jar.SetCookies(c.base, []*http.Cookie{ck})
	for _, stored := range c.jar.Cookies(c.base) {
		if stored.Name == ck.Name && stored.Value == ck.Value {
			return
		}
	}
	c.t.Fatalf("SetCookie %q: the jar would not send it to %s (check Secure, Domain, Path and expiry)", ck.Name, c.origin)
}

// Cookie returns the named cookie's value, if the jar would send it to the
// client's base URL.
func (c *Client) Cookie(name string) (value string, ok bool) {
	for _, ck := range c.jar.Cookies(c.base) {
		if ck.Name == name {
			return ck.Value, true
		}
	}
	return "", false
}

type handlerTransport struct{ handler http.Handler }

// RoundTrip serves one request through the handler without using the network.
func (tr handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Keep the client request intact for diagnostics and relative redirects.
	// The handler gets the same synthetic peer and TLS state as httptest.
	in := req.Clone(req.Context())
	in.RequestURI = req.URL.RequestURI()
	in.RemoteAddr = "192.0.2.1:1234"
	in.GetBody = nil
	if in.Host == "" {
		in.Host = req.URL.Host
	}
	if req.URL.Scheme == "https" {
		in.TLS = &tls.ConnectionState{
			Version: tls.VersionTLS12, HandshakeComplete: true, ServerName: in.Host,
		}
	}
	if len(in.TransferEncoding) == 0 {
		switch {
		case in.ContentLength > 0 && in.Body != nil && in.Body != http.NoBody:
			in.Header.Set("Content-Length", strconv.FormatInt(in.ContentLength, 10))
		case in.ContentLength == 0 && (in.Body == nil || in.Body == http.NoBody):
			// net/http sends an explicit zero for these empty requests.
			switch in.Method {
			case http.MethodPost, http.MethodPut, http.MethodPatch:
				in.Header.Set("Content-Length", "0")
			}
		}
	}
	if in.Body == nil {
		in.Body = http.NoBody
	}
	defer in.Body.Close()

	rec := httptest.NewRecorder()
	tr.handler.ServeHTTP(rec, in)
	return rec.Result(), nil
}
