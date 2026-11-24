package csrf_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/17xande-dev/websec/csrf"
	"github.com/justinas/nosurf"
)

const ownOrigin = "https://app.example"

func TestNew(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*csrf.Config)
	}{
		{"empty origin", func(c *csrf.Config) { c.Origin = "" }},
		{"origin without scheme", func(c *csrf.Config) { c.Origin = "app.example" }},
		{"origin without host", func(c *csrf.Config) { c.Origin = "https://:443" }},
		{"unbracketed IPv6", func(c *csrf.Config) { c.Origin = "https://2001:db8::1" }},
		{"invalid bracketed host", func(c *csrf.Config) { c.Origin = "https://[app.example]" }},
		{"origin trailing slash", func(c *csrf.Config) { c.Origin = "https://a.example/" }},
		{"origin path", func(c *csrf.Config) { c.Origin = "https://a.example/x" }},
		{"origin userinfo", func(c *csrf.Config) { c.Origin = "https://u@a.example" }},
		{"origin query", func(c *csrf.Config) { c.Origin = "https://a.example?q=x" }},
		{"origin empty query", func(c *csrf.Config) { c.Origin = "https://a.example?" }},
		{"origin fragment", func(c *csrf.Config) { c.Origin = "https://a.example#part" }},
		{"origin empty fragment", func(c *csrf.Config) { c.Origin = "https://a.example#" }},
		{"uppercase origin", func(c *csrf.Config) { c.Origin = "HTTPS://A.EXAMPLE" }},
		{"uppercase host", func(c *csrf.Config) { c.Origin = "https://A.EXAMPLE" }},
		{"invalid origin port", func(c *csrf.Config) { c.Origin = "https://a.example:65536" }},
		{"empty origin port", func(c *csrf.Config) { c.Origin = "https://a.example:" }},
		{"non-HTTP origin", func(c *csrf.Config) { c.Origin = "ftp://a.example" }},
		{"plain HTTP without Insecure", func(c *csrf.Config) { c.Origin = "http://a.example" }},
		{"invalid extra origin", func(c *csrf.Config) { c.TrustedOrigins = []string{"https://embed.example", "https://a.example/path"} }},
		{"plain HTTP extra without Insecure", func(c *csrf.Config) { c.TrustedOrigins = []string{"http://embed.example"} }},
		{"origin with the default HTTPS port", func(c *csrf.Config) { c.Origin = "https://a.example:443" }},
		{"origin with the default HTTP port", func(c *csrf.Config) { c.Origin, c.Insecure = "http://a.example:80", true }},
		{"extra origin with the default HTTPS port", func(c *csrf.Config) { c.TrustedOrigins = []string{"https://embed.example:443"} }},
		{"extra origin with the default HTTP port", func(c *csrf.Config) {
			c.Insecure, c.TrustedOrigins = true, []string{"http://embed.example:80"}
		}},
		{"insecure cross-site cookie", func(c *csrf.Config) { c.Insecure, c.CrossSite = true, true }},
		{"negative default body cap", func(c *csrf.Config) { c.MaxBody = -1 }},
		{"default body cap over 64 MiB", func(c *csrf.Config) { c.MaxBody = 64<<20 + 1 }},
		{"invalid cookie name", func(c *csrf.Config) { c.Name = "invalid name" }},
		{"host-prefixed cookie name", func(c *csrf.Config) { c.Name = "__Host-token" }},
		{"mixed-case secure-prefixed cookie name", func(c *csrf.Config) { c.Name = "__sEcUrE-token" }},
		{"relative cookie path", func(c *csrf.Config) { c.Path = "admin" }},
		{"cookie path with semicolon", func(c *csrf.Config) { c.Path = "/admin;extra" }},
		{"cookie path with control byte", func(c *csrf.Config) { c.Path = "/admin\t" }},
		{"cookie path with space", func(c *csrf.Config) { c.Path = "/admin area" }},
		{"cookie path over 1024 bytes", func(c *csrf.Config) { c.Path = "/" + strings.Repeat("x", 1024) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := csrf.Config{Origin: ownOrigin}
			tc.edit(&c)
			if p, err := csrf.New(c); err == nil || p != nil {
				t.Errorf("New accepted invalid policy: %v", err)
			}
		})
	}
	// Duplicates are ignored; a malformed entry still fails (rows above).
	mustNew(t, csrf.Config{Origin: ownOrigin, TrustedOrigins: []string{ownOrigin, "https://embed.example", "https://embed.example"}})
	mustNew(t, csrf.Config{Origin: "https://[2001:db8::1]:8443", MaxBody: 64 << 20})
	mustNew(t, csrf.Config{Origin: "http://app.example:8080", Insecure: true, TrustedOrigins: []string{"http://embed.example:8081"}})
	// A default port of the other scheme is an ordinary port.
	mustNew(t, csrf.Config{Origin: "https://app.example:80", Insecure: true, TrustedOrigins: []string{"http://embed.example:443"}})
}

func TestOrigins(t *testing.T) {
	const embed = "https://embed.example:8443"
	reasons := make(chan error, 1)
	p := mustNew(t, csrf.Config{
		Origin: ownOrigin, CrossSite: true, TrustedOrigins: []string{embed},
		OnFailure: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reasons <- csrf.Reason(r)
			w.WriteHeader(http.StatusForbidden)
		}),
	})
	s, client := server(t, p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, csrf.Token(r))
	})))
	token, cookie := formToken(t, s, client, "/")
	if cookie.SameSite != http.SameSiteNoneMode || !cookie.Secure {
		t.Fatal("credentialed embed needs a secure SameSite=None cookie")
	}
	for _, tc := range []struct {
		name, origin, referer, host, fetch, forwarded string
		badToken                                      bool
		reason                                        error
	}{
		{name: "own origin", origin: ownOrigin, host: "app.example"},
		{name: "credentialed cross-site embed", origin: embed, fetch: "cross-site"},
		{name: "embed missing exact port", origin: "https://embed.example", reason: nosurf.ErrBadOrigin},
		{name: "sibling subdomain", origin: "https://sibling.app.example", fetch: "same-site", reason: nosurf.ErrBadOrigin},
		{name: "HTTP own host against HTTPS", origin: "http://app.example", host: "app.example", reason: nosurf.ErrBadOrigin},
		{name: "HTTP embed against HTTPS", origin: "http://embed.example:8443", reason: nosurf.ErrBadOrigin},
		{name: "missing origin and referer", reason: nosurf.ErrNoReferer},
		{name: "null origin with own referer", origin: "null", referer: ownOrigin + "/form"},
		{name: "fetch metadata with token", fetch: "same-origin"},
		{name: "fetch metadata without valid token", fetch: "same-origin", badToken: true, reason: nosurf.ErrBadToken},
		{name: "rewritten host behind proxy", origin: ownOrigin, host: "internal.example"},
		{name: "forwarded scheme does not change TLS answer", origin: "http://internal.example", host: "internal.example", forwarded: "http", reason: nosurf.ErrBadOrigin},
		{name: "allowed origin with bad token", origin: ownOrigin, badToken: true, reason: nosurf.ErrBadToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request(t, http.MethodPost, s.URL+"/form", nil)
			if tc.host != "" {
				req.Host = tc.host
				// A rewritten upstream Host is not the browser-facing cookie host.
				req.AddCookie(cookie)
			}
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Referer", tc.referer)
			req.Header.Set("Sec-Fetch-Site", tc.fetch)
			req.Header.Set("X-Forwarded-Proto", tc.forwarded)
			if !tc.badToken {
				req.Header.Set(csrf.HeaderName, token)
			}
			resp, _ := send(t, client, req)
			want := http.StatusOK
			if tc.reason != nil {
				want = http.StatusForbidden
			}
			if resp.StatusCode != want {
				t.Errorf("status=%d, want %d", resp.StatusCode, want)
			}
			if resp.StatusCode == http.StatusForbidden {
				if reason := <-reasons; reason != tc.reason {
					t.Errorf("reason=%v, want %v", reason, tc.reason)
				}
			}
		})
	}
}

func TestInsecureOrigins(t *testing.T) {
	// In plain-HTTP development the TLS answer must be false: nosurf then
	// compares http://Host. A wrong answer would be hidden by the allowlist's
	// own http:// origin, so use a Host the allowlist does not contain.
	p := mustNew(t, csrf.Config{Origin: "http://app.example", Insecure: true})
	s := httptest.NewServer(p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, csrf.Token(r))
	})))
	client := cookieClient(t, s)
	token, cookie := formToken(t, s, client, "/")
	for _, tc := range []struct {
		name, host, origin string
		status             int
	}{
		{"request's own http host", "other.example", "http://other.example", http.StatusOK},
		{"https origin for an http host", "other.example", "https://other.example", http.StatusForbidden},
		{"configured origin", "", "http://app.example", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request(t, http.MethodPost, s.URL+"/form", strings.NewReader(url.Values{csrf.FieldName: {token}}.Encode()))
			req.Header.Set("Content-Type", urlencoded)
			req.Header.Set("Origin", tc.origin)
			if tc.host != "" {
				req.Host = tc.host
				// The jar keys the cookie to the connection's host.
				req.AddCookie(cookie)
			}
			if resp, _ := send(t, client, req); resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func TestCookie(t *testing.T) {
	for _, tc := range []struct {
		name, path, bareName, cookieName string
		insecure, crossSite              bool
		sameSite                         http.SameSite
	}{
		{"secure root-path", "/", "", "__Host-csrf_token", false, false, http.SameSiteLaxMode},
		{"secure admin-path", "/admin", "", "__Secure-csrf_token", false, false, http.SameSiteLaxMode},
		{"plain-HTTP development", "/", "", "csrf_token", true, false, http.SameSiteLaxMode},
		{"credentialed cross-site embed", "/", "", "__Host-csrf_token", false, true, http.SameSiteNoneMode},
		{"custom cookie name", "/", "form_secret", "__Host-form_secret", false, false, http.SameSiteLaxMode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := csrf.Config{Origin: ownOrigin, Name: tc.bareName, Insecure: tc.insecure, CrossSite: tc.crossSite}
			if tc.path != "/" {
				c.Path = tc.path
			}
			if c.Insecure {
				c.Origin = "http://app.example"
			}
			p := mustNew(t, c)
			handler := p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, csrf.Token(r))
			}))
			s := httptest.NewUnstartedServer(handler)
			if c.Insecure {
				s.Start()
			} else {
				s.StartTLS()
			}
			client := cookieClient(t, s)
			token, wire := formToken(t, s, client, tc.path)
			if p.CookieName() != tc.cookieName || wire.Name != tc.cookieName || wire.Path != tc.path ||
				wire.Secure == tc.insecure || !wire.HttpOnly || wire.SameSite != tc.sameSite ||
				wire.Domain != "" || wire.MaxAge != 0 || !wire.Expires.IsZero() {
				t.Errorf("unexpected cookie attributes (name=%q path=%q secure=%t httpOnly=%t SameSite=%d Domain=%q MaxAge=%d Expires=%v)",
					wire.Name, wire.Path, wire.Secure, wire.HttpOnly, wire.SameSite, wire.Domain, wire.MaxAge, wire.Expires)
			}
			req := request(t, http.MethodPost, s.URL+tc.path, strings.NewReader(url.Values{csrf.FieldName: {token}}.Encode()))
			req.Header.Set("Content-Type", urlencoded)
			req.Header.Set("Origin", c.Origin)
			resp, _ := send(t, client, req)
			if resp.StatusCode != http.StatusOK || len(resp.Cookies()) != 0 {
				t.Errorf("cookie did not round-trip with the fixed form field: status=%d, Set-Cookie=%d", resp.StatusCode, len(resp.Cookies()))
			}
		})
	}
}

func TestFailure(t *testing.T) {
	for _, tc := range []struct {
		name, message   string
		htmx, override  bool
		malformedOrigin bool
	}{
		{name: "plain form", message: "This form has expired or came from another site. Reload the page and try again.\n"},
		{name: "htmx form", htmx: true, message: "This form has expired. The page will reload.\n"},
		{name: "htmx response override", htmx: true, override: true, message: "not saved"},
		{name: "malformed origin redaction", malformedOrigin: true, message: "This form has expired or came from another site. Reload the page and try again.\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs logBuffer
			c := csrf.Config{Origin: ownOrigin, Logger: slog.New(slog.NewJSONHandler(&logs, nil))}
			if tc.override {
				c.OnFailure = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if csrf.Reason(r) != nosurf.ErrBadToken {
						t.Errorf("override got reason %v, want ErrBadToken", csrf.Reason(r))
					}
					if logs.String() == "" {
						t.Error("override ran before the warning")
					}
					w.WriteHeader(http.StatusUnprocessableEntity)
					fmt.Fprint(w, "not saved")
				})
			}
			p := mustNew(t, c)
			s, client := server(t, p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("failure passed to next")
				}
				fmt.Fprint(w, csrf.Token(r))
			})))
			token, cookie := formToken(t, s, client, "/")
			const badToken, formSecret, querySecret = "bad-masked-token", "private-form-value", "private-query-value"
			form := url.Values{csrf.FieldName: {badToken}, "field": {formSecret}}
			req := request(t, http.MethodPost, s.URL+"/form?private="+querySecret, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", urlencoded)
			req.Header.Set("Origin", ownOrigin)
			if tc.malformedOrigin {
				req.Header.Set("Origin", "https://%zz"+querySecret)
			}
			if tc.htmx {
				req.Header.Set("HX-Request", "true")
			}
			resp, body := send(t, client, req)
			wantStatus, wantRefresh, wantCache := http.StatusForbidden, "", "no-store"
			if tc.override {
				wantStatus, wantCache = http.StatusUnprocessableEntity, ""
			} else if tc.htmx {
				wantRefresh = "true"
			}
			if resp.StatusCode != wantStatus || body != tc.message || resp.Header.Get("HX-Refresh") != wantRefresh ||
				resp.Header.Get("Cache-Control") != wantCache || !tc.override && resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
				t.Errorf("unexpected failure response: status=%d, body=%q, HX-Refresh=%q, Cache-Control=%q",
					resp.StatusCode, body, resp.Header.Get("HX-Refresh"), resp.Header.Get("Cache-Control"))
			}
			raw := logs.String()
			var record map[string]any
			wantReason := nosurf.ErrBadToken.Error()
			if tc.malformedOrigin {
				wantReason = "malformed origin"
			}
			if err := json.Unmarshal([]byte(raw), &record); err != nil || record["level"] != "WARN" ||
				record["msg"] != "csrf: request refused" || record["method"] != "POST" ||
				record["path"] != "/form" || record["reason"] != wantReason {
				t.Error("missing or incorrect CSRF warning")
			}
			for _, secret := range []string{badToken, token, cookie.Value, formSecret, querySecret} {
				if strings.Contains(raw, secret) {
					t.Error("warning disclosed a token, cookie, form value, or query")
				}
			}
		})
	}
}

func TestRenew(t *testing.T) {
	p := mustNew(t, csrf.Config{Origin: ownOrigin})
	mux := http.NewServeMux()
	mux.Handle("/issue", p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if csrf.Reason(r) != nil {
			t.Error("safe request has a failure reason")
		}
		fmt.Fprint(w, csrf.Token(r))
	})))
	mux.Handle("/renew", p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		old := csrf.Token(r)
		token, err := p.Renew(w, r)
		if err != nil || token == "" || token == old || token != csrf.Token(r) {
			t.Errorf("Renew did not replace the token in the current request: %v", err)
		}
		fmt.Fprint(w, token)
	})))
	mux.Handle("/submit", p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	s, client := server(t, mux)
	oldToken, oldCookie := formToken(t, s, client, "/issue")
	post := func(path, token string) (*http.Response, string) {
		req := request(t, http.MethodPost, s.URL+path, nil)
		req.Header.Set("Origin", ownOrigin)
		req.Header.Set(csrf.HeaderName, token)
		return send(t, client, req)
	}
	resp, renewed := post("/renew", oldToken)
	cookies := resp.Cookies()
	if resp.StatusCode != http.StatusOK || len(cookies) != 1 || cookies[0].Value == oldCookie.Value ||
		cookies[0].Name != oldCookie.Name || cookies[0].Path != oldCookie.Path || cookies[0].Secure != oldCookie.Secure ||
		cookies[0].HttpOnly != oldCookie.HttpOnly || cookies[0].SameSite != oldCookie.SameSite ||
		cookies[0].MaxAge != 0 || !cookies[0].Expires.IsZero() {
		t.Fatalf("renewal did not replace the cookie under the same policy: status=%d, cookies=%d", resp.StatusCode, len(cookies))
	}
	if resp, _ := post("/submit", renewed); resp.StatusCode != http.StatusNoContent {
		t.Errorf("renewed token rejected by another handler: %d", resp.StatusCode)
	}
	if resp, _ := post("/submit", oldToken); resp.StatusCode != http.StatusForbidden {
		t.Errorf("old token not refused: %d", resp.StatusCode)
	}
}

func TestRenewOutside(t *testing.T) {
	p := mustNew(t, csrf.Config{Origin: ownOrigin})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if csrf.Token(r) != "" || csrf.Reason(r) != nil {
		t.Error("unprotected request has CSRF state")
	}
	token, err := p.Renew(w, r)
	if token != "" || !errors.Is(err, csrf.ErrNotProtected) || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Errorf("unprotected renewal should do nothing, got error %v", err)
	}
}

func TestNosurfRegenerateOutsidePanics(t *testing.T) {
	// Pin the upstream behavior that makes the guard necessary in v1.2.0.
	defer func() {
		if recover() == nil {
			t.Error("upstream regeneration no longer panics without its context; revisit the guard")
		}
	}()
	nosurf.New(nil).RegenerateToken(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func mustNew(t *testing.T, c csrf.Config) *csrf.Protect {
	t.Helper()
	p, err := csrf.New(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func server(t *testing.T, handler http.Handler) (*httptest.Server, *http.Client) {
	t.Helper()
	s := httptest.NewTLSServer(handler)
	return s, cookieClient(t, s)
}

func cookieClient(t *testing.T, s *httptest.Server) *http.Client {
	t.Helper()
	t.Cleanup(s.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := *s.Client()
	client.Jar = jar
	return &client
}

func formToken(t *testing.T, s *httptest.Server, client *http.Client, path string) (string, *http.Cookie) {
	t.Helper()
	resp, token := send(t, client, request(t, http.MethodGet, s.URL+path, nil))
	cookies := resp.Cookies()
	if resp.StatusCode != http.StatusOK || token == "" || len(cookies) != 1 {
		t.Fatalf("could not obtain form token: status=%d, cookies=%d", resp.StatusCode, len(cookies))
	}
	return token, cookies[0]
}

func request(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func send(t *testing.T, client *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

// Repeating the own origin or an earlier entry changes nothing: the list is
// still trusted exactly as written, and nothing else is.
func TestDuplicateOriginsAreIgnored(t *testing.T) {
	const embed = "https://embed.example"
	p := mustNew(t, csrf.Config{Origin: ownOrigin, TrustedOrigins: []string{ownOrigin, embed, embed}})
	s, client := server(t, p.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, csrf.Token(r))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	token, _ := formToken(t, s, client, "/")
	// The port is part of the match: an entry without one never admits a
	// request origin that has one.
	for origin, want := range map[string]int{ownOrigin: 204, embed: 204, "https://other.example": 403,
		ownOrigin + ":8443": 403, embed + ":8443": 403} {
		req := request(t, "POST", s.URL, strings.NewReader(url.Values{csrf.FieldName: {token}}.Encode()))
		req.Header.Set("Content-Type", urlencoded)
		req.Header.Set("Origin", origin)
		if resp, _ := send(t, client, req); resp.StatusCode != want {
			t.Errorf("origin %s: status = %d, want %d", origin, resp.StatusCode, want)
		}
	}
}
