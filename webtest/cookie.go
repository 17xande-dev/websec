package webtest

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// CookieWant describes the expected attributes of a host-only response cookie.
type CookieWant struct {
	Name     string // literal wire name, including any prefix
	Path     string
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
	Session  bool // require neither Max-Age nor Expires
	Cleared  bool // require a deleting Max-Age (negative in Go's parsed cookie)
}

// WantCookie checks the response's one Set-Cookie named want.Name against
// want and requires it to be host-only. It also checks the browser's
// __Host- and __Secure- prefix rules independently of the expected fields.
func WantCookie(t testing.TB, r *Response, want CookieWant) *http.Cookie {
	t.Helper()
	ck := r.setCookie(t, want.Name)

	// A parsed empty string or zero duration can mean either absent or
	// malformed. Check wire attribute presence when the rule requires absence.
	var domain, maxAge, expires bool
	_, attrs, _ := strings.Cut(ck.Raw, ";")
	for attr := range strings.SplitSeq(attrs, ";") {
		name, _, _ := strings.Cut(attr, "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "domain":
			domain = true
		case "max-age":
			maxAge = true
		case "expires":
			expires = true
		}
	}
	label := fmt.Sprintf("%s: cookie %q", r.summary(), ck.Name)
	// Restate the browser rules here so the assertion cannot agree with a
	// bug in the code that produced the cookie. Browsers match the prefixes
	// case-insensitively.
	name := strings.ToLower(ck.Name)
	switch {
	case strings.HasPrefix(name, "__host-"):
		if !ck.Secure || ck.Path != "/" || domain {
			t.Fatalf("%s: __Host- requires Secure, Path=/ and no Domain; got Secure=%t, Path=%q, Domain present=%t",
				label, ck.Secure, ck.Path, domain)
		}
	case strings.HasPrefix(name, "__secure-"):
		if !ck.Secure {
			t.Fatalf("%s: __Secure- requires Secure", label)
		}
	}
	if domain {
		t.Errorf("%s: Domain must be absent (host-only cookie)", label)
	}
	if ck.Path != want.Path {
		t.Errorf("%s: Path = %q; want %q", label, ck.Path, want.Path)
	}
	if ck.Secure != want.Secure {
		t.Errorf("%s: Secure = %t; want %t", label, ck.Secure, want.Secure)
	}
	if ck.HttpOnly != want.HttpOnly {
		t.Errorf("%s: HttpOnly = %t; want %t", label, ck.HttpOnly, want.HttpOnly)
	}
	if ck.SameSite != want.SameSite {
		t.Errorf("%s: SameSite = %v; want %v", label, ck.SameSite, want.SameSite)
	}
	if want.Session && (maxAge || expires) {
		t.Errorf("%s: session cookie requires no Max-Age or Expires; got Max-Age present=%t, Expires present=%t",
			label, maxAge, expires)
	}
	if want.Cleared && ck.MaxAge >= 0 {
		t.Errorf("%s: cleared cookie requires parsed Max-Age < 0; got %d", label, ck.MaxAge)
	}
	return ck
}
