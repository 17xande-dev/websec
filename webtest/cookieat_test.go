package webtest

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// cookieAtHandler issues cookies at several paths on /issue and echoes the
// Cookie header a browser-like client sends on any other request.
func cookieAtHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/issue" {
			http.SetCookie(w, &http.Cookie{Name: "scoped", Value: "admin-only", Path: "/admin"})
			http.SetCookie(w, &http.Cookie{Name: "root", Value: "everywhere", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "dup", Value: "root-value", Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "dup", Value: "admin-value", Path: "/admin"})
			http.SetCookie(w, &http.Cookie{Name: "secure", Value: "tls-only", Path: "/admin", Secure: true})
			return
		}
		io.WriteString(w, r.Header.Get("Cookie"))
	})
}

func TestCookieAt(t *testing.T) {
	for _, tt := range []struct {
		name, origin, path, cookie string
		want                       string
		wantOK                     bool
	}{
		{"sub-path cookie at its path", testOrigin, "/admin", "scoped", "admin-only", true},
		{"sub-path cookie below its path", testOrigin, "/admin/x", "scoped", "admin-only", true},
		{"sub-path cookie at root", testOrigin, "/", "scoped", "", false},
		{"sub-path cookie, empty path means root", testOrigin, "", "scoped", "", false},
		{"sub-path cookie at a sibling prefix", testOrigin, "/administrator", "scoped", "", false},
		{"sub-path cookie elsewhere", testOrigin, "/other", "scoped", "", false},
		{"root cookie at root", testOrigin, "/", "root", "everywhere", true},
		{"root cookie, empty path", testOrigin, "", "root", "everywhere", true},
		{"root cookie at sub-path", testOrigin, "/admin/x", "root", "everywhere", true},
		{"unknown name", testOrigin, "/admin", "missing", "", false},
		{"duplicate name, most specific path wins", testOrigin, "/admin", "dup", "admin-value", true},
		{"duplicate name at root", testOrigin, "/", "dup", "root-value", true},
		{"secure cookie over https", testOrigin, "/admin", "secure", "tls-only", true},
		{"secure cookie over http", "http://app.example", "/admin", "secure", "", false},
		{"query characters are literal path", testOrigin, "/admin?x=1", "scoped", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := New(t, cookieAtHandler(), tt.origin)
			c.Get("/issue").WantStatus(http.StatusOK)
			got, ok := c.CookieAt(tt.path, tt.cookie)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("CookieAt(%q, %q) = %q, %v; want %q, %v", tt.path, tt.cookie, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// TestCookieAtMatchesWhatIsSent compares CookieAt with the Cookie header the
// client really sends, so the helper cannot drift from the jar's rules. For a
// duplicated name the header lists the most specific path first, and CookieAt
// returns that first value.
func TestCookieAtMatchesWhatIsSent(t *testing.T) {
	c := New(t, cookieAtHandler(), testOrigin)
	c.Get("/issue").WantStatus(http.StatusOK)
	for _, name := range []string{"scoped", "root", "dup"} {
		for _, path := range []string{"/", "/admin", "/admin/x", "/other"} {
			sent := ""
			for _, pair := range strings.Split(c.Get(path).Body, "; ") {
				if v, found := strings.CutPrefix(pair, name+"="); found {
					sent = v
					break
				}
			}
			got, _ := c.CookieAt(path, name)
			if got != sent {
				t.Errorf("CookieAt(%q, %q) = %q; the request carried %q", path, name, got, sent)
			}
		}
	}
}

func TestCookieAtCookieDelegatesToRoot(t *testing.T) {
	c := New(t, cookieAtHandler(), testOrigin)
	c.Get("/issue").WantStatus(http.StatusOK)
	if _, ok := c.Cookie("scoped"); ok {
		t.Error("Cookie returned a cookie scoped to /admin")
	}
	if got, ok := c.Cookie("dup"); !ok || got != "root-value" {
		t.Errorf("Cookie(dup) = %q, %v; want the root value", got, ok)
	}
}

func TestCookieAtRejectsPathWithoutSlash(t *testing.T) {
	for _, path := range []string{"admin", "admin/x", "*", "https://app.example/admin"} {
		t.Run(path, func(t *testing.T) {
			checkFailure(t, func(tb testing.TB) {
				New(tb, cookieAtHandler(), testOrigin).CookieAt(path, "scoped")
			}, true, `must start with "/"`)
		})
	}
}

func TestCookieAtReportsToBoundTest(t *testing.T) {
	parent := &failRecorder{TB: t}
	checkFailure(t, func(sub testing.TB) {
		c := New(parent, cookieAtHandler(), testOrigin)
		c.With(sub).CookieAt("admin", "scoped")
	}, true, `must start with "/"`)
	if parent.Failed() {
		t.Errorf("parent failed: %q", parent.messages)
	}
}
