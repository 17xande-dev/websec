package websec

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var fuzzOptions = []RedirectOptions{
	{Fallback: fallback},
	{Prefix: "/admin/", Fallback: fallback},
	{Deny: []string{"/login", "/logout"}, Fallback: fallback},
	{Prefix: "/admin/", Deny: []string{"/admin/login"}, Fallback: fallback},
}

var encodedDot = regexp.MustCompile(`(?i)%2e`)

// browserResolve approximates how a browser resolves a link found on
// https://site.example/base/: it strips TAB, LF and CR anywhere, trims leading
// and trailing C0 controls and space, reads "\" as "/", and treats "%2e" as a
// dot when removing dot segments (Go's own resolver would not). ok is false
// when even this lenient pipeline cannot parse the result.
func browserResolve(next string) (u *url.URL, ok bool) {
	s := strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(next)
	s = strings.TrimFunc(s, func(r rune) bool { return r <= 0x20 })
	s = strings.ReplaceAll(s, `\`, "/")
	s = encodedDot.ReplaceAllString(s, ".")
	ref, err := url.Parse(s)
	if err != nil {
		return nil, false
	}
	base, _ := url.Parse("https://site.example/base/")
	return base.ResolveReference(ref), true
}

// FuzzSafeRedirect checks the property that matters, not the implementation:
// whatever SafeRedirect accepts is returned unchanged and, read the way a
// browser reads it, stays on the same host, under the required prefix and
// outside every denied prefix.
func FuzzSafeRedirect(f *testing.F) {
	for _, r := range redirectTable() {
		for i := range fuzzOptions {
			f.Add(r.in, uint8(i))
		}
	}
	f.Add("/a/b/", uint8(0))
	f.Add("/admin/x", uint8(1))
	// Found by fuzzing: the browser trims the trailing space, exposing "..".
	f.Add("/admin/%2e%2e ", uint8(1))
	f.Fuzz(func(t *testing.T, next string, opt uint8) {
		o := fuzzOptions[int(opt)%len(fuzzOptions)]
		got := SafeRedirect(next, o)
		if got == o.Fallback {
			return // refused (the fallback is not a path, so it is never an accepted value)
		}
		if got != next {
			t.Fatalf("accepted value was rewritten: %q -> %q", next, got)
		}
		u, ok := browserResolve(next)
		if !ok {
			return
		}
		if u.Scheme != "https" || u.Host != "site.example" || u.User != nil {
			t.Fatalf("%q resolves off site: %s", next, u)
		}
		// A browser compares the raw (still-encoded) path, so "/admin%2fx" is not
		// under "/admin/"; Go's decoded u.Path would say it is.
		if !strings.HasPrefix(u.EscapedPath(), o.Prefix) {
			t.Fatalf("%q resolves to %q, outside prefix %q", next, u.EscapedPath(), o.Prefix)
		}
		for _, d := range o.Deny {
			if strings.HasPrefix(u.Path, d) {
				t.Fatalf("%q resolves to %q, under denied %q", next, u.Path, d)
			}
		}
	})
}
