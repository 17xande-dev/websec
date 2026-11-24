package webtest_test

import (
	"slices"
	"testing"

	"github.com/17xande-dev/websec"
	"github.com/17xande-dev/websec/webtest"
)

func TestHostileRedirects(t *testing.T) {
	const fallback = "/fallback"
	corpus := webtest.HostileRedirects()
	for _, want := range []string{
		"//evil.example", "/\t/evil.example", "/\n/evil.example", `/\evil.example`,
		"/%2fevil.example", "/%5cevil.example", "/%09/evil.example",
	} {
		if !slices.Contains(corpus, want) {
			t.Errorf("missing corpus entry %q", want)
		}
	}
	for _, location := range corpus {
		if got := websec.SafeRedirect(location, websec.RedirectOptions{Fallback: fallback}); got != fallback {
			t.Errorf("SafeRedirect(%.60q) = %.60q; want %q", location, got, fallback)
		}
	}
	original := corpus[0]
	corpus[0] = "/changed"
	if got := webtest.HostileRedirects()[0]; got != original {
		t.Errorf("mutating the corpus changed the next result to %q", got)
	}
}
