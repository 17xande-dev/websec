package websec

import (
	"strings"
	"testing"
)

const fallback = "FALLBACK" // deliberately not a valid path: SafeRedirect must return it verbatim

type redirectRow struct {
	opts RedirectOptions
	in   string
	ok   bool // true: accepted and returned byte-identical; false: refused, Fallback returned
}

func checkRows(t *testing.T, rows []redirectRow) {
	t.Helper()
	if len(rows) < 5 { // an "every row" test must not pass vacuously
		t.Fatalf("only %d rows", len(rows))
	}
	for _, r := range rows {
		r.opts.Fallback = fallback
		want := fallback
		if r.ok {
			want = r.in
		}
		if got := SafeRedirect(r.in, r.opts); got != want {
			t.Errorf("SafeRedirect(%.60q, %+v) = %.60q, want %.60q", r.in, r.opts, got, want)
		}
	}
}

func rows(opts RedirectOptions, ok bool, inputs ...string) []redirectRow {
	out := make([]redirectRow, len(inputs))
	for i, in := range inputs {
		out[i] = redirectRow{opts, in, ok}
	}
	return out
}

var (
	noOptions       = RedirectOptions{}
	loginDenied     = RedirectOptions{Deny: []string{"/login", "/logout"}}
	connectorDenied = RedirectOptions{Deny: []string{"/login", "/logout", "/connector/connect", "/connector/callback"}}
	adminOnly       = RedirectOptions{Prefix: "/admin/"}
)

// redirectTable is the union of the redirect rows collected from several
// independent validators, grouped by the options each was used with.
func redirectTable() []redirectRow {
	var t []redirectRow
	add := func(r []redirectRow) { t = append(t, r...) }

	// General hostile and accepted rows, no options.
	add(rows(noOptions, false,
		"", "/%09/evil.example", "/\t/evil", "/\n/evil", "/\\evil", "/\\\\evil", "/%5Cevil",
		"https://evil", "//evil", "///evil", "evil",
		"/%2F/evil", // decodes to "//evil"; refused even though a browser keeps it one segment
		"/a\x00b", "/a\x7fb", "javascript:alert(1)", "/%0a/evil.example",
		"/%00", "/%", "/%zz", "/a/\x1f", "//", "/\r/evil", "http://evil.example/",
		"/\v/evil.example", "/\f/evil.example", "/\x7f/evil.example", "/team\t", "/team\x00",
		"//evil.example", `/\evil.example`, "https://evil.example", "https://evil.example/",
		"/a\\b", "/x?\\evil", "/x#\\evil", "/\\evil.example",
		"/%2fevil.example", "/%5cevil.example", "//user:pass@evil", "relative",
		"//evil.example/", `\\evil.example`,
		"%2Fevil", // no leading "/": only step 2's leading-slash check refuses it
		"/%7F",    // decodes to DEL: only the decoded-path check refuses it
		"/\n/evil.example",
	))
	add(rows(noOptions, true,
		"/settings", "/docs/intro?x=1#y", "/", "/..%2f..%2fetc", "/ok?next=//evil",
		"/ /evil", "/path with space", "/ /evil", "/account", "/team", "/login",
		"/oauth/authorize?client_id=c&redirect_uri=http%3A%2F%2Flocalhost%3A1%2Fcb&state=s",
		"/pages/event?draft=1", "/somewhere#heading",
	))

	// Login and logout pages denied (the sign-in form itself must not be a target).
	add(rows(loginDenied, false,
		"", "//evil.example", `/\evil.example`, "https://evil.example", "javascript:alert(1)",
		"/\t/evil.example", "/\r/evil.example", "/%2fevil.example", "/%5cevil.example",
		"/%09/evil.example", "/login?next=//evil", "/logout", "relative", "//user:pass@evil",
		"/login?next=/x", "/login", "/%6cogin", "/loginhistory", "/logout?x=1",
	))
	add(rows(loginDenied, true, "/", "/pages/event?draft=1", "/somewhere#heading", "/team",
		"/oauth/authorize?client_id=c&redirect_uri=http%3A%2F%2Flocalhost%3A1%2Fcb&state=s"))

	// Login and a connect/callback flow denied.
	add(rows(connectorDenied, false,
		"//evil.example", `/\evil.example`, "https://evil.example/x", "javascript:alert(1)",
		"/%2fevil.example", "/%5cevil.example", "/\t/evil.example", "/connector/connect",
		"/connector/callback?code=x", "//user:pass@evil.example", "evil.example",
		"/login?next=//evil", "", "/connector/connect/extra",
	))
	add(rows(connectorDenied, true, "/pages/sample", "/pages/sample?draft=1", "/", "/admin/jobs?status=dead", "/connector"))

	// Admin-prefixed.
	add(rows(adminOnly, false,
		"https://evil.example/admin/", "//evil.example/admin/", "/admin//evil.example",
		"/admin/x/../../evil", "/events", "/admin/x\r\nSet-Cookie: a=b", "javascript:alert(1)",
		"\\\\evil.example", "/not-the-admin", "http://evil.example/admin/", "/admin/\t/x",
		"", "/administrator/", "/admin/%2e%2e/x", "/admin/x\x00", `/admin/\evil`, `\\evil.example`,
		"/admin", "/Admin/x", "/admin/x#\\evil", "/admin//", "/admin/./x", "/admin/..",
	))
	add(rows(adminOnly, true,
		"/admin/reports", "/admin/x?q=1", "/admin/users/12", "/admin/users", "/admin/",
		"/admin/x#frag", "/admin/café", "/admin/x/", "/admin/x?next=//evil",
	))
	return t
}

func TestSafeRedirectTable(t *testing.T) {
	checkRows(t, redirectTable())
}

// Each row names a way a browser reads a URL differently from a byte-wise check.
func TestSafeRedirectBrowserSemantics(t *testing.T) {
	var all []redirectRow
	all = append(all, rows(noOptions, false,
		"/\t/evil.example", // browser strips the tab: "//evil.example"
		"/\v/x", "/\f/x",   // not stripped by browsers, but never legitimate
		"/x#\\evil", "/x?\t",
		"/a/./b", "/a//b", "/a/%2e/b", "/a/%2E%2e/b", "/a/.%2E/b", "/a/%2e./b", "/a/../b",
		"/ok ", "/a/b/ ", // a browser trims the trailing space
	)...)
	all = append(all, rows(noOptions, true,
		"/a/b/",   // a trailing slash is a normal path
		"/ /evil", // a browser percent-encodes the space; the host cannot change
		"/café",   // non-ASCII is encoded by the browser
		"/x#frag", // fragments never reach the server or the host
		"/path with space",
		"/..%2f..%2fetc", // one segment to a browser
		"/%2e%2e%2f",     // a single segment, not a dot segment
		"/a/%2e%2e%2fb",
		"/.hidden", "/a/..b", "/a/b.",
	)...)
	all = append(all, rows(adminOnly, false,
		"/admin/%2e%2e/x", "/admin/.%2E/x", "/admin/x/../../evil", "/admin//evil.example",
		"/admin", // does not begin with "/admin/"
		// Browsers trim a trailing space before parsing, exposing a dot segment.
		"/admin/.. ", "/admin/%2e%2e ", "/admin/%2e ",
		// The prefix is compared on the raw path, and a dot segment is still a
		// dot segment when a query or fragment follows it.
		"/admin%2fx", "/admin%2F..%2Fx", "/admin/..#x", "/admin/%2e%2e#x", "/admin/..?x",
		"https://evil.example/", "//evil.example/",
	)...)
	all = append(all, rows(adminOnly, true, "/admin/")...)
	all = append(all, rows(RedirectOptions{Deny: []string{"/login"}}, false,
		"/%6cogin", "/loginhistory", "/login", "/login/x", "/%6Cogin?x=1",
	)...)
	// A prefix that does not start with "/" matches no path: it fails closed.
	all = append(all, rows(RedirectOptions{Prefix: "admin/"}, false, "/admin/", "/admin/x", "admin/x", "/")...)
	checkRows(t, all)
}

func TestSafeRedirectLengthCap(t *testing.T) {
	ok := "/" + strings.Repeat("a", MaxRedirectLen-1)
	long := ok + "a"
	if len(ok) != 2048 || len(long) != 2049 || MaxRedirectLen != 2048 {
		t.Fatal("test inputs are the wrong size")
	}
	checkRows(t, []redirectRow{
		{noOptions, ok, true}, {noOptions, long, false},
		{noOptions, "/" + strings.Repeat("a", 2047), true},
		{noOptions, "/?" + strings.Repeat("a", 2046), true},
		{noOptions, "/?" + strings.Repeat("a", 2047), false},
		{adminOnly, "/admin/" + strings.Repeat("a", 2041), true},
		{adminOnly, "/admin/" + strings.Repeat("a", 2042), false},
	})
}

// A refusal returns the caller's fallback exactly, even one that would itself
// be hostile: the caller owns that value, SafeRedirect only passes it on.
func TestSafeRedirectFallbackIsVerbatim(t *testing.T) {
	for _, fb := range []string{"", "/", "//evil.example", "https://evil.example", " \t odd\x00 "} {
		if got := SafeRedirect("//evil", RedirectOptions{Fallback: fb}); got != fb {
			t.Errorf("fallback %q came back as %q", fb, got)
		}
		if got := SafeRedirect("/fine", RedirectOptions{Fallback: fb}); got != "/fine" {
			t.Errorf("accepted value replaced by %q", got)
		}
	}
}

// An accepted value is never rewritten: no trimming, decoding or cleaning.
func TestSafeRedirectReturnsAcceptedInputByteIdentical(t *testing.T) {
	for _, in := range []string{"/a%20b?x=%2F#%41", "/inner space/x", "/é/ü?ß=1", "/a/b/", "/%41"} {
		if got := SafeRedirect(in, RedirectOptions{Fallback: fallback}); got != in {
			t.Errorf("SafeRedirect(%q) = %q", in, got)
		}
	}
}

// A well-known web framework's bad-URL vectors (from its test
// suite). All are absolute, scheme-relative, backslash or control-character
// forms; none may be accepted as a same-site path.
func TestSafeRedirectFrameworkBadURLVectors(t *testing.T) {
	vectors := []string{
		"http://example.com",
		"http:///example.com",
		"https://example.com",
		"ftp://example.com",
		`\\example.com`,
		`\\\example.com`,
		`/\\/example.com`,
		`\\//example.com`,
		`/\/example.com`,
		`\/example.com`,
		`/\example.com`,
		`http:/\//example.com`,
		`http:\/example.com`,
		`http:/\example.com`,
		`javascript:alert("XSS")`,
		"\njavascript:alert(x)",
		"java\nscript:alert(x)",
		"\x08//example.com",
		`http://otherserver\@example.com`,
		`http:\\testserver\@example.com`,
		`http://testserver\me:pass@example.com`,
		`http://testserver\@example.com`,
		`http:\\testserver\confirm\me@example.com`,
		"http:999999999",
		"ftp:9999999999",
		"\n",
		"http://[2001:cdba:0000:0000:0000:0000:3257:9652/",
		"http://2001:cdba:0000:0000:0000:0000:3257:9652]/",
	}
	var all []redirectRow
	for _, o := range []RedirectOptions{noOptions, adminOnly, loginDenied} {
		all = append(all, rows(o, false, vectors...)...)
	}
	checkRows(t, all)
}
