package websec

import (
	"net/url"
	"strings"
)

// MaxRedirectLen is the longest next value SafeRedirect accepts, in bytes.
// Anything longer is refused: a redirect target is a page link, not a payload,
// and an unbounded one ends up in a Location header and in logs.
const MaxRedirectLen = 2048

// RedirectOptions configures SafeRedirect. The zero value accepts any
// same-site path and falls back to the empty string.
type RedirectOptions struct {
	// Prefix, if set, must begin the raw path (for example "/admin/"). A prefix
	// that does not start with "/" can never match a path and so refuses
	// everything: a misconfiguration fails closed rather than open.
	Prefix string

	// Deny lists path prefixes that are refused. Each is matched as a plain
	// string prefix against the decoded path, so "/login" also refuses
	// "/loginhistory" and "/%6cogin". Include a trailing slash to be narrower.
	Deny []string

	// Fallback is returned verbatim when next is refused. It is not validated;
	// pass a constant you trust.
	Fallback string
}

// SafeRedirect returns next unchanged when it is a safe same-site redirect
// target under o's rules, and o.Fallback otherwise. It never rewrites next: a
// value is either accepted exactly as given or refused, so there is no
// "cleaned" form for a second parser to disagree about.
//
// The usual use is a ?next= value carried through a sign-in form. An open
// redirect there is a ready-made phishing step, and validators written as a
// prefix check have repeatedly shipped bypasses because a browser does not read
// a URL the way a byte-wise check does. Each step below names the browser
// behaviour or the attack it answers:
//
//  1. Empty or longer than [MaxRedirectLen]: nothing to redirect to, or a
//     payload rather than a link.
//  2. The raw string must start with a single "/" (a "//" start is a
//     scheme-relative URL naming another host), must not end in a space, and
//     must contain no byte below 0x20, no DEL and no backslash anywhere. A
//     trailing space is trimmed by browsers before parsing, so it can hide a
//     dot segment: "/admin/%2e%2e " is "/admin/%2e%2e" to a browser and escapes
//     the prefix. Browsers also strip TAB, LF and CR from any position in a
//     URL, so "/\t/evil.example" becomes "//evil.example"; they read "\" as
//     "/" in the path of an http(s) URL, so "/\evil" becomes "//evil" (it is
//     refused everywhere, for simplicity); and the other controls are never
//     legitimate.
//  3. url.Parse must succeed with no scheme, host, user info or opaque part.
//     This refuses "https://x", "javascript:x" and malformed escapes like
//     "/%zz".
//  4. The decoded path must again start with "/" but not "//", and contain no
//     control byte or backslash. This refuses "/%2F/evil", "/%5cevil" and
//     "/%09/x", which a lenient consumer further down the line might decode
//     and then act on.
//  5. The raw path (the part before the first "?" or "#") must be canonical as
//     a browser sees it: no empty segment (a canonical path keeps the
//     Prefix check meaningful, and no legitimate target needs "/a//b"), and no "." or
//     ".." segment, including the "%2e" spellings, which the WHATWG URL parser
//     treats as dots. A trailing slash is allowed, and "/..%2f..%2fetc" is one
//     ordinary segment to a browser, so it is accepted.
//  6. If o.Prefix is set, the raw path must begin with it. Checking the raw
//     path, after step 5, means the prefix cannot be satisfied and then left
//     by dot segments.
//  7. No o.Deny entry may be a prefix of the decoded path, so a login page
//     cannot be bounced back to itself under an encoded spelling.
//  8. Otherwise next is returned as given. Query, fragment, spaces and
//     non-ASCII text are all allowed: none of them can change the host.
func SafeRedirect(next string, o RedirectOptions) string {
	// Step 1.
	if next == "" || len(next) > MaxRedirectLen {
		return o.Fallback
	}

	// Step 2. A trailing space is refused because browsers trim leading and
	// trailing C0 controls and space from the whole URL before parsing, so it
	// can hide a dot segment ("/admin/%2e%2e " becomes "/admin/%2e%2e" and
	// escapes the Prefix); a leading one is impossible, next must start with "/".
	if next[0] != '/' || strings.HasPrefix(next, "//") || next[len(next)-1] == ' ' || hasUnsafeByte(next) {
		return o.Fallback
	}

	// Step 3.
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return o.Fallback
	}

	// Step 4.
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || hasUnsafeByte(u.Path) {
		return o.Fallback
	}

	// Step 5.
	rawPath := next
	if i := strings.IndexAny(rawPath, "?#"); i >= 0 {
		rawPath = rawPath[:i]
	}
	if !canonicalPath(rawPath) {
		return o.Fallback
	}

	// Step 6.
	if o.Prefix != "" && !strings.HasPrefix(rawPath, o.Prefix) {
		return o.Fallback
	}

	// Step 7.
	for _, d := range o.Deny {
		if strings.HasPrefix(u.Path, d) {
			return o.Fallback
		}
	}

	// Step 8.
	return next
}

// hasUnsafeByte reports whether s contains a byte below 0x20, DEL or a
// backslash: the bytes a browser strips or rewrites inside a URL.
func hasUnsafeByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f || c == '\\' {
			return true
		}
	}
	return false
}

// canonicalPath reports whether the raw path p (which starts with "/") has no
// empty segment and no dot segment, counting "%2e" spellings. One trailing
// empty segment (a trailing slash) is allowed.
func canonicalPath(p string) bool {
	segs := strings.Split(p[1:], "/")
	if segs[len(segs)-1] == "" {
		segs = segs[:len(segs)-1]
	}
	for _, s := range segs {
		switch strings.ToLower(s) {
		case "", ".", "%2e", "..", ".%2e", "%2e.", "%2e%2e":
			return false
		}
	}
	return true
}
