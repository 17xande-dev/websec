package webtest

import "strings"

// HostileRedirects returns a fresh slice of targets a strict same-site
// redirect check should refuse. Some navigate off-site; others stay on-site
// in a browser but are noncanonical or can change meaning after decoding.
// Compare the response Location to a literal fallback rather than trying to
// interpret it with Go's URL parser.
func HostileRedirects() []string {
	return []string{
		"//evil.example",                // Inherits the scheme, replaces the host.
		"///evil.example",               // Extra initial slashes are skipped before the host.
		"https://evil.example",          // Absolute URL on another host.
		"/\t/evil.example",              // TAB is removed, exposing the second slash.
		"/\n/evil.example",              // LF is removed, exposing the second slash.
		"/\r/evil.example",              // CR is removed, exposing the second slash.
		`/\evil.example`,                // Backslash is a slash in an HTTP(S) URL.
		`\\evil.example`,                // Two backslashes likewise introduce a host.
		"/%2fevil.example",              // Encoded slash stays in the path unless decoded first.
		"/%5cevil.example",              // Encoded backslash stays in the path unless decoded first.
		"/%09/evil.example",             // Encoded TAB stays in the path unless decoded first.
		"/%0a/evil.example",             // Encoded LF stays in the path unless decoded first.
		"/\x00x",                        // Interior NUL is escaped in the path, not a host separator.
		"/%00",                          // Encoded NUL stays in the path, not canonical input.
		"/admin/%2e%2e/x",               // Normalizes to /x, outside /admin/.
		"/admin/%2e%2e ",                // Trims the space, then normalizes to /.
		"/" + strings.Repeat("a", 2048), // Same-site path, but over the policy's length cap.
	}
}
