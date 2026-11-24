// Package webtest provides HTTP integration-test helpers. Import it only
// from _test.go files.
//
// New runs a handler in-process, preserving what it wrote and making body
// read counts exact. NewServer uses a real connection to an httptest server.
// Both clients keep cookies and send Origin on unsafe requests. Neither
// follows redirects, so tests can assert the literal Location. Use Raw
// when the standard HTTP reader would reject bytes on the wire.
//
// The probes also check temporary-file leftovers and captured logs. Use
// literal expectations rather than deriving them from the code under test.
package webtest

// TokenField is the name of the form field used for request-forgery tokens.
const TokenField = "csrf_token"
