package webtest

import (
	"net/http"
	"net/url"
)

// SignIn loads page, fills its only password form with fields over the form's
// defaults, and submits it with the page's CSRF token. It requires status 303
// and at least one Set-Cookie. The caller can assert the redirect target.
func (c *Client) SignIn(page string, fields url.Values) *Response {
	c.t.Helper()
	p := c.Page(page)
	var found *Form
	var matches int
	for _, f := range p.forms {
		if f.password {
			found = f
			matches++
		}
	}
	if matches != 1 {
		c.t.Fatalf("%s: found %d password forms (%d forms found); want one", p.response.summary(), matches, len(p.forms))
	}
	f := found.copy()
	for name, values := range fields {
		f.Set(name, values...)
	}
	r := f.Set(TokenField, p.Token()).Submit()
	r.WantStatus(http.StatusSeeOther)
	res := http.Response{Header: r.Header}
	if len(res.Cookies()) == 0 {
		c.t.Fatalf("%s: sign-in did not set a cookie (want at least one valid Set-Cookie)", r.summary())
	}
	return r
}
