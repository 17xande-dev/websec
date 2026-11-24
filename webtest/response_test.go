package webtest

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestResponseAssertions(t *testing.T) {
	for _, tt := range []struct {
		name      string
		status    int
		locations []string
		cookies   []string
		check     func(*Client, *Response)
		wantFail  bool
		wantMsg   string
	}{
		{
			name: "multiple locations", status: 303, locations: []string{"/first", "/second"},
			check: func(_ *Client, r *Response) { r.Location() }, wantFail: true, wantMsg: "multiple Location",
		},
		{
			name: "absent location", status: 200,
			check: func(c *Client, r *Response) {
				if got := r.Location(); got != "" {
					c.t.Errorf("Location = %q; want empty", got)
				}
			},
		},
		{
			name: "status matches", status: 201,
			check: func(_ *Client, r *Response) { r.WantStatus(201) },
		},
		{
			name: "wrong status", status: 200,
			check: func(_ *Client, r *Response) { r.WantStatus(204) }, wantFail: true,
			wantMsg: `POST /items?q=1: status 200, body "response note": want status 204`,
		},
		{
			name: "redirect matches raw location", status: 303, locations: []string{"/\t/final"},
			check: func(_ *Client, r *Response) { r.WantRedirect(303, "/\t/final") },
		},
		{
			name: "wrong location", status: 303, locations: []string{"/first"},
			check: func(_ *Client, r *Response) { r.WantRedirect(303, "/second") }, wantFail: true,
			wantMsg: `POST /items?q=1: status 303, body "response note": Location "/first"; want status 303 and Location "/second"`,
		},
		{
			name: "raw locations differ", status: 303, locations: []string{"/\t/final"},
			check: func(_ *Client, r *Response) { r.WantRedirect(303, "//final") }, wantFail: true,
			wantMsg: `Location "/\t/final"; want status 303 and Location "//final"`,
		},
		{
			name: "right location on wrong status", status: 200, locations: []string{"/final"},
			check: func(_ *Client, r *Response) { r.WantRedirect(303, "/final") }, wantFail: true,
			wantMsg: `status 200, body "response note": Location "/final"; want status 303`,
		},
		{
			name: "named cookie", status: 200, cookies: []string{"unrelated=other", "__Host-marker=one; Path=/; Secure"},
			check: func(c *Client, r *Response) {
				if ck := r.SetCookie("__Host-marker"); ck.Name != "__Host-marker" || ck.Value != "one" || !ck.Secure || ck.Path != "/" {
					c.t.Errorf("unexpected cookie: %+v", ck)
				}
			},
		},
		{
			name: "cookie absent from this response", status: 200, cookies: []string{"unrelated=other"},
			check: func(c *Client, r *Response) {
				c.SetCookie(&http.Cookie{Name: "marker", Value: "seeded"})
				r.SetCookie("marker")
			}, wantFail: true, wantMsg: `no Set-Cookie named "marker"`,
		},
		{
			name: "duplicate cookie name", status: 200, cookies: []string{"marker=one; Path=/", "marker=two; Path=/area"},
			check: func(_ *Client, r *Response) { r.SetCookie("marker") }, wantFail: true,
			wantMsg: `multiple Set-Cookie values named "marker"`,
		},
		{
			name: "follow non-redirect", status: 200, locations: []string{"/final"},
			check: func(c *Client, r *Response) { c.Follow(r) }, wantFail: true,
			wantMsg: "cannot follow a non-3xx response",
		},
		{
			name: "follow without location", status: 303,
			check: func(c *Client, r *Response) { c.Follow(r) }, wantFail: true,
			wantMsg: "cannot follow without a Location",
		},
		{
			name: "follow unparseable location", status: 303, locations: []string{"/\t/final"},
			check: func(c *Client, r *Response) { c.Follow(r) }, wantFail: true,
			wantMsg: "assert on Location() instead",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, loc := range tt.locations {
					w.Header().Add("Location", loc)
				}
				for _, ck := range tt.cookies {
					w.Header().Add("Set-Cookie", ck)
				}
				w.WriteHeader(tt.status)
				io.WriteString(w, "response note")
			})
			checkFailure(t, func(t testing.TB) {
				c := New(t, h, testOrigin)
				tt.check(c, c.PostForm("/items?q=1", nil))
			}, tt.wantFail, tt.wantMsg)
		})
	}
}

func TestStatusBodyExcerpt(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("a", 300)+"omitted")
	})
	r := recordFailure(t, func(t testing.TB) {
		New(t, h, testOrigin).Get("/").WantStatus(303)
	})
	if got := strings.Join(r.messages, "\n"); !r.Failed() ||
		!strings.Contains(got, `body "`+strings.Repeat("a", 300)+`"`) || strings.Contains(got, "omitted") {
		t.Errorf("want a failed assertion with a 300-byte body excerpt, got %q", got)
	}
}
