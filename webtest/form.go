package webtest

import (
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

const formURLEncoded = "application/x-www-form-urlencoded"

// Form holds the URL-encoded values for one form and the page it came from.
type Form struct {
	response                *Response
	action, method, enctype string
	values                  url.Values
	password                bool
}

func (f *Form) copy() *Form {
	out := *f
	out.values = f.Values()
	return &out
}

// Values returns a copy of the current submission values, including defaults
// from the page and any changes made with Set or Delete.
func (f *Form) Values() url.Values {
	v := maps.Clone(f.values)
	for name, values := range v {
		v[name] = slices.Clone(values)
	}
	return v
}

// Set replaces all values for name and returns f.
func (f *Form) Set(name string, values ...string) *Form {
	f.values[name] = slices.Clone(values)
	return f
}

// Delete removes all values for name and returns f.
func (f *Form) Delete(name string) *Form {
	f.values.Del(name)
	return f
}

// Submit sends the form's values to its action, relative to the page URL.
// The default action is the page itself and the default method is GET.
// Only URL-encoded submissions are supported.
func (f *Form) Submit(opts ...Option) *Response {
	r := f.response
	r.t.Helper()
	if f.enctype != "" && !strings.EqualFold(f.enctype, formURLEncoded) {
		r.t.Fatalf("%s: unsupported form enctype %q; build the body and use Do", r.summary(), f.enctype)
	}
	target, err := r.Request.URL.Parse(f.action)
	if err != nil {
		r.t.Fatalf("%s: invalid form action %q: %v", r.summary(), f.action, err)
	}
	method := strings.ToUpper(f.method)
	if method == "" {
		method = http.MethodGet
	}
	encoded := f.values.Encode()
	var body io.Reader
	if method == http.MethodGet {
		// A GET submission replaces the action's query with the form data.
		target.RawQuery, target.ForceQuery = encoded, false
	} else {
		body = strings.NewReader(encoded)
	}
	req := r.client.NewRequest(method, target.String(), body)
	if body != nil {
		req.Header.Set("Content-Type", formURLEncoded)
	}
	return r.client.Do(req, opts...)
}
