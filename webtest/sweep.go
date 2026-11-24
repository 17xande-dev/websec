package webtest

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// MinCount fails when got is below min or min is less than one.
func MinCount(t testing.TB, what string, got, min int) {
	t.Helper()
	if min < 1 {
		t.Fatalf("%s: minimum count must be at least 1; got %d", what, min)
	}
	if got < min {
		t.Fatalf("%s: got %d; want at least %d", what, got, min)
	}
}

// Route describes one concrete request to a registered route. Routes are
// protected by default; deliberately public routes must give a reason.
type Route struct {
	Method  string // required
	Path    string // concrete request path, without wildcards
	Pattern string // optional registered pattern, for diagnostics
	Public  bool   // log instead of requesting
	Why     string // required when Public is true
}

// Routes turns registered "METHOD /path" patterns into protected routes.
// Methods must be uppercase HTTP tokens. It fills {name} as one path segment
// and {name...} as a slash-separated tail, escaping each segment. The end
// marker {$} needs no fill value.
func Routes(t testing.TB, patterns []string, fill map[string]string) []Route {
	t.Helper()
	routes := make([]Route, 0, len(patterns))
	for _, pattern := range patterns {
		fields := strings.Fields(pattern)
		if len(fields) != 2 {
			t.Fatalf("route %q: want METHOD /path", pattern)
		}
		if strings.ContainsFunc(fields[0], func(r rune) bool {
			return !('A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r))
		}) {
			t.Fatalf("route %q: invalid method %q; want an uppercase HTTP token", pattern, fields[0])
		}
		if !strings.HasPrefix(fields[1], "/") {
			t.Fatalf("route %q: host patterns are not supported; want METHOD /path", pattern)
		}
		segments := strings.Split(fields[1], "/")
		for i, segment := range segments {
			if !strings.ContainsAny(segment, "{}") {
				continue
			}
			if len(segment) < 3 || segment[0] != '{' || segment[len(segment)-1] != '}' ||
				strings.ContainsAny(segment[1:len(segment)-1], "{}") {
				t.Fatalf("route %q: invalid wildcard %q", pattern, segment)
			}
			name := segment[1 : len(segment)-1]
			if name == "$" && i == len(segments)-1 {
				segments[i] = ""
				continue
			}
			name, tail := strings.CutSuffix(name, "...")
			value, ok := fill[name]
			if !ok {
				t.Fatalf("route %q: no fill for wildcard %q", pattern, name)
			}
			if tail {
				parts := strings.Split(value, "/")
				for j := range parts {
					parts[j] = url.PathEscape(parts[j])
				}
				segments[i] = strings.Join(parts, "/")
			} else {
				segments[i] = url.PathEscape(value)
			}
		}
		routes = append(routes, Route{Method: fields[0], Path: strings.Join(segments, "/"), Pattern: pattern})
	}
	return routes
}

// Sweep checks that every protected route refuses an anonymous request.
type Sweep struct {
	Routes    []Route
	Min       int                          // minimum number of protected routes
	Client    func() *Client               // fresh anonymous client for each attempt
	TokenPage string                       // fetch a token for unsafe requests
	NoToken   bool                         // explicitly skip token fetching, e.g. when session checks run first
	Form      url.Values                   // extra fields for unsafe requests
	Cookies   []*http.Cookie               // try each cookie separately; the jar must send it to the base URL
	Refused   func(Route, *Response) error // required app-specific refusal check
}

// Run requests every protected route and returns how many it swept. It
// rejects 2xx, 404, 405 and 5xx before consulting Refused.
func (s Sweep) Run(t testing.TB) int {
	t.Helper()
	if (s.TokenPage != "") == s.NoToken {
		t.Fatal("route sweep: set exactly one of TokenPage or NoToken")
	}
	if s.Client == nil {
		t.Fatal("route sweep: Client is required")
	}
	if s.Refused == nil {
		t.Fatal("route sweep: Refused is required")
	}
	for i, ck := range s.Cookies {
		if ck == nil {
			t.Fatalf("route sweep: Cookies[%d] is nil", i)
		}
	}

	type key struct{ method, path string }
	seen := make(map[key]Route, len(s.Routes))
	protected := 0
	for _, route := range s.Routes {
		if route.Method == "" {
			t.Fatalf("route %q: Method is required", route.name())
		}
		if strings.ContainsAny(route.Path, "{}") {
			t.Fatalf("route %q: path %q contains a wildcard; use a concrete path", route.name(), route.Path)
		}
		u, err := url.ParseRequestURI(route.Path)
		if err != nil || u.IsAbs() || !strings.HasPrefix(route.Path, "/") || strings.HasPrefix(route.Path, "//") {
			t.Fatalf("route %q: path %q must be a concrete site-relative path", route.name(), route.Path)
		}
		k := key{route.Method, u.RequestURI()}
		if first, ok := seen[k]; ok {
			t.Fatalf("route %q: duplicate route (%q)", route.name(), first.name())
		}
		seen[k] = route
		if route.Public {
			if strings.TrimSpace(route.Why) == "" {
				t.Fatalf("route %q: state why this route is deliberately public", route.name())
			}
			t.Logf("public route %q: %s", route.name(), route.Why)
			continue
		}
		protected++
	}
	MinCount(t, "protected routes", protected, s.Min)

	for _, route := range s.Routes {
		if route.Public {
			continue
		}
		s.attempt(t, route, nil)
		for _, ck := range s.Cookies {
			s.attempt(t, route, ck)
		}
	}
	return protected
}

func (s Sweep) attempt(t testing.TB, route Route, ck *http.Cookie) {
	t.Helper()
	label := fmt.Sprintf("route %q", route.name())
	c := s.Client()
	if c == nil {
		t.Fatalf("%s: Client returned nil", label)
	}
	if ck != nil {
		// Report the scenario without reporting the cookie value.
		label += fmt.Sprintf(" with cookie %q", ck.Name)
		c.SetCookie(ck)
	}
	var r *Response
	switch route.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		r = c.Do(c.NewRequest(route.Method, route.Path, nil))
	default:
		fields := make(url.Values, len(s.Form)+1)
		maps.Copy(fields, s.Form)
		if s.TokenPage != "" {
			fields.Set(TokenField, c.Page(s.TokenPage).Token())
		}
		req := c.NewRequest(route.Method, route.Path, strings.NewReader(fields.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = c.Do(req)
	}
	switch {
	case r.Status >= 200 && r.Status < 300,
		r.Status == http.StatusNotFound,
		r.Status == http.StatusMethodNotAllowed,
		r.Status >= 500 && r.Status < 600:
		t.Errorf("%s: %s: not a refusal", label, r.summary())
	default:
		if err := s.Refused(route, r); err != nil {
			t.Errorf("%s: %s: %v", label, r.summary(), err)
		}
	}
}

func (r Route) name() string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return r.Method + " " + r.Path
}

// RedirectsTo requires a 303 and exactly one raw Location starting with prefix.
// Like Response.Location, it uses the canonical Location header key.
func RedirectsTo(prefix string) func(Route, *Response) error {
	return func(_ Route, r *Response) error {
		locations := r.Header.Values("Location")
		if r.Status != http.StatusSeeOther || len(locations) != 1 || locations[0] == "" || !strings.HasPrefix(locations[0], prefix) {
			return fmt.Errorf("want 303 with one Location starting with %q; got status %d and Location values %q",
				prefix, r.Status, locations)
		}
		return nil
	}
}

// Status requires the given refusal status.
func Status(code int) func(Route, *Response) error {
	return func(_ Route, r *Response) error {
		if r.Status != code {
			return fmt.Errorf("want status %d; got %d", code, r.Status)
		}
		return nil
	}
}

// ByMethod applies safe to GET and HEAD routes and unsafe to all others,
// including OPTIONS and TRACE. Sweep still sends no token on OPTIONS or TRACE.
func ByMethod(safe, unsafe func(Route, *Response) error) func(Route, *Response) error {
	return func(route Route, r *Response) error {
		check := unsafe
		if route.Method == http.MethodGet || route.Method == http.MethodHead {
			check = safe
		}
		if check == nil {
			return fmt.Errorf("no refusal check for method %q", route.Method)
		}
		return check(route, r)
	}
}
