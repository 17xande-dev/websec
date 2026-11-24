package webtest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestMinCount(t *testing.T) {
	for _, tt := range []struct {
		name     string
		got, min int
		wantMsg  string
	}{
		{"empty", 0, 1, "items: got 0; want at least 1"},
		{"zero floor", 3, 0, "items: minimum count must be at least 1; got 0"},
		{"negative floor", 3, -1, "items: minimum count must be at least 1; got -1"},
		{"equality", 3, 3, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checkFailure(t, func(t testing.TB) {
				MinCount(t, "items", tt.got, tt.min)
			}, tt.wantMsg != "", tt.wantMsg)
		})
	}
}

func TestRoutes(t *testing.T) {
	patterns := []string{"GET /items/{id}", "POST /files/{tail...}", "HEAD /{$}", "GET /items/{$}", "PATCH /item"}
	routes := Routes(t, patterns, map[string]string{"id": "a/b", "tail": "a b/c#d"})
	want := []Route{
		{Method: "GET", Path: "/items/a%2Fb", Pattern: patterns[0]},
		{Method: "POST", Path: "/files/a%20b/c%23d", Pattern: patterns[1]},
		{Method: "HEAD", Path: "/", Pattern: patterns[2]},
		{Method: "GET", Path: "/items/", Pattern: patterns[3]},
		{Method: "PATCH", Path: "/item", Pattern: patterns[4]},
	}
	if !slices.Equal(routes, want) {
		t.Errorf("Routes = %+v; want %+v", routes, want)
	}

	// Ensure the concrete paths actually hit the registered patterns.
	mux := http.NewServeMux()
	for _, pattern := range patterns {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Pattern", r.Pattern)
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	c := New(t, mux, testOrigin)
	for _, route := range routes {
		r := c.Do(c.NewRequest(route.Method, route.Path, nil))
		r.WantStatus(http.StatusUnauthorized)
		if got := r.Header.Get("X-Pattern"); got != route.Pattern {
			t.Errorf("%s %s matched %q; want %q", route.Method, route.Path, got, route.Pattern)
		}
	}
}

func TestRoutesFailures(t *testing.T) {
	for _, tt := range []struct {
		name, pattern, wantMsg string
	}{
		{"no method", "/items/{id}", `route "/items/{id}": want METHOD /path`},
		{"missing fill", "GET /items/{id}", `no fill for wildcard "id"`},
		{"missing tail fill", "GET /files/{tail...}", `no fill for wildcard "tail"`},
		{"host pattern", "GET app.example/items", "host patterns are not supported"},
		{"malformed wildcard", "GET /items/prefix{id}", `invalid wildcard "prefix{id}"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checkFailure(t, func(t testing.TB) {
				Routes(t, []string{tt.pattern}, nil)
			}, true, tt.wantMsg)
		})
	}
}

func TestSweepUsesDeclaredMethodsAndFreshClients(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "proof", Value: "bound", Path: "/"})
		fmt.Fprint(w, "fixture-token")
	})
	mux.HandleFunc("GET /items", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login?next=/items")
		w.WriteHeader(http.StatusSeeOther)
	})
	mux.HandleFunc("PATCH /items/{id}", func(w http.ResponseWriter, r *http.Request) {
		proof, err := r.Cookie("proof")
		if err != nil || proof.Value != "bound" || r.PostFormValue("csrf_token") != "fixture-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.PathValue("id") != "1" || r.PostFormValue("title") != "sample" ||
			r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /about", func(w http.ResponseWriter, r *http.Request) {
		t.Error("public route was requested")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	form := url.Values{"title": {"sample"}, "csrf_token": {"unchanged"}}
	var attempts, tokenPages int
	rec := recordFailure(t, func(tb testing.TB) {
		routes := Routes(tb, []string{"GET /items", "PATCH /items/{id}"}, map[string]string{"id": "1"})
		s := Sweep{
			Routes: append(routes, Route{Method: "GET", Path: "/about", Public: true, Why: "public information"}),
			Min:    2,
			Client: func() *Client {
				attempts++
				return NewServer(tb, srv)
			},
			TokenPage: "/login",
			Form:      form,
			Cookies:   []*http.Cookie{{Name: "session", Value: "made-up"}},
			Refused:   ByMethod(RedirectsTo("/login?next="), Status(http.StatusUnauthorized)),
			token: func(c *Client, path string) string {
				tokenPages++
				if _, ok := c.Cookie("proof"); ok {
					tb.Error("client already carries a token-page cookie")
				}
				page := c.Get(path)
				page.WantStatus(http.StatusOK)
				return page.Body
			},
		}
		if got := s.Run(tb); got != 2 {
			tb.Errorf("swept %d routes; want 2", got)
		}
	})
	if rec.Failed() || attempts != 4 || tokenPages != 2 ||
		!slices.Equal(rec.logs, []string{`public route "GET /about": public information`}) ||
		form.Get("csrf_token") != "unchanged" {
		t.Errorf("failures = %q, attempts = %d, token pages = %d, logs = %q, form token = %q",
			rec.messages, attempts, tokenPages, rec.logs, form.Get("csrf_token"))
	}
}

func TestSweepPreflightFailures(t *testing.T) {
	for _, tt := range []struct {
		name    string
		setup   func(*Sweep)
		wantMsg string
	}{
		{"zero routes", func(s *Sweep) { s.Routes = nil }, "protected routes: got 0; want at least 1"},
		{"below floor", func(s *Sweep) { s.Min = 2 }, "protected routes: got 1; want at least 2"},
		{"zero floor", func(s *Sweep) { s.Min = 0 }, "minimum count must be at least 1"},
		{"public does not count", func(s *Sweep) {
			s.Routes[0].Public, s.Routes[0].Why = true, "public information"
		}, "protected routes: got 0; want at least 1"},
		{"public without reason", func(s *Sweep) {
			s.Routes[0].Public = true
			s.Routes = append(s.Routes, Route{Method: "GET", Path: "/other"})
		}, `route "GET /items": state why this route is deliberately public`},
		{"empty method", func(s *Sweep) {
			s.Routes[0].Method, s.Routes[0].Pattern = "", "named items route"
		}, `route "named items route": Method is required`},
		{"duplicate", func(s *Sweep) {
			s.Routes = append(s.Routes, Route{Method: "GET", Path: "/items", Pattern: "second items route"})
		}, `route "second items route": duplicate route ("GET /items")`},
		{"wildcard", func(s *Sweep) { s.Routes[0].Path = "/items/{id}" }, "contains a wildcard"},
		{"external path", func(s *Sweep) { s.Routes[0].Path = "//other.example/items" }, "must be a concrete site-relative path"},
		{"no token policy", func(s *Sweep) { s.NoToken = false }, "set exactly one of TokenPage or NoToken"},
		{"both token policies", func(s *Sweep) { s.TokenPage = "/login" }, "set exactly one of TokenPage or NoToken"},
		{"nil Refused", func(s *Sweep) { s.Refused = nil }, "Refused is required"},
		{"nil Client", func(s *Sweep) { s.Client = nil }, "Client is required"},
		{"nil cookie", func(s *Sweep) { s.Cookies = []*http.Cookie{nil} }, "Cookies[0] is nil"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			attempts := 0
			checkFailure(t, func(tb testing.TB) {
				s := Sweep{
					Routes:  []Route{{Method: "GET", Path: "/items"}},
					Min:     1,
					NoToken: true,
					Client: func() *Client {
						attempts++
						h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
							w.WriteHeader(http.StatusUnauthorized)
						})
						return New(tb, h, testOrigin)
					},
					Refused: Status(http.StatusUnauthorized),
				}
				tt.setup(&s)
				s.Run(tb)
			}, true, tt.wantMsg)
			if attempts != 0 {
				t.Errorf("invalid configuration made %d attempts; want none", attempts)
			}
		})
	}
}

func TestSweepRejectsNonRefusals(t *testing.T) {
	for _, tt := range []struct {
		name       string
		registered string
		status     int
	}{
		{"unprotected 200", "GET /items", 200},
		{"unprotected 299", "GET /items", 299},
		{"missing route 404", "GET /other", 404},
		{"get to post route 405", "POST /items", 405},
		{"server error 500", "GET /items", 500},
		{"server error 599", "GET /items", 599},
	} {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc(tt.registered, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			})
			calls := 0
			checkFailure(t, func(tb testing.TB) {
				Sweep{
					Routes:  []Route{{Method: "GET", Path: "/items", Pattern: "named items route"}},
					Min:     1,
					Client:  func() *Client { return New(tb, mux, testOrigin) },
					NoToken: true,
					Refused: func(Route, *Response) error { calls++; return nil },
				}.Run(tb)
			}, true, fmt.Sprintf(`route "named items route": GET /items: status %d`, tt.status))
			if calls != 0 {
				t.Errorf("Refused called %d times for a built-in failure", calls)
			}
		})
	}
}

func TestSweepReportsEveryFailedRoute(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /items", func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("csrf_token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusSeeOther)
	})
	mux.HandleFunc("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("session"); err == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusSeeOther)
	})
	rec := recordFailure(t, func(tb testing.TB) {
		Sweep{
			Routes:  Routes(tb, []string{"POST /items", "GET /settings"}, nil),
			Min:     2,
			Client:  func() *Client { return New(tb, mux, testOrigin) },
			NoToken: true,
			Cookies: []*http.Cookie{{Name: "session", Value: "made-up"}},
			Refused: RedirectsTo("/login"),
		}.Run(tb)
	})
	if !rec.Failed() || len(rec.messages) != 3 ||
		!strings.Contains(rec.messages[0], `route "POST /items": POST /items: status 403`) ||
		!strings.Contains(rec.messages[1], `route "POST /items" with cookie "session": POST /items: status 403`) ||
		!strings.Contains(rec.messages[2], `route "GET /settings" with cookie "session": GET /settings: status 200`) {
		t.Errorf("failed = %v, messages = %q; want 403 failures and a 200 only with a cookie", rec.Failed(), rec.messages)
	}
}

func TestRefusalChecks(t *testing.T) {
	for _, tt := range []struct {
		name, method string
		status       int
		locations    []string
		check        func(Route, *Response) error
		wantMsg      string
	}{
		{"raw prefix", "GET", 303, []string{"/login?\tnext="}, RedirectsTo("/login?\t"), ""},
		{"wrong redirect status", "GET", 302, []string{"/login"}, RedirectsTo("/login"), "got status 302"},
		{"wrong prefix", "GET", 303, []string{"/other"}, RedirectsTo("/login"), `Location values ["/other"]`},
		{"absent Location", "GET", 303, nil, RedirectsTo("/login"), "Location values []"},
		{"multiple Locations", "GET", 303, []string{"/login", "/other"}, RedirectsTo("/login"), `Location values ["/login" "/other"]`},
		{"wrong status", "POST", 403, nil, Status(401), "want status 401; got 403"},
		{"head uses safe", "HEAD", 401, nil, ByMethod(Status(403), Status(401)), "want status 403; got 401"},
		{"options uses other", "OPTIONS", 401, nil, ByMethod(Status(401), Status(403)), "want status 403; got 401"},
		{"missing check", "GET", 401, nil, ByMethod(nil, Status(401)), `no refusal check for method "GET"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for _, value := range tt.locations {
					w.Header().Add("Location", value)
				}
				w.WriteHeader(tt.status)
			})
			checkFailure(t, func(tb testing.TB) {
				Sweep{
					Routes:  []Route{{Method: tt.method, Path: "/items"}},
					Min:     1,
					NoToken: true,
					Client:  func() *Client { return New(tb, h, testOrigin) },
					Refused: tt.check,
				}.Run(tb)
			}, tt.wantMsg != "", tt.wantMsg)
		})
	}
}
