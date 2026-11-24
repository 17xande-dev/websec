package webtest_test

import (
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/17xande-dev/websec/csrf"
	"github.com/17xande-dev/websec/webtest"
)

const fixtureOrigin = "https://app.example"
const fixtureSession = "__Host-session"

func TestSweepWithCSRF(t *testing.T) {
	for _, mode := range []string{"in-process", "HTTP server", "TLS server"} {
		t.Run(mode, func(t *testing.T) {
			var fresh func() *webtest.Client
			if mode == "in-process" {
				app := csrfFixture(t, fixtureOrigin, false)
				fresh = func() *webtest.Client { return webtest.New(t, app, fixtureOrigin) }
			} else {
				srv := httptest.NewUnstartedServer(nil)
				t.Cleanup(srv.Close)
				if mode == "TLS server" {
					srv.Config.Handler = csrfFixture(t, "https://"+srv.Listener.Addr().String(), false)
					srv.StartTLS()
				} else {
					srv.Config.Handler = csrfFixture(t, "http://"+srv.Listener.Addr().String(), true)
					srv.Start()
				}
				fresh = func() *webtest.Client { return webtest.NewServer(t, srv) }
			}

			refused := webtest.ByMethod(webtest.RedirectsTo("/login?next="), webtest.Status(http.StatusUnauthorized))
			var cookieAttempts int
			n := (webtest.Sweep{
				Routes:    webtest.Routes(t, []string{"GET /admin", "POST /admin/items/{id}/delete"}, map[string]string{"id": "1"}),
				Min:       2,
				Client:    fresh,
				TokenPage: "/login",
				Cookies:   []*http.Cookie{{Name: fixtureSession, Value: "made-up", Path: "/", Secure: true}},
				Refused: func(route webtest.Route, r *webtest.Response) error {
					if r.Header.Get("X-Fixture-Cookie") == "present" {
						cookieAttempts++
					}
					return refused(route, r)
				},
			}).Run(t)
			if n != 2 || cookieAttempts != 2 {
				t.Errorf("swept %d routes with %d made-up cookie attempts; want 2 of each", n, cookieAttempts)
			}
			checkFixtureSignIn(t, fresh())
		})
	}
}

func TestWrongOriginRefused(t *testing.T) {
	app := csrfFixture(t, fixtureOrigin, false)
	for _, tt := range []struct {
		name     string
		defaults []webtest.Option
		opts     []webtest.Option
		want     int
	}{
		{"wrong origin", []webtest.Option{webtest.WithOrigin("https://other.example")}, nil, http.StatusForbidden},
		{"matching origin", nil, nil, http.StatusUnauthorized},
		{"explicit fetch metadata takes precedence", []webtest.Option{webtest.WithOrigin("https://other.example")}, []webtest.Option{webtest.SecFetchSite("same-origin")}, http.StatusUnauthorized},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := webtest.New(t, app, fixtureOrigin, tt.defaults...)
			token := c.Page("/login").Token()
			c.PostForm("/admin/items/1/delete", url.Values{"csrf_token": {token}}, tt.opts...).WantStatus(tt.want)
		})
	}
}

func csrfFixture(t *testing.T, origin string, insecure bool) http.Handler {
	t.Helper()
	p, err := csrf.New(csrf.Config{Origin: origin, Insecure: insecure, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	login := template.Must(template.New("login").Parse(`<form action="/login" method="post">
		<input type="hidden" name="csrf_token" value="{{.}}">
		<input type="password" name="password">
	</form>`))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		if err := login.Execute(w, csrf.Token(r)); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("password") != "fixture-password" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: fixtureSession, Value: "signed-in", Path: "/", Secure: true, HttpOnly: true})
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	})
	protected := func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie(fixtureSession); err == nil {
			w.Header().Set("X-Fixture-Cookie", "present")
			if ck.Value == "signed-in" {
				io.WriteString(w, "signed in")
				return
			}
		}
		if r.Method == http.MethodGet {
			http.Redirect(w, r, "/login?next=/admin", http.StatusSeeOther)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}
	mux.HandleFunc("GET /admin", protected)
	mux.HandleFunc("POST /admin/items/{id}/delete", protected)
	return p.Handler(mux)
}

func checkFixtureSignIn(t *testing.T, c *webtest.Client) {
	t.Helper()
	c.SignIn("/login", url.Values{"password": {"fixture-password"}}).WantRedirect(http.StatusSeeOther, "/admin")
	r := c.Get("/admin")
	r.WantStatus(http.StatusOK)
	if r.Body != "signed in" {
		t.Errorf("signed-in body = %q; want %q", r.Body, "signed in")
	}
}
