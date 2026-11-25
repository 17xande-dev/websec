package webtest

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestClientWithReportsToSubtest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/form", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `<form method="post" action="/submit"></form>`)
	})
	mux.HandleFunc("/multipart", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `<form method="post" enctype="multipart/form-data"></form>`)
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Location", "/first")
		w.Header().Add("Location", "/second")
		w.WriteHeader(http.StatusSeeOther)
	})
	mux.HandleFunc("/cookies", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "first"})
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "second"})
	})
	for _, tt := range []struct {
		name, wantMsg string
		check         func(parent, sub *Client, tb testing.TB)
	}{
		{"client", "resolve request URL", func(_, sub *Client, _ testing.TB) {
			sub.Get("/%")
		}},
		{"response", "want status 204", func(_, sub *Client, _ testing.TB) {
			sub.Get("/form").WantStatus(http.StatusNoContent)
		}},
		{"page", `no "csrf_token" input`, func(_, sub *Client, _ testing.TB) {
			sub.Page("/form").Token()
		}},
		{"form", "unsupported form enctype", func(_, sub *Client, _ testing.TB) {
			sub.Page("/multipart").Form("").Submit()
		}},
		{"form response", "want status 200", func(_, sub *Client, _ testing.TB) {
			sub.Page("/form").Form("").Submit().WantStatus(http.StatusOK)
		}},
		{"follow parent response", "multiple Location values", func(parent, sub *Client, _ testing.TB) {
			sub.Follow(parent.Get("/redirect"))
		}},
		{"want cookie missing", `no Set-Cookie named "session"`, func(parent, _ *Client, tb testing.TB) {
			WantCookie(tb, parent.Get("/form"), CookieWant{Name: "session"})
		}},
		{"want cookie duplicate", `multiple Set-Cookie values named "session"`, func(parent, _ *Client, tb testing.TB) {
			WantCookie(tb, parent.Get("/cookies"), CookieWant{Name: "session"})
		}},
		{"set cookie", "jar would not send", func(_, sub *Client, _ testing.TB) {
			sub.SetCookie(&http.Cookie{Name: "session", Value: "expired", MaxAge: -1})
		}},
		{"sign in", "found 0 password forms", func(_, sub *Client, _ testing.TB) {
			sub.SignIn("/form", nil)
		}},
		{"sweep response", "want status 401", func(_, sub *Client, tb testing.TB) {
			Sweep{
				Routes:  []Route{{Method: http.MethodGet, Path: "/redirect"}},
				Min:     1,
				Client:  func() *Client { return sub },
				NoToken: true,
				Refused: func(_ Route, r *Response) error {
					r.WantStatus(http.StatusUnauthorized)
					return nil
				},
			}.Run(tb)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parent := &failRecorder{TB: t}
			checkFailure(t, func(sub testing.TB) {
				c := New(parent, mux, testOrigin)
				tt.check(c, c.With(sub), sub)
			}, true, tt.wantMsg)
			if parent.Failed() {
				t.Errorf("parent failed: %q", parent.messages)
			}
		})
	}
}

func TestSweepRunReportsToPassedTest(t *testing.T) {
	for _, tt := range []struct {
		name, method, tokenPage string
		status                  int
		wantMsg                 string
	}{
		{"token page", http.MethodPost, "/token", http.StatusUnauthorized, "GET /token: status 404"},
		{"not a refusal", http.MethodGet, "", http.StatusOK, "not a refusal"},
		{"refused error", http.MethodGet, "", http.StatusUnauthorized, "unexpected refusal"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parent := &failRecorder{TB: t}
			mux := http.NewServeMux()
			mux.HandleFunc("/protected", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			})
			checkFailure(t, func(sub testing.TB) {
				Sweep{
					Routes:    []Route{{Method: tt.method, Path: "/protected"}},
					Min:       1,
					Client:    func() *Client { return New(parent, mux, testOrigin) },
					TokenPage: tt.tokenPage,
					NoToken:   tt.tokenPage == "",
					Refused:   func(Route, *Response) error { return errors.New("unexpected refusal") },
				}.Run(sub)
			}, true, tt.wantMsg)
			if parent.Failed() {
				t.Errorf("parent failed: %q", parent.messages)
			}
		})
	}
}

func TestClientWithRejectsNil(t *testing.T) {
	checkFailure(t, func(tb testing.TB) {
		New(tb, http.NotFoundHandler(), testOrigin).With(nil)
	}, true, "With: nil testing.TB")
}

func TestClientWithKeepsOriginalBinding(t *testing.T) {
	sub := &failRecorder{TB: t}
	checkFailure(t, func(parent testing.TB) {
		c := New(parent, http.NotFoundHandler(), testOrigin)
		c.With(sub)
		c.Get("/").WantStatus(http.StatusOK)
	}, true, "want status 200")
	if sub.Failed() {
		t.Errorf("subtest failed: %q", sub.messages)
	}
}

func TestClientWithSharesCookies(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `<form method="post"><input type="password" name="password"><input name="csrf_token" value="fixture-token"></form>`)
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("password") != "fixture-password" || r.PostFormValue("csrf_token") != "fixture-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "signed-in", Path: "/", Secure: true})
		http.Redirect(w, r, "/account", http.StatusSeeOther)
	})
	mux.HandleFunc("POST /account/{page}", func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie("session"); err != nil || ck.Value != "signed-in" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Origin") != "https://"+r.Host || r.Header.Get("X-Client") != "fixture" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: r.PathValue("page"), Value: "visited", Path: "/", Secure: true})
		w.WriteHeader(http.StatusNoContent)
	})
	for _, mode := range []string{"in-process", "TLS server"} {
		t.Run(mode, func(t *testing.T) {
			opt := Header("X-Client", "fixture")
			var c *Client
			if mode == "in-process" {
				c = New(t, mux, testOrigin, opt)
			} else {
				srv := httptest.NewTLSServer(mux)
				t.Cleanup(srv.Close)
				c = NewServer(t, srv, opt)
			}
			c.SignIn("/login", url.Values{"password": {"fixture-password"}}).
				WantRedirect(http.StatusSeeOther, "/account")
			pages := []string{"profile", "settings"}
			t.Cleanup(func() {
				for _, page := range pages {
					if got, ok := c.Cookie(page); !ok || got != "visited" {
						t.Errorf("parent cookie %q = %q, %t; want visited, true", page, got, ok)
					}
				}
			})
			for _, page := range pages {
				t.Run(page, func(t *testing.T) {
					t.Parallel()
					res := c.With(t).PostForm("/account/"+page, nil)
					res.WantStatus(http.StatusNoContent)
					if res.Request.Context() != t.Context() {
						t.Error("request context is not the subtest's")
					}
				})
			}
		})
	}
}
