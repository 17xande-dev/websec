package webtest

import (
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestSignIn(t *testing.T) {
	body := fixtureHTML(t, "signin.html")
	for _, mode := range []string{"in-process", "TLS server"} {
		t.Run(mode, func(t *testing.T) {
			var visits atomic.Int32
			mux := http.NewServeMux()
			mux.HandleFunc("GET /account/sign-in", func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, body)
			})
			mux.HandleFunc("POST /account/session", func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Errorf("ParseForm: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				want := url.Values{
					"account_id": {"reader@app.example"}, "passcode": {"pass+code"}, "step": {"initial"},
					"csrf_token": {"example+token="},
				}
				if !reflect.DeepEqual(r.PostForm, want) {
					t.Errorf("submitted fields = %#v; want %#v", r.PostForm, want)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "signed-in", Path: "/", Secure: true})
				w.Header().Set("Location", "/account")
				w.WriteHeader(http.StatusSeeOther)
			})
			mux.HandleFunc("GET /account", func(w http.ResponseWriter, r *http.Request) {
				visits.Add(1)
				ck, err := r.Cookie("session")
				if err == nil && ck.Value == "signed-in" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.WriteHeader(http.StatusUnauthorized)
			})
			c := testClient(t, mux, mode)
			c.SignIn("/account/sign-in", url.Values{
				"account_id": {"reader@app.example"}, "passcode": {"pass+code"},
			}).WantRedirect(http.StatusSeeOther, "/account")
			if visits.Load() != 0 {
				t.Error("SignIn followed the redirect")
			}
			c.Get("/account").WantStatus(http.StatusNoContent)
		})
	}
}

func TestSignInFailures(t *testing.T) {
	body := fixtureHTML(t, "signin.html")
	for _, tt := range []struct {
		name, body, cookie, wantMsg string
		status                      int
	}{
		{name: "wrong password renders form again", body: body, status: http.StatusOK, wantMsg: "want status 303"},
		{name: "no cookie", body: body, status: http.StatusSeeOther, wantMsg: "want at least one valid Set-Cookie"},
		{name: "malformed cookie", body: body, status: http.StatusSeeOther, cookie: "not-a-cookie", wantMsg: "want at least one valid Set-Cookie"},
		{name: "no password form", body: `<form><input name=csrf_token value=token></form>`, wantMsg: "found 0 password forms (1 forms found); want one"},
		{
			name:    "two password forms",
			body:    `<form><input type=password></form><form><input TYPE=PASSWORD name=other></form>`,
			wantMsg: "found 2 password forms (2 forms found); want one",
		},
		{
			name: "no page token", body: `<form method=post><input type=password name=passcode></form>`,
			wantMsg: `no "csrf_token" input on page (1 forms found)`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					io.WriteString(w, tt.body)
					return
				}
				if tt.status == 0 {
					t.Errorf("unexpected submit: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if tt.cookie != "" {
					w.Header().Set("Set-Cookie", tt.cookie)
				}
				w.WriteHeader(tt.status)
				io.WriteString(w, tt.body)
			})
			checkFailure(t, func(t testing.TB) {
				c := New(t, h, testOrigin)
				// A cookie already in the jar cannot satisfy the assertion.
				c.SetCookie(&http.Cookie{Name: "prior", Value: "existing"})
				c.SignIn("/account/sign-in", url.Values{"passcode": {"wrong"}})
			}, true, tt.wantMsg)
		})
	}
}
