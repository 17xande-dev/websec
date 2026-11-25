package webtest_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/17xande-dev/websec/webtest"
)

func TestSweepAndSignInExample(t *testing.T) {
	const origin = "https://app.example"
	app := csrfFixture(t, origin, false)
	fresh := func() *webtest.Client { return webtest.New(t, app, origin) }

	// In an application, take these patterns from route registration.
	patterns := []string{"GET /admin", "POST /admin/items/{id}/delete"}
	webtest.Sweep{
		Routes:    webtest.Routes(t, patterns, map[string]string{"id": "1"}),
		Min:       2,
		Client:    fresh,
		TokenPage: "/login",
		Refused:   webtest.ByMethod(webtest.RedirectsTo("/login?next="), webtest.Status(http.StatusUnauthorized)),
	}.Run(t)

	c := fresh()
	c.SignIn("/login", url.Values{"password": {"fixture-password"}}).
		WantRedirect(http.StatusSeeOther, "/admin")
	c.Get("/admin").WantStatus(http.StatusOK)
}

func TestClientWithExample(t *testing.T) {
	const origin = "https://app.example"
	c := webtest.New(t, csrfFixture(t, origin, false), origin)
	c.SignIn("/login", url.Values{"password": {"fixture-password"}}).
		WantRedirect(http.StatusSeeOther, "/admin")

	for _, name := range []string{"overview", "details"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c.With(t).Get("/admin?view=" + name).WantStatus(http.StatusOK)
		})
	}
}

func TestUploadRefusalExample(t *testing.T) {
	const secret = "example-upload-key"
	logger, logs := webtest.Logger(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /upload", func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 1024 {
			logger.Warn("upload refused", "path", r.URL.Path)
			http.Error(w, "Upload too large", http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})

	c := webtest.New(t, mux, "https://app.example")
	c.Get("/ready").WantStatus(http.StatusNoContent)

	const size = 1 << 20
	body := webtest.NewCountingReader(webtest.Filler(size))
	req := c.NewRequest(http.MethodPost, "/upload?key="+secret, body)
	req.ContentLength = size
	c.Do(req).WantStatus(http.StatusRequestEntityTooLarge)
	if n := body.N(); n != 0 {
		t.Errorf("read %d upload bytes; want none", n)
	}
	webtest.NoSecrets(t, logs.String(), "upload refused", secret)
}
