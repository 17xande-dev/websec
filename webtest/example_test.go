package webtest_test

import (
	"net/http"
	"testing"

	"github.com/17xande-dev/websec/webtest"
)

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
