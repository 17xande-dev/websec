package webtest

import (
	"net/http"
	"strings"
	"testing"
)

func TestNoSecrets(t *testing.T) {
	const marker = "request refused"
	const secret = "fixture +/&=\"\n"
	const base64Secret = "\uffff-test-secret!"
	for _, tt := range []struct {
		name     string
		text     string
		marker   string
		secrets  []string
		wantFail bool
		wantMsg  string
	}{
		{"redacted", marker + "\n", marker, []string{secret}, false, ""},
		{"raw on later line", marker + "\n" + secret, marker, []string{secret}, true, "(raw)"},
		{"second secret", "a second fixture\n" + marker, marker, []string{secret, "a second fixture"}, true, "secret 2 (raw)"},
		{"query escaped", "fixture+%2B%2F%26%3D%22%0A\n" + marker, marker, []string{secret}, true, "(query escaped)"},
		{"path escaped", marker + "\nfixture%20+%2F&=%22%0A", marker, []string{secret}, true, "(path escaped)"},
		{"JSON escaped", marker + ` fixture +/&=\"\n`, marker, []string{secret}, true, "(JSON escaped)"},
		{"JSON HTML escaped", marker + ` fixture +/\u0026=\"\n`, marker, []string{secret}, true, "(JSON HTML escaped)"},
		{"HTML escaped", marker + " fixture +/&amp;=&#34;\n", marker, []string{secret}, true, "(HTML escaped)"},
		{"base64 standard", marker + " 77+/LXRlc3Qtc2VjcmV0IQ==", marker, []string{base64Secret}, true, "(base64 standard)"},
		{"base64 raw standard", marker + " 77+/LXRlc3Qtc2VjcmV0IQ", marker, []string{base64Secret}, true, "(base64 raw standard)"},
		{"base64 URL", marker + " 77-_LXRlc3Qtc2VjcmV0IQ==", marker, []string{base64Secret}, true, "(base64 URL)"},
		{"base64 raw URL", marker + " 77-_LXRlc3Qtc2VjcmV0IQ", marker, []string{base64Secret}, true, "(base64 raw URL)"},
		{"hex", marker + " 66697874757265202b2f263d220a", marker, []string{secret}, true, "(hex)"},
		{"uppercase hex", marker + " 66697874757265202B2F263D220A", marker, []string{secret}, true, "(uppercase hex)"},
		{"missing marker", "request allowed", marker, []string{secret}, true, "missing the required nonempty marker"},
		{"empty marker", marker, "", []string{secret}, true, "missing the required nonempty marker"},
		{"empty log", "", marker, []string{secret}, true, "missing the required nonempty marker"},
		{"five bytes", marker, marker, []string{"short"}, true, "must be at least 12 bytes"},
		{"eleven bytes", marker, marker, []string{"12345678901"}, true, "must be at least 12 bytes"},
		{"twelve bytes", marker, marker, []string{"éééééé"}, false, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checkFailure(t, func(t testing.TB) {
				NoSecrets(t, tt.text, tt.marker, tt.secrets...)
			}, tt.wantFail, tt.wantMsg)
		})
	}
}

func TestLoggerAfterResponse(t *testing.T) {
	logger, logs := Logger(t)
	release, drained, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		w.WriteHeader(http.StatusNoContent)
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
			return
		}
		select {
		case <-release:
		case <-t.Context().Done():
			return
		}
		for range 50 {
			logger.Debug("request complete", "path", r.URL.Path)
		}
		select {
		case <-drained:
			logger.Debug("capture complete", "path", r.URL.Path)
		case <-t.Context().Done():
		}
	})
	c := testClient(t, h, "server")
	res := c.Get("/items")
	if got := logs.String(); got != "" {
		t.Errorf("log was not empty before handler was released: %q", got)
	}
	close(release)
	for range 50 {
		_ = logs.String()
		logs.Reset()
	}
	close(drained)
	<-done
	res.WantStatus(http.StatusNoContent)

	text := logs.String()
	for _, want := range []string{`"level":"DEBUG"`, `"msg":"capture complete"`, `"path":"/items"`} {
		if !strings.Contains(text, want) {
			t.Errorf("JSON log missing %q", want)
		}
	}
	logs.Reset()
	if got := logs.String(); got != "" {
		t.Errorf("log after Reset = %q; want empty", got)
	}
}
