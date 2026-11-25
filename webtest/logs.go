package webtest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// Logs captures log records. String and Reset are safe to call while a
// handler is logging, but callers must wait for the records they expect.
type Logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Logger returns a JSON slog logger capturing Debug and higher levels.
func Logger(t testing.TB) (*slog.Logger, *Logs) {
	t.Helper()
	logs := &Logs{}
	return slog.New(slog.NewJSONHandler(logWriter{logs}, &slog.HandlerOptions{Level: slog.LevelDebug})), logs
}

type logWriter struct{ logs *Logs }

func (w logWriter) Write(p []byte) (int, error) {
	w.logs.mu.Lock()
	defer w.logs.mu.Unlock()
	return w.logs.buf.Write(p)
}

// String returns a snapshot of the captured log.
func (l *Logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Reset discards the records captured so far.
func (l *Logs) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.Reset()
}

// NoSecrets requires a nonempty mustContain marker in text and checks all of
// text for each secret: raw, URL query and path escapes, JSON and HTML escapes,
// standard and URL base64, hex, and every byte percent-encoded (upper and
// lower-case digits). Each secret must be at least 12 bytes to
// avoid chance matches against random IDs. Failures do not print the secrets
// or captured log.
func NoSecrets(t testing.TB, text, mustContain string, secrets ...string) {
	t.Helper()
	if mustContain == "" || !strings.Contains(text, mustContain) {
		t.Fatal("log is missing the required nonempty marker")
	}
	for i, secret := range secrets {
		if len(secret) < 12 {
			t.Fatalf("secret %d must be at least 12 bytes", i+1)
		}
		for _, form := range secretForms(secret) {
			if strings.Contains(text, form.value) {
				t.Fatalf("log contains secret %d (%s)", i+1, form.name)
			}
		}
	}
}

func secretForms(secret string) []struct{ name, value string } {
	raw := []byte(secret)
	jsonHTML, _ := json.Marshal(secret) // A string is always JSON-encodable.
	var jsonLog bytes.Buffer
	encoder := json.NewEncoder(&jsonLog)
	encoder.SetEscapeHTML(false) // The JSON slog handler does not escape HTML.
	_ = encoder.Encode(secret)
	jsonValue := strings.TrimSuffix(jsonLog.String(), "\n")
	hexValue := hex.EncodeToString(raw)
	// url.QueryEscape and url.PathEscape leave unreserved bytes alone, so a
	// value with every byte escaped is a different string that decodes to the
	// same secret.
	var percentUpper, percentLower strings.Builder
	for _, b := range raw {
		fmt.Fprintf(&percentUpper, "%%%02X", b)
		fmt.Fprintf(&percentLower, "%%%02x", b)
	}
	return []struct{ name, value string }{
		{"raw", secret},
		{"query escaped", url.QueryEscape(secret)},
		{"path escaped", url.PathEscape(secret)},
		{"JSON escaped", jsonValue[1 : len(jsonValue)-1]},
		{"JSON HTML escaped", string(jsonHTML[1 : len(jsonHTML)-1])},
		{"HTML escaped", html.EscapeString(secret)},
		{"base64 standard", base64.StdEncoding.EncodeToString(raw)},
		{"base64 raw standard", base64.RawStdEncoding.EncodeToString(raw)},
		{"base64 URL", base64.URLEncoding.EncodeToString(raw)},
		{"base64 raw URL", base64.RawURLEncoding.EncodeToString(raw)},
		{"hex", hexValue},
		{"all bytes percent-encoded", percentUpper.String()},
		{"all bytes lowercase percent-encoded", percentLower.String()},
		{"uppercase hex", strings.ToUpper(hexValue)},
	}
}
