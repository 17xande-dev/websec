package cookie_test

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/17xande-dev/websec/cookie"
)

func TestPrefixedName(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		insecure   bool
		want       string
	}{
		{"secure root", "/", false, "__Host-session"},
		{"default path", "", false, "__Host-session"},
		{"secure admin path", "/admin", false, "__Secure-session"},
		{"secure trailing slash", "/admin/", false, "__Secure-session"},
		{"insecure root", "/", true, "session"},
		{"insecure admin path", "/admin", true, "session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cookie.PrefixedName("session", tc.path, tc.insecure); got != tc.want {
				t.Errorf("PrefixedName = %q, want %q", got, tc.want)
			}
			policy := newCookie(t, cookie.Config{Name: "session", Path: tc.path, Insecure: tc.insecure})
			if got := policy.Name(); got != tc.want {
				t.Errorf("Name = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewRefusesInvalidConfig(t *testing.T) {
	for _, tc := range []struct{ name, cookieName, path string }{
		{"empty name", "", "/"},
		{"host prefix", "__Host-session", "/"},
		{"secure prefix", "__Secure-session", "/"},
		{"mixed-case host prefix", "__hOsT-session", "/"},
		{"mixed-case secure prefix", "__sEcUrE-session", "/"},
		{"non-token name", "session=token", "/"},
		{"relative path", "session", "admin"},
		{"semicolon in path", "session", "/admin;attr"},
		{"control byte in path", "session", "/ad\x00min"},
		{"DEL in path", "session", "/ad\x7fmin"},
		{"space in path", "session", "/ad min"},
		{"path exceeds 1024 bytes", "session", "/" + strings.Repeat("a", 1024)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, insecure := range []bool{false, true} {
				if got, err := cookie.New(cookie.Config{Name: tc.cookieName, Path: tc.path, Insecure: insecure}); got != nil || err == nil {
					t.Errorf("New (Insecure=%t) = %v, %v; want nil policy and an error", insecure, got, err)
				}
			}
		})
	}
	newCookie(t, cookie.Config{Name: "session", Path: "/" + strings.Repeat("a", 1023)})
}

func TestSetAttributes(t *testing.T) {
	for _, tc := range []struct {
		name, path, wireName, wirePath string
		insecure, browserSession       bool
	}{
		{"secure persistent", "", "__Host-session", "/", false, false},
		{"insecure persistent", "/admin", "session", "/admin", true, false},
		{"browser session", "/admin/", "__Secure-session", "/admin/", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := newCookie(t, cookie.Config{
				Name: "session", Path: tc.path, Insecure: tc.insecure, BrowserSession: tc.browserSession,
			})
			expires := time.Now().Add(time.Hour).In(time.FixedZone("offset", 2*60*60))
			if tc.browserSession {
				expires = time.Time{} // Ignored, even though it would clear a persistent cookie.
			}
			server := newServer(t, tc.insecure, func(w http.ResponseWriter, r *http.Request) {
				policy.Set(w, "token", expires)
			})
			before := time.Now()
			got, raw := responseCookie(t, get(t, server.Client(), server.URL+tc.wirePath))
			after := time.Now()
			checkAttributes(t, got, tc.wireName, tc.wirePath, !tc.insecure)
			if got.Value != "token" {
				t.Errorf("Value = %q, want token", got.Value)
			}
			if tc.browserSession {
				if got.MaxAge != 0 || !got.Expires.IsZero() || strings.Contains(raw, "Max-Age=") || strings.Contains(raw, "Expires=") {
					t.Errorf("browser-session cookie has expiry attributes: %s", raw)
				}
				return
			}
			if want := "Expires=" + expires.UTC().Format(http.TimeFormat); !strings.Contains(raw, want) {
				t.Errorf("Set-Cookie = %s, want %s", raw, want)
			}
			if got.Expires != expires.UTC().Truncate(time.Second) {
				t.Errorf("Expires = %v, want UTC expiry rounded down from %v", got.Expires, expires)
			}
			if minAge, maxAge := int(expires.Sub(after)/time.Second), int(expires.Sub(before)/time.Second); got.MaxAge <= 0 || got.MaxAge < minAge || got.MaxAge > maxAge {
				t.Errorf("Max-Age = %d, want whole seconds remaining in [%d, %d]", got.MaxAge, minAge, maxAge)
			}
		})
	}
}

func TestSetClearsExpiredCookie(t *testing.T) {
	policy := newCookie(t, cookie.Config{Name: "session"})
	for _, tc := range []struct {
		name string
		left time.Duration
	}{
		{"past", -time.Minute},
		{"now", 0},
		{"less than a whole second", 500 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newServer(t, false, func(w http.ResponseWriter, r *http.Request) {
				policy.Set(w, "expired", time.Now().Add(tc.left))
			})
			got, raw := responseCookie(t, get(t, server.Client(), server.URL))
			checkAttributes(t, got, "__Host-session", "/", true)
			checkDeletion(t, got, raw)
		})
	}
}

func TestClearDropsCookie(t *testing.T) {
	for _, tc := range []struct {
		name, wireName string
		insecure       bool
	}{
		{"secure admin path", "__Secure-session", false},
		{"insecure admin path", "session", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := newCookie(t, cookie.Config{Name: "session", Path: "/admin", Insecure: tc.insecure})
			server := newServer(t, tc.insecure, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/admin/set":
					policy.Set(w, "token", time.Now().Add(time.Hour))
				case "/admin/clear":
					policy.Clear(w)
				default:
					value, _ := policy.Value(r)
					io.WriteString(w, value)
				}
			})
			client := server.Client()
			get(t, client, server.URL+"/admin/set")
			if got := body(t, get(t, client, server.URL+"/admin")); got != "token" {
				t.Fatalf("jar did not send the cookie before Clear: got %q", got)
			}
			got, raw := responseCookie(t, get(t, client, server.URL+"/admin/clear"))
			checkAttributes(t, got, tc.wireName, "/admin", !tc.insecure)
			checkDeletion(t, got, raw)
			if got := body(t, get(t, client, server.URL+"/admin")); got != "" {
				t.Errorf("jar still sends cookie after Clear: %q", got)
			}
		})
	}
}

func TestValue(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		insecure     bool
		want         string
	}{
		{"prefixed", "__Host-session=token", false, "token"},
		{"prefixed alongside a bare decoy", "session=decoy; __Host-session=token", false, "token"},
		{"bare decoy alone", "session=decoy", false, ""},
		{"insecure bare", "session=token", true, "token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := newCookie(t, cookie.Config{Name: "session", Insecure: tc.insecure})
			server := newServer(t, tc.insecure, func(w http.ResponseWriter, r *http.Request) {
				value, ok := policy.Value(r)
				if !ok {
					w.WriteHeader(http.StatusNotFound)
				}
				io.WriteString(w, value)
			})
			req, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Cookie", tc.header)
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			wantStatus := http.StatusOK
			if tc.want == "" {
				wantStatus = http.StatusNotFound
			}
			if got := body(t, resp); resp.StatusCode != wantStatus || got != tc.want {
				t.Errorf("Value returned HTTP %d and %q, want HTTP %d and %q", resp.StatusCode, got, wantStatus, tc.want)
			}
		})
	}
}

func TestBrowserRoundTrip(t *testing.T) {
	token := []byte("0123456789abcdefghijklmnopqrstu\xff")
	for _, tc := range []struct{ name, value string }{
		{"base64url", base64.RawURLEncoding.EncodeToString(token)},
		{"hex", hex.EncodeToString(token)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := newCookie(t, cookie.Config{Name: "session", Path: "/admin"})
			server := newServer(t, false, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/admin/set" {
					policy.Set(w, tc.value, time.Now().Add(time.Hour))
					return
				}
				value, _ := policy.Value(r)
				io.WriteString(w, value)
			})
			client := server.Client()
			get(t, client, server.URL+"/admin/set")
			if got := body(t, get(t, client, server.URL+"/admin")); got != tc.value {
				t.Errorf("cookie at /admin = %q, want %q", got, tc.value)
			}
			if got := body(t, get(t, client, server.URL+"/")); got != "" {
				t.Errorf("cookie outside /admin = %q, want none", got)
			}
		})
	}
}

func TestSetPanicsOnInvalidValue(t *testing.T) {
	policy := newCookie(t, cookie.Config{Name: "session"})
	rec := httptest.NewRecorder()
	defer func() {
		if got := recover(); got != "cookie: invalid session cookie value" {
			t.Errorf("Set panic = %v, want an invalid value message", got)
		}
		if got := rec.Header().Get("Set-Cookie"); got != "" {
			t.Errorf("Set wrote a cookie before panicking: %q", got)
		}
	}()
	policy.Set(rec, "invalid;token", time.Now().Add(time.Hour))
}

func newCookie(t *testing.T, cfg cookie.Config) *cookie.Cookie {
	t.Helper()
	policy, err := cookie.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func newServer(t *testing.T, insecure bool, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	start := httptest.NewTLSServer
	if insecure {
		start = httptest.NewServer
	}
	server := start(handler)
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Client().Jar = jar
	return server
}

func get(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", url, resp.Status)
	}
	return resp
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

func responseCookie(t *testing.T, resp *http.Response) (*http.Cookie, string) {
	t.Helper()
	raw := resp.Header.Values("Set-Cookie")
	parsed := resp.Cookies()
	if len(raw) != 1 || len(parsed) != 1 {
		t.Fatalf("want one valid Set-Cookie, got %q", raw)
	}
	return parsed[0], raw[0]
}

func checkAttributes(t *testing.T, got *http.Cookie, name, path string, secure bool) {
	t.Helper()
	if got.Name != name || got.Path != path || got.Secure != secure {
		t.Errorf("name=%q Path=%q Secure=%t; want %q, %q, %t", got.Name, got.Path, got.Secure, name, path, secure)
	}
	if !got.HttpOnly || got.SameSite != http.SameSiteLaxMode || got.Domain != "" {
		t.Errorf("want HttpOnly, SameSite=Lax and no Domain: %s", got.Raw)
	}
}

func checkDeletion(t *testing.T, got *http.Cookie, raw string) {
	t.Helper()
	if got.Value != "" || got.MaxAge >= 0 || !got.Expires.Equal(time.Unix(0, 0)) || !strings.Contains(raw, "Max-Age=0") {
		t.Errorf("want an empty value, Max-Age=0 and Unix epoch expiry: %s", raw)
	}
}
