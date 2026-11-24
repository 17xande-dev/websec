package webtest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWantCookie(t *testing.T) {
	for _, tt := range []struct {
		name, header string
		want         CookieWant
		wantMsg      string
	}{
		{
			"host session", "__Host-marker=value; Path=/; Secure; HttpOnly; SameSite=Lax",
			CookieWant{Name: "__Host-marker", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Session: true}, "",
		},
		{
			"secure deletion", "__Secure-marker=value; Path=/area; Secure; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
			CookieWant{Name: "__Secure-marker", Path: "/area", Secure: true, SameSite: http.SameSiteStrictMode, Cleared: true}, "",
		},
		{"literal name does not match", "__Host-marker=value; Path=/; Secure", CookieWant{Name: "marker"}, `no Set-Cookie named "marker"`},
		{"path", "marker=value; Path=/area", CookieWant{Name: "marker", Path: "/"}, `Path = "/area"; want "/"`},
		{"secure", "marker=value", CookieWant{Name: "marker", Secure: true}, "Secure = false; want true"},
		{"unexpected secure", "marker=value; Secure", CookieWant{Name: "marker"}, "Secure = true; want false"},
		{"http only", "marker=value", CookieWant{Name: "marker", HttpOnly: true}, "HttpOnly = false; want true"},
		{"unexpected http only", "marker=value; HttpOnly", CookieWant{Name: "marker"}, "HttpOnly = true; want false"},
		{
			"same site", "marker=value; SameSite=Lax",
			CookieWant{Name: "marker", SameSite: http.SameSiteStrictMode}, "SameSite =",
		},
		{
			"session with max age", "marker=value; Max-Age=60",
			CookieWant{Name: "marker", Session: true}, "Max-Age present=true, Expires present=false",
		},
		{
			"session with malformed max age", "marker=value; Max-Age=invalid",
			CookieWant{Name: "marker", Session: true}, "Max-Age present=true, Expires present=false",
		},
		{
			"session with expires", "marker=value; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
			CookieWant{Name: "marker", Session: true}, "Max-Age present=false, Expires present=true",
		},
		{
			"session with malformed expires", "marker=value; eXpires=invalid",
			CookieWant{Name: "marker", Session: true}, "Max-Age present=false, Expires present=true",
		},
		{"deletion with positive age", "marker=value; Max-Age=60", CookieWant{Name: "marker", Cleared: true}, "parsed Max-Age < 0; got 60"},
		{
			"deletion with expires only", "marker=value; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
			CookieWant{Name: "marker", Cleared: true}, "parsed Max-Age < 0; got 0",
		},
		{"domain present", "marker=value; Domain=app.example", CookieWant{Name: "marker"}, "Domain must be absent"},
		{"domain empty", "marker=value; DOMAIN=", CookieWant{Name: "marker"}, "Domain must be absent"},
		{
			"host prefix missing secure", "__Host-marker=value; Path=/",
			CookieWant{Name: "__Host-marker", Path: "/"}, "__Host- requires Secure, Path=/ and no Domain",
		},
		{
			"host prefix with subpath", "__Host-marker=value; Path=/area; Secure",
			CookieWant{Name: "__Host-marker", Path: "/area", Secure: true}, "__Host- requires Secure, Path=/ and no Domain",
		},
		{
			"host prefix missing path", "__Host-marker=value; Secure",
			CookieWant{Name: "__Host-marker", Secure: true}, "__Host- requires Secure, Path=/ and no Domain",
		},
		{
			"host prefix with domain", "__Host-marker=value; Path=/; Secure; Domain=app.example",
			CookieWant{Name: "__Host-marker", Path: "/", Secure: true}, "__Host- requires Secure, Path=/ and no Domain",
		},
		{"secure prefix missing secure", "__Secure-marker=value", CookieWant{Name: "__Secure-marker"}, "__Secure- requires Secure"},
		{"mixed case prefix missing secure", "__sEcUrE-marker=value", CookieWant{Name: "__sEcUrE-marker"}, "__Secure- requires Secure"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Set-Cookie", "unrelated=other")
				w.Header().Add("Set-Cookie", tt.header)
				w.WriteHeader(http.StatusSeeOther)
			}))
			t.Cleanup(srv.Close)
			checkFailure(t, func(tb testing.TB) {
				r := NewServer(tb, srv).Get("/issue")
				ck := WantCookie(tb, r, tt.want)
				if tt.wantMsg == "" && (ck.Name != tt.want.Name || ck.Value != "value") {
					tb.Errorf("cookie = %+v; want %q with value %q", ck, tt.want.Name, "value")
				}
			}, tt.wantMsg != "", tt.wantMsg)
		})
	}
}

func TestWantCookieRejectsDuplicateName(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", "marker=first; Path=/")
		w.Header().Add("Set-Cookie", "marker=second; Path=/area")
	})
	checkFailure(t, func(tb testing.TB) {
		WantCookie(tb, New(tb, h, testOrigin).Get("/issue"), CookieWant{Name: "marker", Path: "/"})
	}, true, `multiple Set-Cookie values named "marker"`)
}
