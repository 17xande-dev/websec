package csrf_test

import (
	"testing"

	"github.com/17xande-dev/websec/csrf"
)

var originCases = []struct {
	name, origin string
	insecure, ok bool
}{
	{"https", "https://app.example", false, true},
	{"http-secure", "http://app.example", false, false},
	{"http-insecure", "http://app.example", true, true},
	{"explicit-port", "https://app.example:8443", false, true},
	{"max-port", "https://app.example:65535", false, true},
	{"out-of-range-port", "https://app.example:65536", false, false},
	{"https-default-port", "https://app.example:443", false, false},
	{"http-default-port", "http://app.example:80", true, false},
	{"https-port-80", "https://app.example:80", false, true},
	{"leading-zero-default-port", "https://app.example:0443", false, false},
	{"leading-zeros-default-port", "https://app.example:00443", false, false},
	{"zero-port", "https://app.example:0", false, false},
	{"leading-zero-other-port", "https://app.example:08443", false, false},
	{"ipv6-port", "https://[2001:db8::1]:8443", false, true},
	{"ipv6-leading-zero-port", "https://[2001:db8::1]:0443", false, false},
	{"ipv6", "https://[::1]", false, true},
	{"empty", "", false, false},
	{"trailing-slash", "https://app.example/", false, false},
	{"uppercase-host", "https://APP.example", false, false},
	{"uppercase-scheme", "HTTPS://app.example", false, false},
	{"userinfo", "https://u@app.example", false, false},
	{"empty-port", "https://app.example:", false, false},
	{"query", "https://app.example?x", false, false},
	{"ftp", "ftp://app.example", false, false},
}

func TestValidateOrigin(t *testing.T) {
	for _, tc := range originCases {
		t.Run(tc.name, func(t *testing.T) {
			standalone := csrf.ValidateOrigin(tc.origin, tc.insecure)
			_, own := csrf.New(csrf.Config{Origin: tc.origin, Insecure: tc.insecure})
			_, trusted := csrf.New(csrf.Config{
				Origin: "https://app.example", TrustedOrigins: []string{tc.origin}, Insecure: tc.insecure,
			})
			if (standalone == nil) != (own == nil) || (standalone == nil) != (trusted == nil) {
				t.Errorf("entry points disagree: ValidateOrigin = %v, Origin = %v, TrustedOrigins = %v", standalone, own, trusted)
			}
			if (standalone == nil) != tc.ok {
				t.Errorf("ValidateOrigin(%q, %t) = %v, want success: %t", tc.origin, tc.insecure, standalone, tc.ok)
			}
		})
	}
}

func FuzzValidateOrigin(f *testing.F) {
	for _, tc := range originCases {
		f.Add(tc.origin, tc.insecure)
	}
	f.Fuzz(func(t *testing.T, s string, insecure bool) {
		standalone := csrf.ValidateOrigin(s, insecure)
		_, own := csrf.New(csrf.Config{Origin: s, Insecure: insecure})
		if (standalone == nil) != (own == nil) {
			t.Errorf("entry points disagree: ValidateOrigin = %v, New = %v", standalone, own)
		}
	})
}
