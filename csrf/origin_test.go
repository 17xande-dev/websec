package csrf_test

import (
	"errors"
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

var originHostCases = []struct {
	name, origin, wantCause string
}{
	{"unicode-host", "https://äpp.example", "origin host must be ASCII; use Punycode for internationalized names"},
	{"uppercase-unicode-host", "https://Äpp.example", "origin host must be ASCII; use Punycode for internationalized names"},
	{"punycode-host", "https://xn--pp-uia.example", ""},
	{"ipv6-expanded", "https://[2001:db8:0:0::1]", "IPv6 origin host must use canonical spelling; use [2001:db8::1]"},
	{"ipv6-canonical", "https://[2001:db8::1]", ""},
	{"ipv6-canonical-port", "https://[2001:db8::1]:8443", ""},
	{"ipv6-mapped-dotted", "https://[::ffff:192.0.2.1]", "IPv6 origin host must use canonical spelling; use [::ffff:c000:201]"},
	{"ipv6-mapped-hex", "https://[::ffff:c000:201]", ""},
	{"ipv4-short", "https://127.1", "IPv4 origin host must use canonical dotted-quad spelling"},
	{"ipv4-hex", "https://0x7f.1", "IPv4 origin host must use canonical dotted-quad spelling"},
	{"ipv4-leading-zero", "https://127.000.0.1", "IPv4 origin host must use canonical dotted-quad spelling"},
	{"ipv4-integer", "https://2130706433", "IPv4 origin host must use canonical dotted-quad spelling"},
	{"ipv4-trailing-dot", "https://127.0.0.1.", "IPv4 origin host must use canonical dotted-quad spelling"},
	{"ipv4-canonical", "https://127.0.0.1", ""},
	{"localhost", "https://localhost", ""},
	{"dns-numeric-label", "https://127.app.example", ""},
	{"dns-trailing-dot", "https://app.example.", ""},
}

func TestValidateOriginHost(t *testing.T) {
	for _, tc := range originHostCases {
		t.Run(tc.name, func(t *testing.T) {
			standalone := checkOriginAgreement(t, tc.origin, false)
			switch {
			case tc.wantCause == "" && standalone != nil:
				t.Errorf("ValidateOrigin(%q) = %v, want nil", tc.origin, standalone)
			case tc.wantCause != "" && (standalone == nil || standalone.Error() != "csrf: "+tc.wantCause):
				t.Errorf("ValidateOrigin(%q) = %v, want csrf: %s", tc.origin, standalone, tc.wantCause)
			}
		})
	}
}

func FuzzValidateOrigin(f *testing.F) {
	for _, tc := range originCases {
		f.Add(tc.origin, tc.insecure)
	}
	for _, tc := range originHostCases {
		f.Add(tc.origin, false)
	}
	f.Fuzz(func(t *testing.T, s string, insecure bool) {
		checkOriginAgreement(t, s, insecure)
	})
}

func checkOriginAgreement(t *testing.T, s string, insecure bool) error {
	t.Helper()
	standalone := csrf.ValidateOrigin(s, insecure)
	_, own := csrf.New(csrf.Config{Origin: s, Insecure: insecure})
	_, trusted := csrf.New(csrf.Config{
		Origin: "https://app.example", TrustedOrigins: []string{s}, Insecure: insecure,
	})
	cause := func(err error) string {
		if underlying := errors.Unwrap(err); underlying != nil {
			return underlying.Error()
		}
		return ""
	}
	if (standalone == nil) != (own == nil) || (standalone == nil) != (trusted == nil) ||
		cause(standalone) != cause(own) || cause(standalone) != cause(trusted) {
		t.Errorf("entry points disagree: ValidateOrigin = %v, Origin = %v, TrustedOrigins = %v", standalone, own, trusted)
	}
	return standalone
}
