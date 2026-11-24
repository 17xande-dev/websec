package csrf

import (
	"net/http"
	"testing"
)

// MaxMemory is not observable through a response (a file part can never be
// larger than the body that holds it), so the normalised values are checked
// directly.
func TestBodyLimitNormalised(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   BodyLimit
		want BodyLimit
	}{
		{"zero value", BodyLimit{}, BodyLimit{MaxBytes: 256 << 10}},
		{"default memory is capped by the multipart cap", BodyLimit{MultipartMaxBytes: 512 << 10}, BodyLimit{MaxBytes: 256 << 10, MultipartMaxBytes: 512 << 10, MaxMemory: 512 << 10}},
		{"default memory is 1 MiB", BodyLimit{MultipartMaxBytes: 64 << 20}, BodyLimit{MaxBytes: 256 << 10, MultipartMaxBytes: 64 << 20, MaxMemory: 1 << 20}},
		{"memory above the cap is clamped", BodyLimit{MultipartMaxBytes: 1 << 20, MaxMemory: 8 << 20}, BodyLimit{MaxBytes: 256 << 10, MultipartMaxBytes: 1 << 20, MaxMemory: 1 << 20}},
		{"memory below the cap is kept", BodyLimit{MultipartMaxBytes: 8 << 20, MaxMemory: 2 << 20}, BodyLimit{MaxBytes: 256 << 10, MultipartMaxBytes: 8 << 20, MaxMemory: 2 << 20}},
		{"negative values act as 0", BodyLimit{MaxBytes: -5, MultipartMaxBytes: -5, MaxMemory: -5}, BodyLimit{MaxBytes: 256 << 10}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Protect{maxBody: 256 << 10, limit: func(*http.Request) BodyLimit { return tc.in }}
			got := p.bodyLimit(&http.Request{})
			if got.MaxBytes != tc.want.MaxBytes || got.MultipartMaxBytes != tc.want.MultipartMaxBytes || got.MaxMemory != tc.want.MaxMemory {
				t.Errorf("bodyLimit = %+v, want %+v", got, tc.want)
			}
		})
	}
}
