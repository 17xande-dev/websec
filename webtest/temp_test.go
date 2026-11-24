package webtest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNoTempFiles(t *testing.T) {
	for _, tt := range []struct {
		name     string
		setup    func(testing.TB)
		wantFail bool
		wantMsg  string
	}{
		{name: "empty"},
		{"file", func(t testing.TB) {
			f, err := os.CreateTemp("", "upload-")
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}, true, `unexpected TMPDIR entries: ["upload-`},
		{"subdirectory", func(t testing.TB) {
			dir := filepath.Join(os.TempDir(), "uploads")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "part"), []byte("data"), 0600); err != nil {
				t.Fatal(err)
			}
		}, true, `unexpected TMPDIR entries: ["uploads"]`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// A real, non-parallel subtest owns the environment override.
			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			first := os.TempDir()
			checkFailure(t, func(t testing.TB) {
				check := NoTempFiles(t)
				if second := os.TempDir(); second == first || second != os.Getenv("TMPDIR") {
					t.Fatal("os.TempDir did not pick up the new TMPDIR")
				}
				if tt.setup != nil {
					tt.setup(t)
				}
				check()
			}, tt.wantFail, tt.wantMsg)
		})
	}
}
