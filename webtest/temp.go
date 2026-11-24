package webtest

import (
	"os"
	"testing"
)

// NoTempFiles sets TMPDIR to a fresh directory and returns a check for
// anything left in it. Because it uses t.Setenv, do not call it in a parallel
// test or one with a parallel ancestor.
// A subtest's first t.TempDir call can create a directory under the watched
// TMPDIR, which the check will report as a leftover.
//
// It cannot see files created and removed before the check. In-process tests
// are stricter: they do not get net/http's automatic multipart cleanup.
func NoTempFiles(t testing.TB) (check func()) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return func() {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("check TMPDIR: %v", err)
		}
		if len(entries) != 0 {
			names := make([]string, 0, len(entries))
			for _, entry := range entries {
				names = append(names, entry.Name())
			}
			t.Fatalf("unexpected TMPDIR entries: %q", names)
		}
	}
}
