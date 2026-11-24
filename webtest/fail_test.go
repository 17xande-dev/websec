package webtest

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// failRecorder embeds TB to satisfy its private method. The assertions use
// the methods below instead of failing the test that is checking them.
type failRecorder struct {
	testing.TB
	failed   bool
	messages []string
	logs     []string
}

func (*failRecorder) Helper() {}

func (r *failRecorder) Error(args ...any) {
	r.failed = true
	r.messages = append(r.messages, fmt.Sprint(args...))
}

func (r *failRecorder) Errorf(format string, args ...any) {
	r.Error(fmt.Sprintf(format, args...))
}

func (r *failRecorder) Fatal(args ...any) {
	r.Error(args...)
	r.FailNow()
}

func (r *failRecorder) Fatalf(format string, args ...any) {
	r.Errorf(format, args...)
	r.FailNow()
}

func (r *failRecorder) FailNow() {
	r.failed = true
	runtime.Goexit()
}

func (r *failRecorder) Failed() bool { return r.failed }

func (r *failRecorder) Logf(format string, args ...any) {
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}

func recordFailure(t testing.TB, check func(testing.TB)) *failRecorder {
	done := make(chan *failRecorder, 1)
	go func() {
		r := &failRecorder{TB: t}
		defer func() { done <- r }()
		check(r)
	}()
	return <-done
}

func checkFailure(t *testing.T, check func(testing.TB), wantFail bool, wantMsg string) {
	t.Helper()
	r := recordFailure(t, check)
	if r.Failed() != wantFail || !strings.Contains(strings.Join(r.messages, "\n"), wantMsg) {
		t.Errorf("failed = %v, messages = %q; want failed = %v, message containing %q",
			r.Failed(), r.messages, wantFail, wantMsg)
	}
}

func TestFailRecorder(t *testing.T) {
	for _, tt := range []struct {
		name     string
		check    func(testing.TB)
		wantFail bool
		wantMsg  string
		wantLog  string
	}{
		{"pass", func(t testing.TB) { t.Helper(); t.Logf("note %d", 1) }, false, "", "note 1"},
		{"error", func(t testing.TB) { t.Error("error"); t.Logf("continued") }, true, "error", "continued"},
		{"errorf", func(t testing.TB) { t.Errorf("error %d", 2); t.Logf("continued") }, true, "error 2", "continued"},
		{"fatal", func(t testing.TB) { t.Fatal("fatal"); t.Logf("continued") }, true, "fatal", ""},
		{"fatalf", func(t testing.TB) { t.Fatalf("fatal %d", 3); t.Logf("continued") }, true, "fatal 3", ""},
		{"fail now", func(t testing.TB) { t.FailNow(); t.Logf("continued") }, true, "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := recordFailure(t, tt.check)
			if r.Failed() != tt.wantFail || strings.Join(r.messages, "\n") != tt.wantMsg || strings.Join(r.logs, "\n") != tt.wantLog {
				t.Errorf("failed = %v, messages = %q, logs = %q; want %v, %q, %q",
					r.Failed(), r.messages, r.logs, tt.wantFail, tt.wantMsg, tt.wantLog)
			}
		})
	}
}
