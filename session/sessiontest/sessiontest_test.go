package sessiontest_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/17xande-dev/websec/session"
	"github.com/17xande-dev/websec/session/sessiontest"
)

type row struct {
	user              string
	created, lastSeen time.Time
	raw               string // populated only by the raw-token mutation
}

type reference struct {
	lifetime session.Lifetime
	every    time.Duration
	mutation string
	format   string
	users    map[string]bool // true if disabled
	rows     map[[sha256.Size]byte]*row
}

func (s *reference) encode(b []byte) string {
	switch s.format {
	case "hex":
		return hex.EncodeToString(b)
	case "upper-hex":
		return strings.ToUpper(hex.EncodeToString(b))
	case "padded":
		return base64.URLEncoding.EncodeToString(b)
	default:
		return base64.RawURLEncoding.EncodeToString(b)
	}
}

func (s *reference) tokenBytes() int {
	switch s.mutation {
	case "short-token":
		return 16
	case "short-hex-token":
		return 31
	default:
		return 32
	}
}

func (s *reference) key(token string) ([sha256.Size]byte, bool) {
	var b []byte
	var err error
	switch s.format {
	case "hex", "upper-hex":
		b, err = hex.DecodeString(token)
	case "padded":
		b, err = base64.URLEncoding.DecodeString(token)
	default:
		b, err = base64.RawURLEncoding.DecodeString(token)
	}
	if err == nil && len(b) == s.tokenBytes() {
		canonical := s.encode(b)
		if canonical == token || (s.format == "upper-hex" && strings.EqualFold(canonical, token)) {
			return sha256.Sum256(b), true
		}
	}
	if s.mutation == "decode-alternates" && !strings.ContainsAny(token, "\r\n") {
		for _, decode := range []func(string) ([]byte, error){
			hex.DecodeString, base64.RawURLEncoding.DecodeString, base64.URLEncoding.DecodeString,
			base64.RawStdEncoding.DecodeString, base64.StdEncoding.DecodeString,
		} {
			if b, err := decode(token); err == nil && len(b) == s.tokenBytes() {
				return sha256.Sum256(b), true
			}
		}
	}
	return [sha256.Size]byte{}, false
}

func (s *reference) expired(r *row, now time.Time, sweep bool) bool {
	l := s.lifetime
	if (!sweep && s.mutation == "ignore-idle") || (sweep && s.mutation == "sweep-ignores-idle") {
		l.IdleOff = true
	}
	lastSeen := r.lastSeen
	if !sweep && s.mutation == "idle-from-created" {
		lastSeen = r.created
	}
	if !sweep && s.mutation == "ignore-absolute" {
		return !l.IdleOff && !now.Before(lastSeen.Add(l.Idle))
	}
	return l.Expired(r.created, lastSeen, now)
}

func (s *reference) lookup(_ *testing.T, token string) (string, bool, error) {
	k, valid := s.key(token)
	if !valid {
		switch s.mutation {
		case "malformed-error":
			return "", false, errors.New("malformed token")
		case "malformed-panic":
			panic("malformed token")
		}
		return "", false, nil
	}
	r, ok := s.rows[k]
	now := time.Now().Truncate(time.Second)
	if !ok || (s.users[r.user] && s.mutation != "disabled-accepted") || s.expired(r, now, false) {
		return "", false, nil
	}
	every := s.every
	if every == 0 {
		every = session.TouchEvery
	}
	if !s.lifetime.IdleOff && s.mutation != "never-touch" &&
		(s.mutation != "ignore-future-touch" || !r.lastSeen.After(now)) &&
		(s.mutation == "always-touch" || session.NeedsTouchAfter(r.lastSeen, now, every)) {
		r.lastSeen = now
	}
	return r.user, true, nil
}

func (s *reference) sweep(_ *testing.T) (removed int) {
	if s.mutation == "sweep-nothing" {
		return 0
	}
	now := time.Now()
	for k, r := range s.rows {
		if s.mutation == "sweep-live" || s.expired(r, now, true) {
			delete(s.rows, k)
			removed++
		}
	}
	return removed
}

func (s *reference) harness() sessiontest.Harness {
	return sessiontest.Harness{
		Lifetime: s.lifetime,
		NewUser: func(t *testing.T) string {
			user := fmt.Sprint(len(s.users) + 1)
			s.users[user] = false
			return user
		},
		Create: s.create,
		Lookup: s.lookup,
		Backdate: func(t *testing.T, token string, created, lastSeen time.Time) {
			k, _ := s.key(token)
			r := s.rows[k]
			r.created, r.lastSeen = created.Truncate(time.Second), lastSeen.Truncate(time.Second)
		},
		LastSeen: func(t *testing.T, token string) time.Time {
			k, _ := s.key(token)
			return s.rows[k].lastSeen
		},
		Sweep: s.sweep,
		Count: func(t *testing.T) int { return len(s.rows) },
		RawRows: func(t *testing.T) []string {
			var cells []string
			for k, r := range s.rows {
				cells = append(cells, hex.EncodeToString(k[:]), r.user, r.created.String(), r.lastSeen.String(), r.raw)
			}
			return cells
		},
		Disable: func(t *testing.T, user string) {
			if s.mutation == "disable-one" {
				for k, r := range s.rows {
					if r.user == user {
						delete(s.rows, k)
						break
					}
				}
				return
			}
			s.users[user] = true
		},
		ChangePassword: s.changePassword,
		RevokeUser: func(t *testing.T, user string) {
			spare := s.mutation == "revoke-spares-one"
			for k, r := range s.rows {
				if r.user == user {
					if spare {
						spare = false
						continue
					}
					delete(s.rows, k)
				}
			}
		},
	}
}

func (s *reference) create(_ *testing.T, user string) string {
	b := make([]byte, s.tokenBytes())
	rand.Read(b)
	token := s.encode(b)
	now := time.Now().Truncate(time.Second)
	r := &row{user: user, created: now, lastSeen: now}
	if s.mutation == "raw-token" {
		r.raw = token
	}
	s.rows[sha256.Sum256(b)] = r
	return token
}

func (s *reference) changePassword(t *testing.T, user, current string) string {
	key, _ := s.key(current)
	removeCurrent := false
	switch s.mutation {
	case "password-end-all", "password-ends-all", "password-rotate":
		removeCurrent = true
	}
	for k, r := range s.rows {
		if s.mutation == "password-ends-other-user" && r.user != user {
			delete(s.rows, k)
		}
		if r.user == user && (k != key || removeCurrent) && s.mutation != "password-keeps-all" {
			delete(s.rows, k)
		}
	}
	switch s.mutation {
	case "password-end-all", "password-reports-ended":
		return ""
	case "password-rotate", "password-rotate-keeps-old":
		return s.create(t, user)
	default:
		return current
	}
}

func newReference(l session.Lifetime, mutation, format string) sessiontest.Harness {
	s := reference{
		lifetime: l,
		mutation: mutation,
		format:   format,
		users:    make(map[string]bool),
		rows:     make(map[[sha256.Size]byte]*row),
	}
	return s.harness()
}

func TestReference(t *testing.T) {
	for _, format := range []string{"base64url", "padded", "hex", "upper-hex"} {
		t.Run(format, func(t *testing.T) {
			sessiontest.Run(t, newReference(session.Default, "", format))
		})
	}
	for _, mode := range []string{"keep", "password-rotate", "password-end-all"} {
		t.Run(mode, func(t *testing.T) {
			sessiontest.Run(t, newReference(session.Default, mode, "base64url"))
		})
	}
	t.Run("hourly-touch", func(t *testing.T) {
		h := hourlyReference(time.Hour)
		sessiontest.Run(t, h)
	})
}

func hourlyReference(actual time.Duration) sessiontest.Harness {
	s := reference{
		lifetime: session.Lifetime{Idle: 4 * time.Hour, Absolute: session.Default.Absolute},
		every:    actual,
		users:    make(map[string]bool),
		rows:     make(map[[sha256.Size]byte]*row),
	}
	h := s.harness()
	h.TouchEvery = time.Hour
	return h
}

const childMode = "WEBSEC_SESSIONTEST_CHILD"

// Run real testing.T failures in a child process: a failed subtest would
// otherwise fail the parent test that intentionally exercises the mutation.
func TestConformanceChild(t *testing.T) {
	mode := os.Getenv(childMode)
	if mode == "" {
		t.Skip("only run by conformance assertions")
	}
	h := newReference(session.Default, mode, "base64url")
	switch mode {
	case "idle-off", "sweep-nothing-idle-off", "short-absolute", "touch-with-idle-off":
		l := session.Lifetime{Absolute: session.Default.Absolute, IdleOff: true}
		if mode == "short-absolute" {
			l.Absolute = 2 * time.Minute
		}
		mutation := strings.TrimSuffix(mode, "-idle-off")
		h = newReference(l, mutation, "base64url")
		h.LastSeen = nil
		if mode == "touch-with-idle-off" {
			h.TouchEvery = time.Minute
		}
	case "equal-limits":
		h.Lifetime.Idle = h.Lifetime.Absolute
	case "short-idle":
		h.Lifetime.Idle = 2 * time.Minute
	case "invalid-lifetime":
		h.Lifetime = session.Lifetime{}
	case "missing-last-seen":
		h.LastSeen = nil
	case "missing-disable":
		h.Disable = nil
	case "missing-count":
		h.Count = nil
	case "opt-out":
		h.Disable, h.ChangePassword, h.RevokeUser = nil, nil, nil
		h.NotApplicable = map[sessiontest.Case]string{
			"disable": "no disabled accounts", "password-change": "no local password", "revoke-user": "no administrative revoke",
		}
	case "blank-reason":
		h.Disable = nil
		h.NotApplicable = map[sessiontest.Case]string{"disable": " \t"}
	case "idle-opt-out":
		h.NotApplicable = map[sessiontest.Case]string{"idle": "not tested"}
	case "opt-out-with-disable":
		h.NotApplicable = map[sessiontest.Case]string{"disable": "no disabled accounts"}
	case "callback-skip":
		h.Disable = func(t *testing.T, _ string) { t.Skip("callback skipped") }
	case "raw-rows-empty":
		h.RawRows = func(*testing.T) []string { return nil }
	case "raw-rows-static":
		h.RawRows = func(*testing.T) []string { return []string{"not a session row"} }
	case "touch-negative":
		h.TouchEvery = -time.Second
	case "touch-too-fine":
		h.TouchEvery = 30 * time.Second
	case "touch-too-coarse":
		h.TouchEvery = time.Hour
	case "touch-huge":
		h.TouchEvery = time.Duration(1<<63 - 1)
	case "touch-declared-hourly":
		h = hourlyReference(time.Minute)
	case "short-hex-token":
		h = newReference(session.Default, mode, "hex")
	}
	sessiontest.Run(t, h)
}

func runChild(t *testing.T, mode string, wantFail bool) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestConformanceChild$", "-test.v")
	cmd.Env = append(os.Environ(), childMode+"="+mode, "GORACE=atexit_sleep_ms=0")
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if wantFail {
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			t.Fatalf("child error = %v, want exit status 1:\n%s", err, out)
		}
	} else if err != nil {
		t.Fatalf("child error = %v, want success:\n%s", err, out)
	}
	return string(out)
}

func TestMutations(t *testing.T) {
	failedCase := regexp.MustCompile(`(?m)^\s*--- FAIL: TestConformanceChild/(\S+)`)
	for _, tc := range []struct {
		mutation string
		cases    []string
		message  string
	}{
		// The absolute case and the dedicated idle/miss cases use some
		// overlapping fixtures, so these failures are not mutually exclusive.
		{"ignore-absolute", []string{"absolute", "miss"}, "past absolute deadline"},
		{"ignore-idle", []string{"idle"}, "past idle deadline"},
		{"idle-from-created", []string{"absolute", "idle"}, "before idle deadline"},
		{"always-touch", []string{"touch"}, "Lookup changed LastSeen inside TouchEvery"},
		{"never-touch", []string{"touch"}, "Lookup did not move LastSeen"},
		{"ignore-future-touch", []string{"touch"}, "Lookup did not rewrite future LastSeen"},
		{"touch-declared-hourly", []string{"touch"}, "Lookup changed LastSeen inside TouchEvery"},
		{"malformed-error", []string{"miss"}, "short token: Lookup hit = false, error = true"},
		{"malformed-panic", []string{"miss"}, "short token: Lookup panicked"},
		{"decode-alternates", []string{"miss"}, "alternate token encoding: Lookup hit = true"},
		{"disable-one", []string{"disable"}, "session: Lookup hit = true"},
		{"disabled-accepted", []string{"disable"}, "disabled user's second session: Lookup hit = true"},
		{"password-ends-all", []string{"password-change"}, "kept session: Lookup hit = false"},
		{"password-keeps-all", []string{"password-change"}, "other session of the user changing password: Lookup hit = true"},
		{"password-reports-ended", []string{"password-change"}, "current session after ending all sessions: Lookup hit = true"},
		{"password-rotate-keeps-old", []string{"password-change"}, "old current session after rotation: Lookup hit = true"},
		{"password-ends-other-user", []string{"password-change"}, "other user's session: Lookup hit = false"},
		{"revoke-spares-one", []string{"revoke-user"}, "session: Lookup hit = true"},
		{"sweep-live", []string{"sweep"}, "live session after sweep: Lookup hit = false"},
		{"sweep-ignores-idle", []string{"sweep"}, "Sweep removed 1 rows, want 2"},
		{"sweep-nothing", []string{"sweep"}, "Sweep removed 0 rows, want 2"},
		{"sweep-nothing-idle-off", []string{"sweep"}, "Sweep removed 0 rows, want 1"},
		{"raw-token", []string{"raw-token"}, "stored session columns contain the raw token"},
		{"raw-rows-empty", []string{"raw-token"}, "sessiontest: RawRows returned nothing for stored sessions"},
		{"raw-rows-static", []string{"raw-token"}, "sessiontest: RawRows returned nothing for stored sessions"},
		{"short-token", []string{"distinct-tokens"}, "decodes to 16 bytes"},
		{"short-hex-token", []string{"distinct-tokens"}, "decodes to 31 bytes"},
	} {
		t.Run(tc.mutation, func(t *testing.T) {
			out := runChild(t, tc.mutation, true)
			var got []string
			for _, match := range failedCase.FindAllStringSubmatch(out, -1) {
				got = append(got, match[1])
			}
			if !slices.Equal(got, tc.cases) {
				t.Fatalf("failing cases = %v, want %v:\n%s", got, tc.cases, out)
			}
			if !strings.Contains(out, tc.message) {
				t.Fatalf("missing mutation diagnostic %q:\n%s", tc.message, out)
			}
		})
	}
}

func TestBadConfigurations(t *testing.T) {
	const idleMessage = "Idle must be at least 5m and 4*TouchEvery, and at least 5m shorter than Absolute; an idle limit that can never end a session before Absolute should be IdleOff"
	for _, tc := range []struct{ mode, message string }{
		{"equal-limits", idleMessage},
		{"short-absolute", "Absolute must be at least 10m for the suite's fixtures"},
		{"short-idle", idleMessage},
		{"invalid-lifetime", "Harness.Lifetime is invalid: session: Absolute must be positive"},
		{"missing-last-seen", "LastSeen is required when idle is on"},
		{"missing-disable", `Disable is required unless NotApplicable["disable"] gives a reason`},
		{"missing-count", "Count is required"},
		{"blank-reason", `NotApplicable["disable"] requires a reason`},
		{"idle-opt-out", `"idle" cannot be listed in NotApplicable`},
		{"opt-out-with-disable", "NotApplicable[disable] set but its callback is provided; remove one"},
		{"touch-negative", "TouchEvery must not be negative"},
		{"touch-too-fine", "TouchEvery may only be coarser than session.TouchEvery"},
		{"touch-too-coarse", idleMessage},
		{"touch-huge", idleMessage},
		{"touch-with-idle-off", "TouchEvery has no effect with IdleOff"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			out := runChild(t, tc.mode, true)
			if !strings.Contains(out, "sessiontest: "+tc.message) || strings.Contains(out, "=== RUN   TestConformanceChild/") {
				t.Fatalf("want configuration failure %q before any case runs:\n%s", tc.message, out)
			}
		})
	}
}

func TestCallbackSkipFailsParent(t *testing.T) {
	out := runChild(t, "callback-skip", true)
	for _, message := range []string{
		"sessiontest: case disable was skipped; use NotApplicable",
		"--- FAIL: TestConformanceChild (",
		"--- SKIP: TestConformanceChild/disable (",
	} {
		if !strings.Contains(out, message) {
			t.Errorf("missing %q:\n%s", message, out)
		}
	}
}

func TestVisibleSkips(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		messages []string
	}{
		{"opt-out", []string{"not applicable: no disabled accounts", "not applicable: no local password", "not applicable: no administrative revoke"}},
		{"idle-off", []string{"idle off: idle and touch cases not applicable", "--- SKIP: TestConformanceChild/idle", "--- SKIP: TestConformanceChild/touch", "--- PASS: TestConformanceChild/sweep"}},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			out := runChild(t, tc.mode, false)
			for _, message := range tc.messages {
				if !strings.Contains(out, message) {
					t.Errorf("missing %q:\n%s", message, out)
				}
			}
		})
	}
}
