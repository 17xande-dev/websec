// Package sessiontest checks an application's session store through test
// callbacks. It backdates stored rows so the store can use its usual clock.
package sessiontest

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/17xande-dev/websec/session"
)

// Harness connects Run to a store configured with Lifetime. Use an isolated
// test store: Sweep and Count operate on all users' sessions.
type Harness struct {
	Lifetime session.Lifetime

	NewUser func(t *testing.T) (user string)                                   // creates an enabled account
	Create  func(t *testing.T, user string) (token string)                     // sign in and return the raw cookie value
	Lookup  func(t *testing.T, token string) (user string, ok bool, err error) // request-time lookup, including touch

	// Backdate rewrites the stored creation and activity times, including any
	// derived fields such as a stored expiry.
	Backdate func(t *testing.T, token string, created, lastSeen time.Time)
	LastSeen func(t *testing.T, token string) time.Time // may be nil if Lifetime.IdleOff
	Sweep    func(t *testing.T) (removed int)
	Count    func(t *testing.T) int
	RawRows  func(t *testing.T) []string // every session column, with binary values rendered as hex

	Disable func(t *testing.T, user string)
	// ChangePassword runs the user's own password change from current and
	// returns current if kept, a new token if rotated, or "" if all of the
	// user's sessions ended.
	ChangePassword func(t *testing.T, user, current string) (still string)
	TouchEvery     time.Duration                   // the store's touch interval; zero means session.TouchEvery
	RevokeUser     func(t *testing.T, user string) // administrative or directory revocation

	// NotApplicable may skip disable, password-change, or revoke-user with
	// a non-blank reason, and only when the corresponding callback is nil.
	NotApplicable map[Case]string
}

// Case names a subtest. Only "disable", "password-change", and "revoke-user"
// can be used in Harness.NotApplicable.
type Case string

const m = time.Minute

// Run runs the session store conformance subtests. It fails before running
// any subtest if the harness is incomplete or its real lifetime cannot
// exercise the time fixtures.
func Run(t *testing.T, h Harness) {
	t.Helper()
	l := h.Lifetime
	if err := l.Validate(); err != nil {
		t.Fatalf("sessiontest: Harness.Lifetime is invalid: %v", err)
	}
	if l.Absolute < 10*m {
		t.Fatal("sessiontest: Absolute must be at least 10m for the suite's fixtures")
	}
	tau := h.TouchEvery
	switch {
	case tau < 0:
		t.Fatal("sessiontest: TouchEvery must not be negative")
	case tau == 0:
		tau = session.TouchEvery
	case tau < session.TouchEvery:
		t.Fatal("sessiontest: TouchEvery may only be coarser than session.TouchEvery")
	case l.IdleOff:
		t.Fatal("sessiontest: TouchEvery has no effect with IdleOff")
	}
	// Divide instead of multiplying so large durations cannot overflow.
	if !l.IdleOff && (l.Idle < 5*m || l.Idle/4 < tau || l.Absolute-l.Idle < 5*m) {
		t.Fatal("sessiontest: Idle must be at least 5m and 4*TouchEvery, and at least 5m shorter than Absolute; an idle limit that can never end a session before Absolute should be IdleOff")
	}
	if !l.IdleOff && h.LastSeen == nil {
		t.Fatal("sessiontest: LastSeen is required when idle is on")
	}
	for _, f := range []struct {
		name    string
		missing bool
	}{
		{"NewUser", h.NewUser == nil},
		{"Create", h.Create == nil},
		{"Lookup", h.Lookup == nil},
		{"Backdate", h.Backdate == nil},
		{"Sweep", h.Sweep == nil},
		{"Count", h.Count == nil},
		{"RawRows", h.RawRows == nil},
	} {
		if f.missing {
			t.Fatalf("sessiontest: %s is required", f.name)
		}
	}
	for c := range h.NotApplicable {
		switch c {
		case "disable", "password-change", "revoke-user":
		default:
			t.Fatalf("sessiontest: %q cannot be listed in NotApplicable", c)
		}
	}
	for _, f := range []struct {
		c       Case
		name    string
		missing bool
	}{
		{"disable", "Disable", h.Disable == nil},
		{"password-change", "ChangePassword", h.ChangePassword == nil},
		{"revoke-user", "RevokeUser", h.RevokeUser == nil},
	} {
		reason, optedOut := h.NotApplicable[f.c]
		if optedOut && !f.missing {
			t.Fatalf("sessiontest: NotApplicable[%s] set but its callback is provided; remove one", f.c)
		}
		if optedOut && strings.TrimSpace(reason) == "" {
			t.Fatalf("sessiontest: NotApplicable[%q] requires a reason", f.c)
		}
		if f.missing && !optedOut {
			t.Fatalf("sessiontest: %s is required unless NotApplicable[%q] gives a reason", f.name, f.c)
		}
	}
	if l.IdleOff {
		t.Log("idle off: idle and touch cases not applicable")
	}
	h.TouchEvery = tau

	for _, tc := range []struct {
		name Case
		run  func(Harness, *testing.T, time.Time)
	}{
		{"fresh", Harness.fresh},
		{"absolute", Harness.absolute},
		{"idle", Harness.idle},
		{"touch", Harness.touch},
		{"miss", Harness.misses},
		{"disable", Harness.disable},
		{"password-change", Harness.passwordChange},
		{"revoke-user", Harness.revokeUser},
		{"sweep", Harness.sweep},
		{"raw-token", Harness.rawToken},
		{"distinct-tokens", Harness.distinctTokens},
	} {
		t.Run(string(tc.name), func(sub *testing.T) {
			now := time.Now()
			if l.IdleOff && (tc.name == "idle" || tc.name == "touch") {
				sub.Skip("idle off")
			}
			if reason, ok := h.NotApplicable[tc.name]; ok {
				sub.Skipf("not applicable: %s", reason)
			}
			sub.Cleanup(func() {
				if sub.Skipped() {
					t.Errorf("sessiontest: case %s was skipped; use NotApplicable", tc.name)
				}
			})
			tc.run(h, sub, now)
		})
	}
}

// Check the store's result without putting a credential in test output.
func (h Harness) hit(t *testing.T, label, token, wantUser string) {
	t.Helper()
	user, ok, err := h.Lookup(t, token)
	if err != nil || !ok || user != wantUser {
		t.Errorf("%s: Lookup hit = %t, correct user = %t, error = %t; want a hit for the correct user without error", label, ok, user == wantUser, err != nil)
	}
}

func (h Harness) miss(t *testing.T, label, token string) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("%s: Lookup panicked (%T); want a miss without error", label, p)
		}
	}()
	_, ok, err := h.Lookup(t, token)
	if ok || err != nil {
		t.Errorf("%s: Lookup hit = %t, error = %t; want a miss without error", label, ok, err != nil)
	}
}

func (h Harness) fresh(t *testing.T, _ time.Time) {
	u, v := h.NewUser(t), h.NewUser(t)
	if u == v {
		t.Fatal("NewUser returned the same account twice")
	}
	a, b := h.Create(t, u), h.Create(t, v)
	h.hit(t, "first user", a, u)
	h.hit(t, "second user", b, v)
}

func (h Harness) backdateAbsolute(t *testing.T, token string, now time.Time, offset time.Duration) {
	t.Helper()
	h.Backdate(t, token, now.Add(-h.Lifetime.Absolute).Add(offset), now.Add(-m))
}

func (h Harness) absolute(t *testing.T, now time.Time) {
	u := h.NewUser(t)
	a, b := h.Create(t, u), h.Create(t, u)
	h.backdateAbsolute(t, a, now, -m)
	h.backdateAbsolute(t, b, now, m)
	h.miss(t, "past absolute deadline", a)
	h.hit(t, "before absolute deadline", b, u)
}

func (h Harness) backdateIdle(t *testing.T, token string, now time.Time, offset time.Duration) {
	t.Helper()
	h.Backdate(t, token, now.Add(-h.Lifetime.Idle-2*m), now.Add(-h.Lifetime.Idle+offset))
}

func (h Harness) idle(t *testing.T, now time.Time) {
	u := h.NewUser(t)
	a, b := h.Create(t, u), h.Create(t, u)
	h.backdateIdle(t, a, now, -m)
	h.backdateIdle(t, b, now, m)
	h.miss(t, "past idle deadline", a)
	h.hit(t, "before idle deadline", b, u)
}

func (h Harness) touch(t *testing.T, now time.Time) {
	u := h.NewUser(t)
	token := h.Create(t, u)
	tau := h.TouchEvery
	created := now.Add(-3 * tau)
	h.Backdate(t, token, created, now.Add(-2*tau))
	h.hit(t, "activity due for a touch", token, u)
	if got := h.LastSeen(t, token); got.Before(now.Add(-m)) || got.After(now.Add(m)) {
		t.Errorf("Lookup did not move LastSeen to within one minute of now (offset %v)", got.Sub(now))
	}

	// Seed a distinct timestamp so an unwanted write is visible even with
	// one-second storage precision.
	want := now.Add(-tau / 2)
	h.Backdate(t, token, created, want)
	h.hit(t, "activity inside the touch interval", token, u)
	if delta := h.LastSeen(t, token).Sub(want); delta <= -time.Second || delta >= time.Second {
		t.Errorf("Lookup changed LastSeen inside TouchEvery (offset %v from backdated time)", delta)
	}

	h.Backdate(t, token, created, now.Add(tau))
	// At the default interval the seed is itself within the allowed skew
	// window. Read it back at store precision to also require an actual write.
	future := h.LastSeen(t, token)
	h.hit(t, "activity recorded in the future", token, u)
	if got := h.LastSeen(t, token); got.Equal(future) || got.Before(now.Add(-m)) || got.After(now.Add(m)) {
		t.Errorf("Lookup did not rewrite future LastSeen to within one minute of now (offset %v)", got.Sub(now))
	}
}

const badEncoding = "sessiontest: token is neither hex nor base64; cannot build alternate encodings"

var base64Decoders = []*base64.Encoding{
	base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
}

func decodings(token string) [][]byte {
	var decoded [][]byte
	if b, err := hex.DecodeString(token); err == nil {
		decoded = append(decoded, b)
	}
	for _, enc := range base64Decoders {
		if b, err := enc.DecodeString(token); err == nil {
			decoded = append(decoded, b)
		}
	}
	return decoded
}

func unknownToken(token string) string {
	if b, err := hex.DecodeString(token); err == nil {
		rand.Read(b)
		return hex.EncodeToString(b)
	}
	for i, enc := range base64Decoders {
		if b, err := enc.DecodeString(token); err == nil {
			rand.Read(b)
			// Keep the token's byte length and padding, using the URL alphabet.
			return base64Decoders[i%2].EncodeToString(b)
		}
	}
	return ""
}

func (h Harness) misses(t *testing.T, now time.Time) {
	u := h.NewUser(t)
	live, expired := h.Create(t, u), h.Create(t, u)
	h.backdateAbsolute(t, expired, now, -m)
	for _, tc := range []struct{ label, token string }{
		{"empty token", ""},
		{"short token", "x"},
		{"oversized token", strings.Repeat("a", 1<<20)},
		{"token with NUL", live + "\x00"},
		{"token with trailing newline", live + "\n"},
		{"absolute-expired token", expired},
	} {
		h.miss(t, tc.label, tc.token)
	}

	seen := make(map[string]bool)
	_, hexErr := hex.DecodeString(live)
	for _, b := range decodings(live) {
		for i, s := range []string{
			hex.EncodeToString(b),
			base64.RawURLEncoding.EncodeToString(b),
			base64.URLEncoding.EncodeToString(b),
			base64.StdEncoding.EncodeToString(b),
		} {
			if s == live || seen[s] || (i == 0 && hexErr == nil && strings.EqualFold(s, live)) {
				continue
			}
			seen[s] = true
			h.miss(t, "alternate token encoding", s)
		}
	}
	if len(seen) == 0 {
		t.Fatal(badEncoding)
	}
	h.miss(t, "well-formed unknown token", unknownToken(live))
}

func (h Harness) twoUsers(t *testing.T) (u, a, b, v, c string) {
	t.Helper()
	u, v = h.NewUser(t), h.NewUser(t)
	a, b, c = h.Create(t, u), h.Create(t, u), h.Create(t, v)
	return
}

func (h Harness) disable(t *testing.T, _ time.Time) {
	u, a, b, v, c := h.twoUsers(t)
	h.Disable(t, u)
	h.miss(t, "disabled user's first session", a)
	h.miss(t, "disabled user's second session", b)
	h.hit(t, "other user's session", c, v)
}

func (h Harness) passwordChange(t *testing.T, _ time.Time) {
	u, a, b, v, c := h.twoUsers(t)
	still := h.ChangePassword(t, u, a)
	h.miss(t, "other session of the user changing password", b)
	h.hit(t, "other user's session", c, v)
	switch still {
	case "":
		h.miss(t, "current session after ending all sessions", a)
	case a:
		h.hit(t, "kept session", a, u)
	default:
		h.hit(t, "rotated session", still, u)
		h.miss(t, "old current session after rotation", a)
		if still == b {
			t.Error("password change returned the user's other session as the rotated session")
		}
	}
}

func (h Harness) revokeUser(t *testing.T, _ time.Time) {
	u, a, b, v, c := h.twoUsers(t)
	h.RevokeUser(t, u)
	h.miss(t, "revoked user's first session", a)
	h.miss(t, "revoked user's second session", b)
	h.hit(t, "other user's session", c, v)
}

func (h Harness) sweep(t *testing.T, now time.Time) {
	h.Sweep(t) // discard expired rows left by earlier cases or setup
	u := h.NewUser(t)
	live, expired := h.Create(t, u), h.Create(t, u)
	h.backdateAbsolute(t, expired, now, -m)
	want := 1
	if !h.Lifetime.IdleOff {
		h.backdateIdle(t, h.Create(t, u), now, -m)
		want++
	}
	before := h.Count(t)
	removed := h.Sweep(t)
	if removed != want {
		t.Errorf("Sweep removed %d rows, want %d", removed, want)
	}
	if after := h.Count(t); after != before-removed {
		t.Errorf("row count after Sweep = %d, want %d (before %d, reported removed %d)", after, before-removed, before, removed)
	}
	h.hit(t, "live session after sweep", live, u)
}

func (h Harness) rawToken(t *testing.T, _ time.Time) {
	u := h.NewUser(t)
	first := h.Create(t, u)
	rows := h.RawRows(t)
	n := len(rows)
	const missingRows = "sessiontest: RawRows returned nothing for stored sessions"
	if n == 0 {
		t.Fatal(missingRows)
	}
	checkRawToken(t, rows, first)

	second := h.Create(t, u)
	rows = h.RawRows(t)
	if len(rows) <= n {
		t.Fatal(missingRows)
	}
	checkRawToken(t, rows, first)
	checkRawToken(t, rows, second)
}

func checkRawToken(t *testing.T, rows []string, token string) {
	t.Helper()
	spellings := []string{token}
	for _, b := range decodings(token) {
		lower := hex.EncodeToString(b)
		spellings = append(spellings, lower, strings.ToUpper(lower))
		for _, enc := range base64Decoders {
			spellings = append(spellings, enc.EncodeToString(b))
		}
	}
	for _, row := range rows {
		for _, s := range spellings {
			if s != "" && strings.Contains(row, s) {
				t.Fatal("stored session columns contain the raw token or an encoding of it")
			}
		}
	}
}

func (h Harness) distinctTokens(t *testing.T, _ time.Time) {
	u := h.NewUser(t)
	seen := make(map[string]bool, 100)
	for i := range 100 {
		token := h.Create(t, u)
		if seen[token] {
			t.Fatalf("Create repeated a token on call %d", i+1)
		}
		seen[token] = true
		// Prefer hex when both decoders accept the text: reading a short hex
		// token as base64 would overstate its decoded size.
		b, err := hex.DecodeString(token)
		if err != nil {
			b, err = base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				b, err = base64.URLEncoding.DecodeString(token)
			}
		}
		if err != nil {
			t.Fatal(badEncoding)
		}
		if len(b) < 32 {
			t.Fatalf("token %d decodes to %d bytes, want at least 32", i+1, len(b))
		}
	}
}
