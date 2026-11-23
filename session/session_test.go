package session_test

import (
	"testing"
	"time"

	"github.com/17xande-dev/websec/session"
)

func TestDefault(t *testing.T) {
	want := session.Lifetime{Idle: 2 * time.Hour, Absolute: 12 * time.Hour}
	if got := session.Default; got != want {
		t.Errorf("Default = %+v, want %+v", got, want)
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		lifetime session.Lifetime
		wantErr  bool
	}{
		{"default", session.Default, false},
		{"equal limits", session.Lifetime{Idle: time.Hour, Absolute: time.Hour}, false},
		{"idle disabled", session.Lifetime{IdleOff: true, Absolute: time.Hour}, false},
		{"zero lifetime", session.Lifetime{}, true},
		{"missing absolute with idle off", session.Lifetime{IdleOff: true}, true},
		{"missing absolute with idle on", session.Lifetime{Idle: time.Hour}, true},
		{"negative absolute", session.Lifetime{IdleOff: true, Absolute: -time.Nanosecond}, true},
		{"negative idle", session.Lifetime{Idle: -time.Nanosecond, Absolute: time.Hour}, true},
		{"missing idle", session.Lifetime{Absolute: time.Hour}, true},
		{"idle provided but disabled", session.Lifetime{Idle: time.Minute, IdleOff: true, Absolute: time.Hour}, true},
		{"idle exceeds absolute", session.Lifetime{Idle: time.Hour + time.Nanosecond, Absolute: time.Hour}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.lifetime.Validate(); (err != nil) != tc.wantErr {
				t.Errorf("Validate() = %v, want error: %t", err, tc.wantErr)
			}
		})
	}
}

func TestExpired(t *testing.T) {
	created := time.Unix(0, 0).UTC()
	seen := created.Add(time.Hour)
	idle := created.Add(3 * time.Hour)
	absolute := created.Add(12 * time.Hour)
	off := session.Lifetime{IdleOff: true, Absolute: 12 * time.Hour}
	var zero time.Time
	for _, tc := range []struct {
		name                   string
		lifetime               session.Lifetime
		created, lastSeen, now time.Time
		want                   bool
	}{
		{"idle just before", session.Default, created, seen, idle.Add(-time.Nanosecond), false},
		{"idle exact", session.Default, created, seen, idle, true},
		{"idle just after", session.Default, created, seen, idle.Add(time.Nanosecond), true},
		{"absolute just before", session.Default, created, absolute.Add(-time.Minute), absolute.Add(-time.Nanosecond), false},
		{"absolute exact", session.Default, created, absolute.Add(-time.Minute), absolute, true},
		{"absolute just after", session.Default, created, absolute.Add(-time.Minute), absolute.Add(time.Nanosecond), true},
		{"idle disabled", off, created, seen, idle, false},
		{"absolute with idle disabled", off, created, seen, absolute, true},
		{"last seen before creation", session.Default, created, created.Add(-time.Hour), seen, false},
		{"zero last seen at idle deadline", session.Default, created, zero, created.Add(2 * time.Hour), true},
		{"zero timestamps", session.Default, zero, zero, zero, false},
		{"future last seen before absolute deadline", session.Default, created, absolute, idle, false},
		{"future last seen cannot override absolute", session.Default, created, absolute.Add(time.Hour), absolute, true},
		{"clock before creation", session.Default, created, seen, created.Add(-time.Nanosecond), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.lifetime.Expired(tc.created, tc.lastSeen, tc.now); got != tc.want {
				t.Errorf("Expired() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestExpiresAt(t *testing.T) {
	created := time.Unix(0, 0).UTC()
	absolute := created.Add(12 * time.Hour)
	off := session.Lifetime{IdleOff: true, Absolute: 12 * time.Hour}
	for _, tc := range []struct {
		name     string
		lifetime session.Lifetime
		lastSeen time.Time
		want     time.Time
	}{
		{"idle after last activity", session.Default, created.Add(time.Hour), created.Add(3 * time.Hour)},
		{"absolute caps idle", session.Default, absolute.Add(-time.Minute), absolute},
		{"equal deadlines", session.Default, created.Add(10 * time.Hour), absolute},
		{"idle disabled", off, created, absolute},
		{"last seen before creation", session.Default, created.Add(-time.Hour), created.Add(2 * time.Hour)},
		{"zero last seen", session.Default, time.Time{}, created.Add(2 * time.Hour)},
		{"stored timestamp independent of clock rollback", session.Default, created.Add(2 * time.Hour), created.Add(4 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.lifetime.ExpiresAt(created, tc.lastSeen); !got.Equal(tc.want) {
				t.Errorf("ExpiresAt() = %v, want %v", got, tc.want)
			}
			if got := tc.lifetime.AbsoluteExpiry(created); !got.Equal(absolute) {
				t.Errorf("AbsoluteExpiry() = %v, want %v", got, absolute)
			}
		})
	}
}

func TestNeedsTouch(t *testing.T) {
	seen := time.Unix(0, 0).UTC()
	var zero time.Time
	for _, tc := range []struct {
		name          string
		lastSeen, now time.Time
		want          bool
	}{
		{"just before", seen, seen.Add(time.Minute - time.Nanosecond), false},
		{"exact", seen, seen.Add(time.Minute), true},
		{"just after", seen, seen.Add(time.Minute + time.Nanosecond), true},
		{"clock went backwards", seen, seen.Add(-time.Minute), false},
		{"zero timestamps", zero, zero, false},
		{"zero last seen", zero, seen, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := session.NeedsTouch(tc.lastSeen, tc.now); got != tc.want {
				t.Errorf("NeedsTouch() = %t, want %t", got, tc.want)
			}
		})
	}
}
