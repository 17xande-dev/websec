// Package session calculates server-side session lifetimes without reading
// a clock or writing to a store.
package session

import (
	"errors"
	"time"
)

// Lifetime is a session's server-side limit. Every session must have an
// absolute limit, and the idle limit can only be disabled explicitly.
// Validate the policy before using it; the zero Lifetime is invalid.
type Lifetime struct {
	Idle     time.Duration // positive unless IdleOff is set
	IdleOff  bool          // disables idle expiry; Idle must be zero
	Absolute time.Duration // positive and at least Idle
}

// Default allows two hours of inactivity and twelve hours total.
var Default = Lifetime{Idle: 2 * time.Hour, Absolute: 12 * time.Hour}

// TouchEvery is the minimum interval between last-seen writes.
const TouchEvery = time.Minute

// Validate reports whether the lifetime has consistent idle and absolute limits.
func (l Lifetime) Validate() error {
	switch {
	case l.Absolute <= 0:
		return errors.New("session: Absolute must be positive")
	case l.IdleOff && l.Idle != 0:
		return errors.New("session: Idle must be zero when IdleOff is set")
	case !l.IdleOff && l.Idle <= 0:
		return errors.New("session: Idle must be positive unless IdleOff is set")
	case l.Idle > l.Absolute:
		return errors.New("session: Idle must not exceed Absolute")
	}
	return nil
}

// Expired reports whether now has reached either enabled deadline. A session
// created under a clock that was ahead keeps its absolute limit counted
// from the stored creation time. A future lastSeen does not cause idle
// expiry; the next request that touches the session should rewrite it to now.
func (l Lifetime) Expired(created, lastSeen, now time.Time) bool {
	if now.Before(created) {
		return false
	}
	return !now.Before(l.ExpiresAt(created, lastSeen))
}

// ExpiresAt returns the earlier of the absolute deadline and the enabled idle
// deadline, based on stored timestamps. Activity before creation counts as
// creation. Unlike Expired, ExpiresAt does not adjust for the current clock.
func (l Lifetime) ExpiresAt(created, lastSeen time.Time) time.Time {
	absolute := l.AbsoluteExpiry(created)
	if !l.IdleOff {
		if lastSeen.Before(created) {
			lastSeen = created
		}
		if idle := lastSeen.Add(l.Idle); idle.Before(absolute) {
			return idle
		}
	}
	return absolute
}

// AbsoluteExpiry returns the fixed deadline to use for a persistent session
// cookie; activity cannot extend it.
func (l Lifetime) AbsoluteExpiry(created time.Time) time.Time {
	return created.Add(l.Absolute)
}

// NeedsTouch reports whether lastSeen should be rewritten using TouchEvery.
func NeedsTouch(lastSeen, now time.Time) bool {
	return NeedsTouchAfter(lastSeen, now, TouchEvery)
}

// NeedsTouchAfter reports whether at least every has passed since lastSeen,
// or lastSeen is in the future. Rewriting a future value to now at the next
// request lets it extend the session by at most one request.
// NeedsTouchAfter panics if every is not positive.
func NeedsTouchAfter(lastSeen, now time.Time, every time.Duration) bool {
	if every <= 0 {
		panic("session: touch interval must be positive")
	}
	return lastSeen.After(now) || now.Sub(lastSeen) >= every
}
