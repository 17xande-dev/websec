package session

import (
	"testing"
	"time"
)

func TestClampFutureLastSeen(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	past := now.Add(-time.Nanosecond)
	// Expired cannot distinguish now from a future lastSeen with a positive
	// idle limit: neither is old enough to expire. Check the clamp directly.
	for _, tc := range []struct {
		name           string
		lastSeen, want time.Time
	}{
		{"past", past, past},
		{"present", now, now},
		{"future", now.Add(time.Nanosecond), now},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampFutureLastSeen(tc.lastSeen, now); !got.Equal(tc.want) {
				t.Errorf("clampFutureLastSeen() = %v, want %v", got, tc.want)
			}
		})
	}
}
