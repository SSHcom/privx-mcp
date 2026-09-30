package date

import "strings"

// IsMidnightNoopWindow reports whether the configured HH:MM window is the
// "00:00-00:00" sentinel, which PrivX treats as "no time-window enforcement"
// rather than a zero-length interval.
func IsMidnightNoopWindow(startHHMM, endHHMM string) bool {
	return strings.TrimSpace(startHHMM) == "00:00" && strings.TrimSpace(endHHMM) == "00:00"
}
