package date

import (
	"fmt"
	"strings"
	"time"
)

const clockLayout = "15:04"

// IsWithinRangeOfTimeZone checks if time in the provided timezone is inside an
// HH:MM range. Start is inclusive and end is exclusive. Empty start/end are
// treated as open boundaries.
func IsWithinRangeOfTimeZone(at time.Time, timezone, startHHMM, endHHMM string) (bool, error) {
	loc, err := loadLocationOrUTC(timezone)
	if err != nil {
		return false, err
	}

	startMinute, hasStart, err := parseClockMinute(startHHMM)
	if err != nil {
		return false, fmt.Errorf("parse start time %q: %w", startHHMM, err)
	}

	endMinute, hasEnd, err := parseClockMinute(endHHMM)
	if err != nil {
		return false, fmt.Errorf("parse end time %q: %w", endHHMM, err)
	}

	if !hasStart && !hasEnd {
		return true, nil
	}

	current := at.In(loc)
	currentMinute := current.Hour()*60 + current.Minute()

	if hasStart && !hasEnd {
		return currentMinute >= startMinute, nil
	}

	if !hasStart && hasEnd {
		return currentMinute < endMinute, nil
	}

	if startMinute == endMinute {
		return true, nil
	}

	if startMinute < endMinute {
		return currentMinute >= startMinute && currentMinute < endMinute, nil
	}

	return currentMinute >= startMinute || currentMinute < endMinute, nil
}

func loadLocationOrUTC(timezone string) (*time.Location, error) {
	if strings.TrimSpace(timezone) == "" {
		return time.UTC, nil
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, fmt.Errorf("load timezone %q: %w", timezone, err)
	}

	return loc, nil
}

func parseClockMinute(value string) (minute int, hasValue bool, err error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, false, nil
	}

	parsed, err := time.Parse(clockLayout, trimmed)
	if err != nil {
		return 0, false, err
	}

	return parsed.Hour()*60 + parsed.Minute(), true, nil
}
