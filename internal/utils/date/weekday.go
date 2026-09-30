package date

import (
	"fmt"
	"strings"
	"time"
)

var weekdayByToken = map[string]time.Weekday{
	"MON":       time.Monday,
	"MONDAY":    time.Monday,
	"TUE":       time.Tuesday,
	"TUES":      time.Tuesday,
	"TUESDAY":   time.Tuesday,
	"WED":       time.Wednesday,
	"WEDNESDAY": time.Wednesday,
	"THU":       time.Thursday,
	"THUR":      time.Thursday,
	"THURS":     time.Thursday,
	"THURSDAY":  time.Thursday,
	"FRI":       time.Friday,
	"FRIDAY":    time.Friday,
	"SAT":       time.Saturday,
	"SATURDAY":  time.Saturday,
	"SUN":       time.Sunday,
	"SUNDAY":    time.Sunday,
}

// IsWeekdayInLocation checks whether the local weekday in timezone is included in weekdays.
// Empty weekdays means all days are allowed.
func IsWeekdayInLocation(at time.Time, timezone string, weekdays []string) (bool, error) {
	if len(weekdays) == 0 {
		return true, nil
	}

	loc, err := loadLocationOrUTC(timezone)
	if err != nil {
		return false, err
	}

	allowed := make(map[time.Weekday]struct{}, len(weekdays))
	for _, value := range weekdays {
		token := strings.ToUpper(strings.TrimSpace(value))

		weekday, ok := weekdayByToken[token]
		if !ok {
			return false, fmt.Errorf("invalid weekday token %q", value)
		}

		allowed[weekday] = struct{}{}
	}

	_, ok := allowed[at.In(loc).Weekday()]

	return ok, nil
}
