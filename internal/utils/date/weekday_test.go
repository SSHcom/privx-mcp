package date

import "testing"

func TestIsWeekdayInLocation_Match(t *testing.T) {
	at := testTimeUTC(t, "2026-07-06T09:30:00Z") // Monday

	ok, err := IsWeekdayInLocation(at, "UTC", []string{"MON", "WED"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected monday to be allowed")
	}
}

func TestIsWeekdayInLocation_NoMatch(t *testing.T) {
	at := testTimeUTC(t, "2026-07-07T09:30:00Z") // Tuesday

	ok, err := IsWeekdayInLocation(at, "UTC", []string{"MON", "WED"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected tuesday to be denied")
	}
}

func TestIsWeekdayInLocation_EmptyWeekdays(t *testing.T) {
	at := testTimeUTC(t, "2026-07-07T09:30:00Z")

	ok, err := IsWeekdayInLocation(at, "UTC", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected empty validity list to allow all days")
	}
}

func TestIsWeekdayInLocation_InvalidDayToken(t *testing.T) {
	at := testTimeUTC(t, "2026-07-07T09:30:00Z")

	_, err := IsWeekdayInLocation(at, "UTC", []string{"FUNDAY"})
	if err == nil {
		t.Fatal("expected invalid weekday token error")
	}
}
