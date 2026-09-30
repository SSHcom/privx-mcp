package date

import "testing"

func TestIsWithinRangeInTimeZone_DayWindow_Inside(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T09:30:00Z")

	ok, err := IsWithinRangeOfTimeZone(at, "UTC", "09:00", "17:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected time to be inside day window")
	}
}

func TestIsWithinRangeInTimeZone_DayWindow_Outside(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T18:00:00Z")

	ok, err := IsWithinRangeOfTimeZone(at, "UTC", "09:00", "17:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected time to be outside day window")
	}
}

func TestIsWithinRangeInTimeZone_OvernightWindow_InsideAfterMidnight(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T01:30:00Z")

	ok, err := IsWithinRangeOfTimeZone(at, "UTC", "22:00", "06:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected time to be inside overnight window")
	}
}

func TestIsWithinRangeInTimeZone_OvernightWindow_Outside(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T12:00:00Z")

	ok, err := IsWithinRangeOfTimeZone(at, "UTC", "22:00", "06:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected time to be outside overnight window")
	}
}

func TestIsWithinRangeInTimeZone_TimezoneConversion(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T06:30:00Z") // 09:30 in Europe/Helsinki

	ok, err := IsWithinRangeOfTimeZone(at, "Europe/Helsinki", "09:00", "10:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected converted local time to be inside window")
	}
}

func TestIsWithinRangeInTimeZone_EqualBoundsMeansFullDay(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T23:59:00Z")

	ok, err := IsWithinRangeOfTimeZone(at, "UTC", "00:00", "00:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected equal bounds to represent full day window")
	}
}

func TestIsWithinRangeInTimeZone_OnlyStart(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T14:00:00Z")

	ok, err := IsWithinRangeOfTimeZone(at, "UTC", "13:00", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected time to be inside open-ended start window")
	}
}

func TestIsWithinRangeInTimeZone_OnlyEnd(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T09:00:00Z")

	ok, err := IsWithinRangeOfTimeZone(at, "UTC", "", "10:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected time to be inside open-ended end window")
	}
}

func TestIsWithinRangeInTimeZone_NoBounds(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T09:00:00Z")

	ok, err := IsWithinRangeOfTimeZone(at, "UTC", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected empty bounds to allow all times")
	}
}

func TestIsWithinRangeInTimeZone_InvalidTimezone(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T09:30:00Z")

	_, err := IsWithinRangeOfTimeZone(at, "Invalid/Timezone", "09:00", "17:00")
	if err == nil {
		t.Fatal("expected invalid timezone error")
	}
}

func TestIsWithinRangeInTimeZone_InvalidClockValue(t *testing.T) {
	at := testTimeUTC(t, "2026-07-03T09:30:00Z")

	_, err := IsWithinRangeOfTimeZone(at, "UTC", "25:00", "17:00")
	if err == nil {
		t.Fatal("expected invalid clock value error")
	}
}
