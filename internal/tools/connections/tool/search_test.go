package tool

import (
	"strings"
	"testing"
	"time"
)

func TestResolveConnectedWindow(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

	t.Run("defaults to last 7 days", func(t *testing.T) {
		start, end, errResult := resolveConnectedWindow("", "", now)
		if errResult != nil {
			t.Fatalf("unexpected error: %s", errResult.Content[0].Text)
		}
		if start != now.Add(-connectionSearchDefaultWindow).Format(time.RFC3339) {
			t.Errorf("start = %s", start)
		}
		if end != now.Format(time.RFC3339) {
			t.Errorf("end = %s", end)
		}
	})

	t.Run("start only anchors 7 days", func(t *testing.T) {
		raw := "2024-01-01T00:00:00Z"
		start, end, errResult := resolveConnectedWindow(raw, "", now)
		if errResult != nil {
			t.Fatalf("unexpected error: %s", errResult.Content[0].Text)
		}
		if start != raw {
			t.Errorf("start = %s", start)
		}
		wantEnd := time.Date(2024, 1, 8, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		if end != wantEnd {
			t.Errorf("end = %s, want %s", end, wantEnd)
		}
	})

	t.Run("end only anchors 7 days", func(t *testing.T) {
		raw := "2024-03-15T00:00:00Z"
		start, end, errResult := resolveConnectedWindow("", raw, now)
		if errResult != nil {
			t.Fatalf("unexpected error: %s", errResult.Content[0].Text)
		}
		wantStart := time.Date(2024, 3, 8, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		if start != wantStart {
			t.Errorf("start = %s, want %s", start, wantStart)
		}
		if end != raw {
			t.Errorf("end = %s", end)
		}
	})

	t.Run("accepts any 30 day window", func(t *testing.T) {
		startRaw := "2020-06-01T00:00:00Z"
		endRaw := "2020-07-01T00:00:00Z"
		start, end, errResult := resolveConnectedWindow(startRaw, endRaw, now)
		if errResult != nil {
			t.Fatalf("unexpected error: %s", errResult.Content[0].Text)
		}
		if start != startRaw || end != endRaw {
			t.Errorf("window = %s .. %s", start, end)
		}
	})

	t.Run("rejects more than 30 days", func(t *testing.T) {
		_, _, errResult := resolveConnectedWindow("2020-06-01T00:00:00Z", "2020-07-01T00:00:01Z", now)
		if errResult == nil {
			t.Fatal("expected error")
		} else if !strings.Contains(errResult.Content[0].Text, "cannot exceed 30 days") {
			t.Errorf("got %q", errResult.Content[0].Text)
		}
	})

	t.Run("rejects end before start", func(t *testing.T) {
		_, _, errResult := resolveConnectedWindow("2020-07-02T00:00:00Z", "2020-07-01T00:00:00Z", now)
		if errResult == nil {
			t.Fatal("expected error")
		} else if !strings.Contains(errResult.Content[0].Text, "must not be before") {
			t.Errorf("got %q", errResult.Content[0].Text)
		}
	})

	t.Run("rejects non-RFC3339", func(t *testing.T) {
		_, _, errResult := resolveConnectedWindow("yesterday", "", now)
		if errResult == nil {
			t.Fatal("expected error")
		} else if !strings.Contains(errResult.Content[0].Text, "connected_start must be RFC3339") {
			t.Errorf("got %q", errResult.Content[0].Text)
		}
	})
}
