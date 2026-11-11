package common

import "testing"

func TestRequiredPathID(t *testing.T) {
	id, errResult := RequiredPathID(map[string]any{"id": "abc-1"}, "id")
	if errResult != nil {
		t.Fatalf("unexpected error: %s", errResult.Content[0].Text)
	}

	if id != "abc-1" {
		t.Fatalf("id = %q", id)
	}
}

func TestRequiredPathID_Missing(t *testing.T) {
	_, errResult := RequiredPathID(map[string]any{}, "id")
	if errResult == nil || errResult.Content[0].Text != "validation error: missing required field: id" {
		t.Fatalf("got %#v", errResult)
	}
}

func TestRequiredPathID_RejectsRelativeSegments(t *testing.T) {
	for _, value := range []string{".", "..", "../roles", `..\roles`, "a/b", `a\b`} {
		_, errResult := RequiredPathID(map[string]any{"id": value}, "id")
		if errResult == nil {
			t.Fatalf("accepted %q", value)
		}

		if errResult.Content[0].Text != "validation error: id is not a single path segment" {
			t.Fatalf("%q: %s", value, errResult.Content[0].Text)
		}
	}
}

func TestOptionalPathID_Empty(t *testing.T) {
	id, errResult := OptionalPathID(map[string]any{}, "user_id")
	if errResult != nil || id != "" {
		t.Fatalf("id=%q err=%v", id, errResult)
	}
}

func TestOptionalPathID_RejectsDotDot(t *testing.T) {
	_, errResult := OptionalPathID(map[string]any{"user_id": ".."}, "user_id")
	if errResult == nil {
		t.Fatal("accepted ..")
	}
}

func TestPathSegmentError_AllowsDottedHostname(t *testing.T) {
	if errResult := PathSegmentError("hostname", "privx.example.com"); errResult != nil {
		t.Fatal(errResult.Content[0].Text)
	}
}
