package security

import "testing"

func TestPrepare_SanitizesNestedValuesInPlace(t *testing.T) {
	payload := map[string]any{
		"items": []any{
			map[string]any{"common_name": "web\u200B-01", "port": float64(22)},
		},
		"note": "clean value",
	}

	Prepare(payload)

	item := payload["items"].([]any)[0].(map[string]any)
	if item["common_name"] != "web-01" {
		t.Errorf("expected nested string sanitized in place, got %v", item["common_name"])
	}
	if item["port"] != float64(22) {
		t.Errorf("expected non-string value untouched, got %v", item["port"])
	}
}

func TestPrepare_KeysAreNotScanned(t *testing.T) {
	payload := map[string]any{
		"email":  "person@example.com",
		"delete": "no",
		"nested": map[string]any{"instruct": "fine"},
	}

	Prepare(payload)

	if payload["delete"] != "no" {
		t.Errorf("expected key to be left alone, got %v", payload["delete"])
	}
}

func TestPrepare_TopLevelString(t *testing.T) {
	cleaned := Prepare("host\u200Bname")
	if cleaned != "hostname" {
		t.Errorf("expected sanitized string returned, got %v", cleaned)
	}
}

func TestPrepare_ScalarsPassThrough(t *testing.T) {
	for _, value := range []any{nil, float64(3), true} {
		cleaned := Prepare(value)
		if cleaned != value {
			t.Errorf("expected %v unchanged, got %v", value, cleaned)
		}
	}
}

func TestPrepareResponse_ReplacesNestedWordKeepsRow(t *testing.T) {
	payload := map[string]any{
		"items": []any{
			map[string]any{"id": "h1", "common_name": "web-01"},
			map[string]any{"id": "h2", "comment": "please sudo this"},
		},
		"count":    float64(2),
		"returned": float64(2),
	}

	cleaned := PrepareResponse(payload, NewFilter([]string{"sudo"}))
	root := cleaned.(map[string]any)
	items := root["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("kept items = %d, want 2", len(items))
	}
	comment := items[1].(map[string]any)["comment"]
	if comment != "please [redacted] this" {
		t.Errorf("comment = %v", comment)
	}
	if root["count"] != float64(2) || root["returned"] != float64(2) {
		t.Errorf("paging changed: count=%v returned=%v", root["count"], root["returned"])
	}
	if _, ok := root["dropped"]; ok {
		t.Error("response filter must not inject dropped")
	}
}

func TestPrepareResponse_SubstringKept(t *testing.T) {
	payload := map[string]any{"comment": "ssh"}
	cleaned := PrepareResponse(payload, NewFilter([]string{"sh"}))
	if cleaned.(map[string]any)["comment"] != "ssh" {
		t.Errorf("expected substring kept, got %v", cleaned)
	}
}

func TestPrepareResponse_HiddenWordReplaced(t *testing.T) {
	payload := map[string]any{"comment": "please su\u200Bdo this"}
	PrepareResponse(payload, NewFilter([]string{"sudo"}))
	if payload["comment"] != "please [redacted] this" {
		t.Errorf("got %v", payload["comment"])
	}
}

func TestPrepareResponse_EmptyFilterOnlySanitizes(t *testing.T) {
	payload := map[string]any{"comment": "su\u200Bdo this"}
	PrepareResponse(payload, NewFilter(nil))
	if payload["comment"] != "sudo this" {
		t.Errorf("got %v", payload["comment"])
	}
}

func TestPrepareStrings_RedactsAndSanitizes(t *testing.T) {
	name := "ro\u200Bot"
	hostile := "please sudo this"
	filter := NewFilter([]string{"sudo"})

	PrepareStrings(filter, &name, &hostile)

	if name != "root" {
		t.Errorf("expected sanitized name, got %q", name)
	}
	if hostile != "please [redacted] this" {
		t.Errorf("expected redacted value, got %q", hostile)
	}
}
