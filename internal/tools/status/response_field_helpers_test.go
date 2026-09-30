package status

import (
	"encoding/json"
	"testing"
)

func sampleComponent() map[string]any {
	return map[string]any{
		"component_name": "API-PROXY",
		"component_type": "MICROSERVICE",
		"hostname":       "host-a",
		"status_uri":     "https://localhost/api-proxy/api/v1/status",
		"status": map[string]any{
			"version":    "43.0-72",
			"status":     "RUNNING",
			"start_time": "2026-08-07T20:00:07Z",
			"zdu":        map[string]any{"phase": "idle"},
			"status_details": []any{
				map[string]any{"k": "Build date", "v": "2026-03-12"},
			},
		},
		"created": "2026-08-20T10:20:02Z",
	}
}

func TestSelectDottedFields_NestedMerge(t *testing.T) {
	src := sampleComponent()
	out := SelectDottedFields(src, DefaultComponentFields())
	if out["component_name"] != "API-PROXY" || out["component_type"] != "MICROSERVICE" {
		t.Errorf("root = %v", out)
	}
	if _, ok := out["hostname"]; ok {
		t.Error("hostname should not be in defaults")
	}
	st, ok := out["status"].(map[string]any)
	if !ok {
		t.Fatalf("status = %v", out["status"])
	}
	if st["status"] != "RUNNING" || st["start_time"] != "2026-08-07T20:00:07Z" {
		t.Errorf("status projection = %v", st)
	}
	if _, ok := st["zdu"]; ok {
		t.Error("zdu should be dropped")
	}
	if _, ok := st["version"]; ok {
		t.Error("version should be dropped by defaults")
	}
}

func TestSelectDottedFields_UnknownSkipped(t *testing.T) {
	out := SelectDottedFields(sampleComponent(), []string{"missing", "status.nope", "component_name"})
	if out["component_name"] != "API-PROXY" {
		t.Errorf("component_name = %v", out["component_name"])
	}
	if _, ok := out["missing"]; ok {
		t.Error("missing should be skipped")
	}
	if _, ok := out["status"]; ok {
		t.Error("status.nope should not create a status object")
	}
}

func TestFormatComponents_HostnameMapDefaultProjection(t *testing.T) {
	payload := map[string]any{
		"host-a": []any{sampleComponent()},
	}
	out := FormatComponents(payload, "", false, DefaultComponentFields())
	items := out["host-a"]
	if len(items) != 1 {
		t.Fatalf("items = %v", items)
	}
	if _, ok := items[0]["status_uri"]; ok {
		t.Error("status_uri should be dropped")
	}
	st := items[0]["status"].(map[string]any)
	if _, ok := st["zdu"]; ok {
		t.Error("zdu should be dropped")
	}
}

func TestFormatComponents_RawKeepsNested(t *testing.T) {
	payload := map[string]any{
		"host-a": []any{sampleComponent()},
	}
	out := FormatComponents(payload, "", true, DefaultComponentFields())
	st := out["host-a"][0]["status"].(map[string]any)
	if _, ok := st["zdu"]; !ok {
		t.Error("raw should keep zdu")
	}
}

func TestFormatComponents_ArrayWrapsHostname(t *testing.T) {
	out := FormatComponents([]any{sampleComponent()}, "host-a", false, DefaultComponentFields())
	if _, ok := out["host-a"]; !ok {
		t.Fatalf("expected wrap under host-a, got %v", out)
	}
	if out["host-a"][0]["component_name"] != "API-PROXY" {
		t.Errorf("item = %v", out["host-a"][0])
	}
}

func TestFormatInstance_ProjectsComponents(t *testing.T) {
	payload := []any{sampleComponent()}
	got := FormatInstance(payload, false, DefaultComponentFields()).([]map[string]any)
	if len(got) != 1 {
		t.Fatalf("items = %v", got)
	}
	item := got[0]
	if item["component_name"] != "API-PROXY" || item["component_type"] != "MICROSERVICE" {
		t.Errorf("root projection = %v", item)
	}
	if _, ok := item["hostname"]; ok {
		t.Error("hostname should be dropped by defaults")
	}
	if _, ok := item["status_uri"]; ok {
		t.Error("status_uri should be dropped by defaults")
	}
	st := item["status"].(map[string]any)
	if st["status"] != "RUNNING" || st["start_time"] != "2026-08-07T20:00:07Z" {
		t.Errorf("status = %v", st)
	}
	if _, ok := st["zdu"]; ok {
		t.Error("zdu should be dropped")
	}
	if _, ok := st["version"]; ok {
		t.Error("version should be dropped by defaults")
	}
}

func TestFormatInstance_RawKeepsNested(t *testing.T) {
	payload := []any{sampleComponent()}
	got := FormatInstance(payload, true, DefaultComponentFields()).([]any)
	st := got[0].(map[string]any)["status"].(map[string]any)
	if _, ok := st["zdu"]; !ok {
		t.Error("raw should keep zdu")
	}
}

func TestFormatInstance_ExtraFields(t *testing.T) {
	payload := []any{sampleComponent()}
	got := FormatInstance(payload, false, []string{"component_name", "status.status", "status.version"}).([]map[string]any)
	st := got[0]["status"].(map[string]any)
	if st["version"] != "43.0-72" {
		t.Errorf("version = %v", st["version"])
	}
}

func TestDecodeJSON(t *testing.T) {
	raw := json.RawMessage(`{"a":1}`)
	v, err := DecodeJSON(&raw)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	m := v.(map[string]any)
	if m["a"].(float64) != 1 {
		t.Errorf("got %v", m)
	}
	if _, err := DecodeJSON(nil); err == nil {
		t.Fatal("expected error for nil")
	}
}
