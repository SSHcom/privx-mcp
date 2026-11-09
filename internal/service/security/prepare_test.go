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

func TestPrepareExcept_KeepsNamedSubtree(t *testing.T) {
	secret := "p\u200Bass\u202Eword"
	payload := map[string]any{
		"name": "db\u200B",
		"data": map[string]any{
			"password": secret,
			"notes":    []any{"line\u0001"},
		},
		"read_roles": []any{
			map[string]any{"name": "ad\u200Bmin"},
		},
	}

	PrepareExcept(payload, []string{"data"})

	data := payload["data"].(map[string]any)
	if data["password"] != secret {
		t.Errorf("password = %q", data["password"])
	}
	if data["notes"].([]any)[0] != "line\u0001" {
		t.Errorf("nested secret = %q", data["notes"].([]any)[0])
	}
	if payload["name"] != "db" {
		t.Errorf("name = %q", payload["name"])
	}
	role := payload["read_roles"].([]any)[0].(map[string]any)
	if role["name"] != "admin" {
		t.Errorf("role name = %q", role["name"])
	}
}

func TestPrepareExcept_KeepsArrayField(t *testing.T) {
	bind := "bind\u00A0secret"
	entra := "entra\u200Bsecret"
	payload := map[string]any{
		"comment": "note\u200B",
		"items": []any{
			map[string]any{
				"name": "vault\u200B",
				"data": map[string]any{"password": "p\u200Bass"},
			},
		},
		"endpoints": []any{
			map[string]any{
				"ldap_address":        "dc\u200B.example",
				"ldap_bind_password":  bind,
				"entra_client_secret": entra,
			},
		},
	}

	PrepareExcept(payload, []string{
		"items[].data",
		"endpoints[].ldap_bind_password",
		"endpoints[].entra_client_secret",
	})

	if payload["comment"] != "note" {
		t.Errorf("comment = %q", payload["comment"])
	}
	item := payload["items"].([]any)[0].(map[string]any)
	if item["name"] != "vault" {
		t.Errorf("item name = %q", item["name"])
	}
	if item["data"].(map[string]any)["password"] != "p\u200Bass" {
		t.Errorf("item data = %v", item["data"])
	}
	endpoint := payload["endpoints"].([]any)[0].(map[string]any)
	if endpoint["ldap_address"] != "dc.example" {
		t.Errorf("ldap_address = %q", endpoint["ldap_address"])
	}
	if endpoint["ldap_bind_password"] != bind {
		t.Errorf("bind password = %q", endpoint["ldap_bind_password"])
	}
	if endpoint["entra_client_secret"] != entra {
		t.Errorf("entra secret = %q", endpoint["entra_client_secret"])
	}
}

func TestPrepareResponseExcept_KeepsPathAndFiltersSibling(t *testing.T) {
	payload := map[string]any{
		"comment": "please sudo this",
		"data":    map[string]any{"password": "su\u200Bdo"},
	}

	PrepareResponseExcept(payload, NewFilter([]string{"sudo"}), []string{"data"})

	if payload["comment"] != "please [redacted] this" {
		t.Errorf("comment = %v", payload["comment"])
	}
	if payload["data"].(map[string]any)["password"] != "su\u200Bdo" {
		t.Errorf("password = %v", payload["data"])
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
