package common

import "testing"

func TestDeletePaths(t *testing.T) {
	root := map[string]any{
		"id": "h1",
		"mfa": map[string]any{
			"status": "ok",
			"seed":   "SECRET",
		},
		"services": []any{
			map[string]any{
				"service": "DB",
				"db": map[string]any{
					"protocol":                      "postgres",
					"tls_certificate_trust_anchors": "ANCHOR",
				},
			},
			"skip",
		},
	}

	DeletePaths(nil, "id")
	DeletePaths(root, "mfa.seed", "services[].db.tls_certificate_trust_anchors", "missing.path")

	mfa := root["mfa"].(map[string]any)
	if _, ok := mfa["seed"]; ok {
		t.Error("seed should be deleted")
	}
	if mfa["status"] != "ok" {
		t.Errorf("status = %v", mfa["status"])
	}

	svc := root["services"].([]any)[0].(map[string]any)
	db := svc["db"].(map[string]any)
	if _, ok := db["tls_certificate_trust_anchors"]; ok {
		t.Error("trust anchors should be deleted")
	}
	if db["protocol"] != "postgres" {
		t.Errorf("protocol = %v", db["protocol"])
	}
	if root["services"].([]any)[1] != "skip" {
		t.Error("non-map array entry should remain")
	}
	if root["id"] != "h1" {
		t.Errorf("id = %v", root["id"])
	}
}
