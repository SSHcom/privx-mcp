package network_targets

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
)

func TestPatchNetworkTarget_PreservesUntouchedFields(t *testing.T) {
	current := &networkaccessmanager.NetworkTarget{
		ID:      "id-1",
		Name:    "old",
		Comment: "keep-me",
		Tags:    []string{"t1"},
		Dst: []networkaccessmanager.Destination{
			{Sel: networkaccessmanager.Selector{IP: networkaccessmanager.IPRange{Start: "1.1.1.1", End: "1.1.1.1"}}},
		},
		Roles: []networkaccessmanager.RoleHandle{{ID: "r1", Name: "role"}},
	}

	err := PatchNetworkTarget(current, map[string]any{"name": "new"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if current.Name != "new" {
		t.Fatalf("name = %q", current.Name)
	}
	if current.Comment != "keep-me" || current.ID != "id-1" || len(current.Dst) != 1 || len(current.Roles) != 1 {
		t.Fatalf("untouched fields changed: %+v", current)
	}
}

func TestPatchNetworkTarget_WrongTypeStringRejected(t *testing.T) {
	current := &networkaccessmanager.NetworkTarget{Name: "n", Comment: "keep"}
	err := PatchNetworkTarget(current, map[string]any{"comment": 1})
	if err == nil || !strings.Contains(err.Error(), "comment") {
		t.Fatalf("got %v", err)
	}
	if current.Comment != "keep" {
		t.Fatalf("comment = %q", current.Comment)
	}
}

func TestPatchNetworkTarget_EmptyCommentClears(t *testing.T) {
	current := &networkaccessmanager.NetworkTarget{Name: "n", Comment: "keep"}
	err := PatchNetworkTarget(current, map[string]any{"comment": ""})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if current.Comment != "" {
		t.Fatalf("comment = %q, want empty", current.Comment)
	}
}

func TestPatchNetworkTarget_WholesaleReplaceDstAndRoles(t *testing.T) {
	current := &networkaccessmanager.NetworkTarget{
		Name: "n",
		Dst: []networkaccessmanager.Destination{
			{Sel: networkaccessmanager.Selector{IP: networkaccessmanager.IPRange{Start: "1.1.1.1", End: "1.1.1.1"}}},
		},
		Roles: []networkaccessmanager.RoleHandle{{ID: "r1"}},
	}

	err := PatchNetworkTarget(current, map[string]any{
		"dst": []any{
			map[string]any{
				"selector": map[string]any{
					"ip": map[string]any{"start": "2.2.2.2"},
				},
			},
		},
		"roles": []any{},
		"tags":  []any{"x"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(current.Dst) != 1 || current.Dst[0].Sel.IP.Start != "2.2.2.2" {
		t.Fatalf("dst = %+v", current.Dst)
	}
	if current.Roles == nil || len(current.Roles) != 0 {
		t.Fatalf("roles = %+v", current.Roles)
	}
	if len(current.Tags) != 1 || current.Tags[0] != "x" {
		t.Fatalf("tags = %v", current.Tags)
	}
}

func TestPatchNetworkTarget_BoolPresence(t *testing.T) {
	current := &networkaccessmanager.NetworkTarget{Name: "n", SrcNAT: true, ExclusiveAccess: true}
	err := PatchNetworkTarget(current, map[string]any{"src_nat": false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if current.SrcNAT {
		t.Fatal("src_nat should be false")
	}
	if !current.ExclusiveAccess {
		t.Fatal("exclusive_access should be preserved")
	}
}

func TestPatchNetworkTarget_IntegrationType(t *testing.T) {
	validNQX := `{"type":"tunnel","source_id":"az-01","source_name":"azure-privx"}`
	current := &networkaccessmanager.NetworkTarget{
		Name:            "n",
		IntegrationType: IntegrationTypeNQX,
		StaticConfig:    validNQX,
	}

	if err := PatchNetworkTarget(current, map[string]any{"integration_type": IntegrationTypeGeneric}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if current.IntegrationType != IntegrationTypeGeneric {
		t.Fatalf("integration_type = %q", current.IntegrationType)
	}
	if current.StaticConfig != validNQX {
		t.Fatalf("static_config should be preserved, got %q", current.StaticConfig)
	}

	if err := PatchNetworkTarget(current, map[string]any{"integration_type": ""}); err != nil {
		t.Fatalf("unexpected error clearing integration: %v", err)
	}
	if current.IntegrationType != "" || current.StaticConfig != "" {
		t.Fatalf("None should clear static_config: type=%q config=%q", current.IntegrationType, current.StaticConfig)
	}

	current.IntegrationType = ""
	current.StaticConfig = ""
	err := PatchNetworkTarget(current, map[string]any{"static_config": `{"x":1}`})
	if err == nil {
		t.Fatal("expected error setting static_config with None integration")
	}

	err = PatchNetworkTarget(current, map[string]any{"integration_type": "nqx"})
	if err == nil {
		t.Fatal("expected error for lowercase integration_type")
	}
}

func TestPatchNetworkTarget_NQXStaticConfigShape(t *testing.T) {
	current := &networkaccessmanager.NetworkTarget{Name: "n"}

	err := PatchNetworkTarget(current, map[string]any{
		"integration_type": IntegrationTypeNQX,
		"static_config":    `{"type":"tunnel","source_id":"1","source_name":"src"}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = PatchNetworkTarget(current, map[string]any{
		"static_config": `{"type":"nope","source_id":"1","source_name":"src"}`,
	})
	if err == nil {
		t.Fatal("expected error for invalid NQX type")
	}

	err = PatchNetworkTarget(current, map[string]any{
		"static_config": `{"type":"tunnel","source_id":"1","source_name":"src","extra":true}`,
	})
	if err == nil {
		t.Fatal("expected error for unknown NQX fields")
	}

	err = PatchNetworkTarget(current, map[string]any{
		"static_config": `{"type":"tunnel","source_id":"1"}`,
	})
	if err == nil {
		t.Fatal("expected error for missing source_name")
	}
}

func TestValidateNQXStaticConfig(t *testing.T) {
	if err := validateNQXStaticConfig(`{"type":"combo","source_id":"123","source_name":"test-src"}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := validateNQXStaticConfig(""); err == nil {
		t.Fatal("expected error for empty config")
	}
	if err := validateNQXStaticConfig(`{"type":"l3rules","source_id":"","source_name":"x"}`); err == nil {
		t.Fatal("expected error for empty source_id")
	}
}

func TestPatchNetworkTarget_GenericStaticConfigMustBeJSON(t *testing.T) {
	current := &networkaccessmanager.NetworkTarget{Name: "n", IntegrationType: IntegrationTypeGeneric}

	if err := PatchNetworkTarget(current, map[string]any{"static_config": `{"a":1}`}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := PatchNetworkTarget(current, map[string]any{"static_config": `not-json`}); err == nil {
		t.Fatal("expected error for non-JSON static_config")
	}
}

func TestBuildNetworkTargetFromCreateParams_DefaultsAndOptionalFields(t *testing.T) {
	created, err := BuildNetworkTargetFromCreateParams(map[string]any{"name": "n"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.Name != "n" {
		t.Fatalf("name = %q", created.Name)
	}
	if created.SrcNAT || created.ExclusiveAccess {
		t.Fatal("create defaults should leave bools false")
	}
	if created.Dst == nil || created.Roles == nil || created.Tags == nil {
		t.Fatal("create should initialize empty slices")
	}

	created, err = BuildNetworkTargetFromCreateParams(map[string]any{
		"name":             "n",
		"src_nat":          true,
		"exclusive_access": true,
		"tags":             []any{"a"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !created.SrcNAT || !created.ExclusiveAccess || len(created.Tags) != 1 {
		t.Fatalf("optional create fields not applied: %+v", created)
	}

	current := &networkaccessmanager.NetworkTarget{
		Name:            "keep",
		SrcNAT:          true,
		ExclusiveAccess: true,
		Tags:            []string{"old"},
	}
	if err := PatchNetworkTarget(current, map[string]any{"comment": "x"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !current.SrcNAT || !current.ExclusiveAccess || len(current.Tags) != 1 || current.Tags[0] != "old" {
		t.Fatalf("patch must preserve omitted collections/bools: %+v", current)
	}
}
