package network_targets

import (
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
)

func TestToDestination_MinimalIP(t *testing.T) {
	dst, err := ToDestination(map[string]any{
		"selector": map[string]any{
			"ip": map[string]any{"start": "10.0.0.1"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.Sel.IP.Start != "10.0.0.1" || dst.Sel.IP.End != "10.0.0.1" {
		t.Fatalf("ip = %+v, want start=end=10.0.0.1", dst.Sel.IP)
	}
	if dst.Sel.Port != nil || dst.NAT != nil {
		t.Fatalf("expected nil port and nat, got port=%v nat=%v", dst.Sel.Port, dst.NAT)
	}
}

func TestToDestination_PortAndNAT(t *testing.T) {
	dst, err := ToDestination(map[string]any{
		"selector": map[string]any{
			"ip": map[string]any{
				"start": "192.168.0.5",
				"end":   "192.168.0.10",
			},
			"proto": "TCP",
			"port":  map[string]any{"start": float64(22)},
		},
		"nat": map[string]any{
			"addr": "hextender/192.168.0.5",
			"port": float64(22),
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.Sel.IP.End != "192.168.0.10" {
		t.Fatalf("ip.end = %q", dst.Sel.IP.End)
	}
	if dst.Sel.Protocol != "TCP" {
		t.Fatalf("proto = %q", dst.Sel.Protocol)
	}
	if dst.Sel.Port == nil || dst.Sel.Port.Start != 22 || dst.Sel.Port.End != 22 {
		t.Fatalf("port = %+v, want start=end=22", dst.Sel.Port)
	}
	if dst.NAT == nil || dst.NAT.Addr != "hextender/192.168.0.5" || dst.NAT.Port != 22 {
		t.Fatalf("nat = %+v", dst.NAT)
	}
}

func TestToDestination_ProtoAllRejectsPortAndNAT(t *testing.T) {
	_, err := ToDestination(map[string]any{
		"selector": map[string]any{
			"ip":    map[string]any{"start": "10.0.0.1"},
			"proto": "All",
			"port":  map[string]any{"start": float64(80)},
		},
	})
	if err == nil {
		t.Fatal("expected error for port with proto All")
	}

	_, err = ToDestination(map[string]any{
		"selector": map[string]any{
			"ip":    map[string]any{"start": "10.0.0.1"},
			"proto": "all",
		},
		"nat": map[string]any{"addr": "10.0.0.1"},
	})
	if err == nil {
		t.Fatal("expected error for nat with proto All")
	}
}

func TestToDestination_ProtoAllAllowedWithoutPortOrNAT(t *testing.T) {
	dst, err := ToDestination(map[string]any{
		"selector": map[string]any{
			"ip":    map[string]any{"start": "10.0.0.1"},
			"proto": "All",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.Sel.Protocol != "All" {
		t.Fatalf("proto = %q", dst.Sel.Protocol)
	}
}

func TestToDestination_MissingIPStart(t *testing.T) {
	_, err := ToDestination(map[string]any{
		"selector": map[string]any{
			"ip": map[string]any{},
		},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestToRoleHandle(t *testing.T) {
	role, err := ToRoleHandle(map[string]any{"id": "role-1", "name": "admins"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role != (networkaccessmanager.RoleHandle{ID: "role-1", Name: "admins"}) {
		t.Fatalf("role = %+v", role)
	}

	_, err = ToRoleHandle(map[string]any{"name": "admins"})
	if err == nil {
		t.Fatal("expected error when id missing")
	}
}

func TestBuildNetworkTargetFromCreateParams(t *testing.T) {
	target, err := BuildNetworkTargetFromCreateParams(map[string]any{
		"name": "nta-1",
		"dst": []any{
			map[string]any{
				"selector": map[string]any{
					"ip": map[string]any{"start": "10.0.0.1"},
				},
			},
		},
		"roles": []any{
			map[string]any{"id": "role-1"},
		},
		"src_nat": true,
		"tags":    []any{"a", "b"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Name != "nta-1" || !target.SrcNAT || len(target.Dst) != 1 || len(target.Roles) != 1 {
		t.Fatalf("target = %+v", target)
	}
	if len(target.Tags) != 2 || target.Tags[0] != "a" {
		t.Fatalf("tags = %v", target.Tags)
	}
}

func TestBuildNetworkTargetFromCreateParams_RequiresName(t *testing.T) {
	_, err := BuildNetworkTargetFromCreateParams(map[string]any{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBuildNetworkTargetFromCreateParams_IntegrationNoneClearsStaticConfig(t *testing.T) {
	target, err := BuildNetworkTargetFromCreateParams(map[string]any{
		"name": "nta-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.IntegrationType != "" || target.StaticConfig != "" {
		t.Fatalf("None should leave empty integration/static_config: %+v", target)
	}

	_, err = BuildNetworkTargetFromCreateParams(map[string]any{
		"name":          "nta-1",
		"static_config": `{"type":"tunnel"}`,
	})
	if err == nil {
		t.Fatal("expected error for static_config with None integration")
	}

	_, err = BuildNetworkTargetFromCreateParams(map[string]any{
		"name":             "nta-1",
		"integration_type": IntegrationTypeNQX,
		"static_config":    `{"type":"tunnel"}`,
	})
	if err == nil {
		t.Fatal("expected error for incomplete NQX static_config")
	}

	target, err = BuildNetworkTargetFromCreateParams(map[string]any{
		"name":             "nta-1",
		"integration_type": IntegrationTypeNQX,
		"static_config":    `{"type":"tunnel","source_id":"az-01","source_name":"azure-privx"}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.IntegrationType != IntegrationTypeNQX {
		t.Fatalf("target = %+v", target)
	}
}
