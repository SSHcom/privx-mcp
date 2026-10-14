package target_domains

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
)

func sampleDomain() secretsmanager.TargetDomain {
	return secretsmanager.TargetDomain{
		Name:                 "keep",
		DomainName:           "keep.example",
		Enabled:              true,
		PeriodicScan:         true,
		PeriodicScanInterval: 900,
		AutoOnboarding:       true,
		AutoOnboardingPolicy: &secretsmanager.PasswordPolicyHandle{ID: "pol-old", Name: "old"},
		Comment:              "keep-comment",
		EndPoints: []secretsmanager.TargetDomainEndpoint{{
			Type:             "AD",
			ScanPriority:     1,
			RotationPriority: 1,
			LdapAddress:      "dc.example",
			LdapBindPassword: "stored-secret",
		}},
	}
}

func TestApplyTargetDomainFields(t *testing.T) {
	t.Run("absent keys preserve current values", func(t *testing.T) {
		domain := sampleDomain()
		if err := ApplyTargetDomainFields(&domain, map[string]any{}); err != nil {
			t.Fatalf("err: %v", err)
		}
		if domain.Name != "keep" ||
			domain.DomainName != "keep.example" ||
			domain.Comment != "keep-comment" ||
			domain.PeriodicScanInterval != 900 ||
			domain.AutoOnboardingPolicy.ID != "pol-old" ||
			len(domain.EndPoints) != 1 ||
			domain.EndPoints[0].LdapBindPassword != "stored-secret" {
			t.Fatalf("domain changed: %+v", domain)
		}
	})

	t.Run("applies overlay fields", func(t *testing.T) {
		domain := sampleDomain()
		err := ApplyTargetDomainFields(&domain, map[string]any{
			"name":                      "new",
			"domain_name":               "new.example",
			"enabled":                   false,
			"periodic_scan":             false,
			"periodic_scan_interval":    float64(60),
			"auto_onboarding":           false,
			"auto_onboarding_policy_id": "pol-new",
			"comment":                   "edited",
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if domain.Name != "new" ||
			domain.DomainName != "new.example" ||
			domain.Enabled ||
			domain.PeriodicScan ||
			domain.AutoOnboarding ||
			domain.PeriodicScanInterval != 60 ||
			domain.AutoOnboardingPolicy.ID != "pol-new" ||
			domain.Comment != "edited" ||
			domain.EndPoints[0].LdapAddress != "dc.example" {
			t.Fatalf("unexpected overlay: %+v", domain)
		}
	})

	t.Run("empty strings do not clear existing values", func(t *testing.T) {
		domain := sampleDomain()
		err := ApplyTargetDomainFields(&domain, map[string]any{
			"name":                      "",
			"domain_name":               "",
			"comment":                   "",
			"auto_onboarding_policy_id": "",
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if domain.Name != "keep" ||
			domain.DomainName != "keep.example" ||
			domain.Comment != "keep-comment" ||
			domain.AutoOnboardingPolicy.ID != "pol-old" {
			t.Fatalf("empty strings cleared values: %+v", domain)
		}
	})

	t.Run("present endpoints replace the slice and keep a bind password", func(t *testing.T) {
		domain := sampleDomain()
		err := ApplyTargetDomainFields(&domain, map[string]any{
			"endpoints": []any{
				map[string]any{
					"type":               "AD",
					"scan_priority":      float64(2),
					"rotation_priority":  float64(1),
					"ldap_bind_password": "new-secret",
					"attribute_mapping":  map[string]any{"mail": "email"},
					"entra_group_filter": []any{"group-a"},
				},
			},
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(domain.EndPoints) != 1 {
			t.Fatalf("endpoints = %+v", domain.EndPoints)
		}
		ep := domain.EndPoints[0]
		if ep.ScanPriority != 2 ||
			ep.LdapBindPassword != "new-secret" ||
			ep.LdapAddress != "" ||
			ep.AttributeMapping["mail"] != "email" ||
			len(ep.EntraGroupFilter) != 1 ||
			ep.EntraGroupFilter[0] != "group-a" {
			t.Fatalf("endpoint = %+v", ep)
		}
	})

	t.Run("duplicate scan_priority is rejected", func(t *testing.T) {
		domain := sampleDomain()
		err := ApplyTargetDomainFields(&domain, map[string]any{
			"endpoints": []any{
				map[string]any{"type": "AD", "scan_priority": float64(1), "rotation_priority": float64(1)},
				map[string]any{"type": "AD", "scan_priority": float64(1), "rotation_priority": float64(0)},
			},
		})
		if err == nil || !strings.Contains(err.Error(), "duplicate scan_priority 1") {
			t.Fatalf("got %v", err)
		}
		if domain.EndPoints[0].LdapBindPassword != "stored-secret" {
			t.Fatal("endpoints should stay unchanged when parsing fails")
		}
	})

	t.Run("invalid bool is rejected", func(t *testing.T) {
		domain := sampleDomain()
		err := ApplyTargetDomainFields(&domain, map[string]any{"enabled": 1})
		if err == nil || !strings.Contains(err.Error(), "enabled") {
			t.Fatalf("got %v", err)
		}
		if !domain.Enabled {
			t.Fatal("enabled should stay true")
		}
	})
}

func sampleManagedAccount() secretsmanager.ManagedAccount {
	return secretsmanager.ManagedAccount{
		ID:               "ma1",
		Username:         "svc-sql",
		Enabled:          true,
		RotationEnabled:  true,
		ExplicitCheckout: true,
		Comment:          "keep-comment",
		PasswordPolicy:   &secretsmanager.PasswordPolicyHandle{ID: "pol-old", Name: "old"},
	}
}

func TestApplyManagedAccountFields(t *testing.T) {
	t.Run("omitted rotation_enabled keeps the fetched value", func(t *testing.T) {
		account := sampleManagedAccount()
		err := ApplyManagedAccountFields(&account, map[string]any{
			"comment":  "edited",
			"username": "renamed",
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !account.RotationEnabled || account.Username != "svc-sql" || account.Comment != "edited" {
			t.Fatalf("account = %+v", account)
		}
	})

	t.Run("present explicit_checkout false clears it", func(t *testing.T) {
		account := sampleManagedAccount()
		if err := ApplyManagedAccountFields(&account, map[string]any{"explicit_checkout": false}); err != nil {
			t.Fatalf("err: %v", err)
		}
		if account.ExplicitCheckout || !account.RotationEnabled {
			t.Fatalf("account = %+v", account)
		}
	})

	t.Run("empty strings do not clear comment or password policy", func(t *testing.T) {
		account := sampleManagedAccount()
		err := ApplyManagedAccountFields(&account, map[string]any{
			"comment":            "",
			"password_policy_id": "",
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if account.Comment != "keep-comment" || account.PasswordPolicy.ID != "pol-old" {
			t.Fatalf("empty strings cleared values: %+v", account)
		}
	})
}
