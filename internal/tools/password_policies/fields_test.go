package password_policies

import (
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
)

func TestApplyPasswordPolicyFields(t *testing.T) {
	base := secretsmanager.PasswordPolicy{
		Name:                   "keep",
		MaxVersions:            2,
		RotationInterval:       "P1M",
		PasswordMinLength:      20,
		PasswordMaxLength:      20,
		UseSpecialCharacters:   true,
		UseLowercase:           true,
		UseUppercase:           true,
		UseNumbers:             true,
		NumberOfRetries:        5,
		RetryInterval:          "PT5M",
		MaxConcurrentCheckouts: 1,
		MaxCheckoutDuration:    "PT10M",
		RotateOnRelease:        false,
		VerifyAfterRotation:    false,
	}

	t.Run("absent keys preserve current values", func(t *testing.T) {
		policy := base
		if err := ApplyPasswordPolicyFields(&policy, map[string]any{}); err != nil {
			t.Fatalf("err: %v", err)
		}
		if policy != base {
			t.Fatalf("policy changed: %+v", policy)
		}
	})

	t.Run("applies every overlay field", func(t *testing.T) {
		policy := base
		err := ApplyPasswordPolicyFields(&policy, map[string]any{
			"name":                     "new",
			"max_versions":             7,
			"rotation_interval":        "P30D",
			"password_min_length":      12,
			"password_max_length":      24,
			"use_special_characters":   false,
			"use_lower_case":           false,
			"use_upper_case":           false,
			"use_numbers":              false,
			"number_of_retries":        0,
			"retry_interval":           "PT1M",
			"max_concurrent_checkouts": 3,
			"max_checkout_duration":    "PT1H",
			"rotate_on_release":        true,
			"verify_after_rotation":    true,
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		if policy.Name != "new" ||
			policy.MaxVersions != 7 ||
			policy.RotationInterval != "P30D" ||
			policy.PasswordMinLength != 12 ||
			policy.PasswordMaxLength != 24 ||
			policy.UseSpecialCharacters ||
			policy.UseLowercase ||
			policy.UseUppercase ||
			policy.UseNumbers ||
			policy.NumberOfRetries != 0 ||
			policy.RetryInterval != "PT1M" ||
			policy.MaxConcurrentCheckouts != 3 ||
			policy.MaxCheckoutDuration != "PT1H" ||
			!policy.RotateOnRelease ||
			!policy.VerifyAfterRotation {
			t.Fatalf("unexpected overlay: %+v", policy)
		}
	})

	t.Run("empty strings do not clear existing values", func(t *testing.T) {
		policy := base
		err := ApplyPasswordPolicyFields(&policy, map[string]any{
			"name":                  "",
			"rotation_interval":     "",
			"retry_interval":        "",
			"max_checkout_duration": "",
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if policy.Name != "keep" || policy.RotationInterval != "P1M" {
			t.Fatalf("empty strings cleared values: %+v", policy)
		}
	})

	t.Run("invalid int is rejected", func(t *testing.T) {
		policy := base
		err := ApplyPasswordPolicyFields(&policy, map[string]any{"password_min_length": "nope"})
		if err == nil || !strings.Contains(err.Error(), "password_min_length") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("wrong type bool is rejected", func(t *testing.T) {
		policy := base
		err := ApplyPasswordPolicyFields(&policy, map[string]any{"rotate_on_release": 1})
		if err == nil || !strings.Contains(err.Error(), "rotate_on_release") {
			t.Fatalf("got %v", err)
		}
		if policy.RotateOnRelease {
			t.Fatal("rotate_on_release should stay false")
		}
	})

	t.Run("wrong type string is rejected", func(t *testing.T) {
		policy := base
		err := ApplyPasswordPolicyFields(&policy, map[string]any{"name": 1})
		if err == nil || !strings.Contains(err.Error(), "name") {
			t.Fatalf("got %v", err)
		}
		if policy.Name != "keep" {
			t.Fatalf("name = %q", policy.Name)
		}
	})
}
