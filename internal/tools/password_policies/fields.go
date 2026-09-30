package password_policies

import (
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

type stringField struct {
	key string
	set func(*secretsmanager.PasswordPolicy, string)
}

type intField struct {
	key string
	set func(*secretsmanager.PasswordPolicy, int)
}

type boolField struct {
	key string
	set func(*secretsmanager.PasswordPolicy, bool)
}

var passwordPolicyStringFields = []stringField{
	{key: "name", set: func(p *secretsmanager.PasswordPolicy, v string) { p.Name = v }},
	{key: "rotation_interval", set: func(p *secretsmanager.PasswordPolicy, v string) { p.RotationInterval = v }},
	{key: "retry_interval", set: func(p *secretsmanager.PasswordPolicy, v string) { p.RetryInterval = v }},
	{key: "max_checkout_duration", set: func(p *secretsmanager.PasswordPolicy, v string) { p.MaxCheckoutDuration = v }},
}

var passwordPolicyIntFields = []intField{
	{key: "max_versions", set: func(p *secretsmanager.PasswordPolicy, v int) { p.MaxVersions = v }},
	{key: "password_min_length", set: func(p *secretsmanager.PasswordPolicy, v int) { p.PasswordMinLength = v }},
	{key: "password_max_length", set: func(p *secretsmanager.PasswordPolicy, v int) { p.PasswordMaxLength = v }},
	{key: "number_of_retries", set: func(p *secretsmanager.PasswordPolicy, v int) { p.NumberOfRetries = v }},
	{key: "max_concurrent_checkouts", set: func(p *secretsmanager.PasswordPolicy, v int) { p.MaxConcurrentCheckouts = v }},
}

var passwordPolicyBoolFields = []boolField{
	{key: "use_special_characters", set: func(p *secretsmanager.PasswordPolicy, v bool) { p.UseSpecialCharacters = v }},
	{key: "use_lower_case", set: func(p *secretsmanager.PasswordPolicy, v bool) { p.UseLowercase = v }},
	{key: "use_upper_case", set: func(p *secretsmanager.PasswordPolicy, v bool) { p.UseUppercase = v }},
	{key: "use_numbers", set: func(p *secretsmanager.PasswordPolicy, v bool) { p.UseNumbers = v }},
	{key: "rotate_on_release", set: func(p *secretsmanager.PasswordPolicy, v bool) { p.RotateOnRelease = v }},
	{key: "verify_after_rotation", set: func(p *secretsmanager.PasswordPolicy, v bool) { p.VerifyAfterRotation = v }},
}

// ApplyPasswordPolicyFields overlays present params onto policy. Absent keys
// are left unchanged. Empty strings are ignored so create defaults and
// fetched update values are preserved when the caller omits those fields.
func ApplyPasswordPolicyFields(policy *secretsmanager.PasswordPolicy, params map[string]any) error {
	for _, field := range passwordPolicyStringFields {
		v, ok, err := utils.OverlayString(params, field.key)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if ok && v != "" {
			field.set(policy, v)
		}
	}

	for _, field := range passwordPolicyIntFields {
		if _, ok := params[field.key]; !ok {
			continue
		}

		val, err := utils.IntFromMap(params, field.key, 0)
		if err != nil {
			return fmt.Errorf("validation error: %s: %w", field.key, err)
		}

		field.set(policy, val)
	}

	for _, field := range passwordPolicyBoolFields {
		v, ok, err := utils.OverlayBool(params, field.key)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if ok {
			field.set(policy, v)
		}
	}

	return nil
}
