package network_targets

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// Allowed integration_type values (UI: None / GENERIC / NQX). None means the
// field is omitted and IntegrationType stays empty.
const (
	IntegrationTypeGeneric = "GENERIC"
	IntegrationTypeNQX     = "NQX"
)

// Allowed NQX static_config.type values.
const (
	NQXTypeL3Rules = "l3rules"
	NQXTypeTunnel  = "tunnel"
	NQXTypeCombo   = "combo"
)

// nqxStaticConfig is the only allowed static_config JSON shape for NQX.
type nqxStaticConfig struct {
	Type       string `json:"type"`
	SourceID   string `json:"source_id"`
	SourceName string `json:"source_name"`
}

// PatchNetworkTarget overlays caller-supplied overrides onto the fetched
// network target. Only fields present in params are touched; everything else
// is preserved. Server-managed fields (id, created, author, updated,
// updated_by, disabled) are never read from params.
func PatchNetworkTarget(current *networkaccessmanager.NetworkTarget, params map[string]any) error {
	for key := range params {
		switch key {
		case "name":
			name, _, err := utils.OverlayString(params, key)
			if err != nil {
				return fmt.Errorf("validation error: %w", err)
			}

			if name == "" {
				return fmt.Errorf("validation error: name must be non-empty when provided")
			}

			current.Name = name
		case "comment":
			s, _, err := utils.OverlayString(params, key)
			if err != nil {
				return fmt.Errorf("validation error: %w", err)
			}

			current.Comment = s
		case "user_instructions":
			s, _, err := utils.OverlayString(params, key)
			if err != nil {
				return fmt.Errorf("validation error: %w", err)
			}

			current.UserInstructions = s
		}
	}

	return applyNetworkTargetFields(current, params, false)
}

// BuildNetworkTargetFromCreateParams builds a NetworkTarget for create from
// MCP params. Name is required; other fields are applied when present.
func BuildNetworkTargetFromCreateParams(params map[string]any) (*networkaccessmanager.NetworkTarget, error) {
	name := utils.StringFromMap(params, "name")
	if name == "" {
		return nil, fmt.Errorf("validation error: missing required field: name")
	}

	target := &networkaccessmanager.NetworkTarget{
		Name:  name,
		Dst:   []networkaccessmanager.Destination{},
		Roles: []networkaccessmanager.RoleHandle{},
		Tags:  []string{},
	}

	if v, ok := params["comment"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("validation error: comment must be a string")
		}

		target.Comment = s
	}

	if v, ok := params["user_instructions"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("validation error: user_instructions must be a string")
		}

		target.UserInstructions = s
	}

	if err := applyNetworkTargetFields(target, params, true); err != nil {
		return nil, err
	}

	return target, nil
}

// applyNetworkTargetFields applies integration plus the shared collection and
// bool fields. Create passes create=true so omitted integration keys default
// to empty; patch leaves omitted keys untouched.
func applyNetworkTargetFields(target *networkaccessmanager.NetworkTarget, params map[string]any, create bool) error {
	if err := applyIntegrationAndStaticConfig(target, params, create); err != nil {
		return err
	}

	if v, ok := params["tags"]; ok {
		tags, err := utils.ToStringSlice(v)
		if err != nil {
			return fmt.Errorf("validation error: tags: %w", err)
		}

		target.Tags = tags
	}

	if v, ok := params["src_nat"]; ok {
		b, err := utils.AsBool(v)
		if err != nil {
			return fmt.Errorf("validation error: src_nat: %w", err)
		}

		target.SrcNAT = b
	}

	if v, ok := params["exclusive_access"]; ok {
		b, err := utils.AsBool(v)
		if err != nil {
			return fmt.Errorf("validation error: exclusive_access: %w", err)
		}

		target.ExclusiveAccess = b
	}

	if v, ok := params["dst"]; ok {
		dst, err := ToDestinations(v)
		if err != nil {
			return fmt.Errorf("validation error: dst: %w", err)
		}

		target.Dst = dst
	}

	if v, ok := params["roles"]; ok {
		roles, err := ToRoles(v)
		if err != nil {
			return fmt.Errorf("validation error: roles: %w", err)
		}

		target.Roles = roles
	}

	return nil
}

// applyIntegrationAndStaticConfig validates and applies integration_type /
// static_config. Allowed integration types are GENERIC and NQX; omit means
// None. When the resulting integration type is None, StaticConfig is forced
// empty. On update, omitted keys leave the current values untouched (except
// StaticConfig is cleared when integration_type is set to None via empty).
func applyIntegrationAndStaticConfig(target *networkaccessmanager.NetworkTarget, params map[string]any, create bool) error {
	if v, ok := params["integration_type"]; ok {
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("validation error: integration_type must be a string")
		}

		normalized, err := parseIntegrationType(s)
		if err != nil {
			return err
		}

		target.IntegrationType = normalized
	} else if create {
		target.IntegrationType = ""
	}

	staticProvided := false
	if v, ok := params["static_config"]; ok {
		staticProvided = true

		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("validation error: static_config must be a string")
		}

		target.StaticConfig = s
	} else if create {
		target.StaticConfig = ""
	}

	switch target.IntegrationType {
	case "":
		if staticProvided && target.StaticConfig != "" {
			return fmt.Errorf("validation error: static_config must be empty when integration_type is None")
		}

		target.StaticConfig = ""
	case IntegrationTypeGeneric:
		if target.StaticConfig != "" {
			if err := validateJSONStaticConfig(target.StaticConfig); err != nil {
				return err
			}
		}
	case IntegrationTypeNQX:
		if err := validateNQXStaticConfig(target.StaticConfig); err != nil {
			return err
		}
	}

	return nil
}

func parseIntegrationType(s string) (string, error) {
	switch s {
	case "":
		// Empty is treated as None so update can clear an existing integration.
		return "", nil
	case IntegrationTypeGeneric, IntegrationTypeNQX:
		return s, nil
	default:
		return "", fmt.Errorf(`validation error: integration_type must be "GENERIC" or "NQX" (omit for None)`)
	}
}

func validateJSONStaticConfig(raw string) error {
	if !json.Valid([]byte(raw)) {
		return fmt.Errorf("validation error: static_config must be valid JSON")
	}

	return nil
}

func validateNQXStaticConfig(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf(`validation error: static_config is required when integration_type is "NQX"`)
	}

	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()

	var cfg nqxStaticConfig
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf(`validation error: static_config for NQX must be JSON {"type":"l3rules"|"tunnel"|"combo","source_id":"...","source_name":"..."}: %w`, err)
	}
	// Reject trailing junk after the object.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf(`validation error: static_config for NQX must be a single JSON object`)
	}

	switch cfg.Type {
	case NQXTypeL3Rules, NQXTypeTunnel, NQXTypeCombo:
	default:
		return fmt.Errorf(`validation error: static_config.type must be "l3rules", "tunnel", or "combo"`)
	}

	if cfg.SourceID == "" {
		return fmt.Errorf("validation error: static_config.source_id is required for NQX")
	}

	if cfg.SourceName == "" {
		return fmt.Errorf("validation error: static_config.source_name is required for NQX")
	}

	return nil
}
