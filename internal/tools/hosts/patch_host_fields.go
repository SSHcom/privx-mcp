package hosts

import (
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

func applyPatchHostStringScalars(current *hoststore.Host, params map[string]any) error {
	assign := func(key string, dst *string) error {
		s, ok, err := utils.OverlayString(params, key)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if ok {
			*dst = s
		}

		return nil
	}

	for key := range params {
		var err error

		switch key {
		case "common_name":
			err = assign(key, &current.CommonName)
		case "organization":
			err = assign(key, &current.Organization)
		case "organizational_unit":
			err = assign(key, &current.OrganizationalUnit)
		case "zone":
			err = assign(key, &current.Zone)
		case "host_type":
			err = assign(key, &current.HostType)
		case "host_classification":
			err = assign(key, &current.HostClassification)
		case "comment":
			err = assign(key, &current.Comment)
		case "contact_address":
			err = assign(key, &current.ContactAddress)
		case "user_message":
			err = assign(key, &current.UserMessage)
		case "distinguished_name":
			err = assign(key, &current.DistinguishedName)
		case "external_id":
			err = assign(key, &current.ExternalID)
		case "instance_id":
			err = assign(key, &current.InstanceID)
		case "access_group_id":
			err = assign(key, &current.AccessGroupID)
		case "cloud_provider":
			err = assign(key, &current.CloudProvider)
		case "cloud_provider_region":
			err = assign(key, &current.CloudProviderRegion)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func applyPatchHostStringArrays(current *hoststore.Host, params map[string]any) error {
	if v, ok := params["addresses"]; ok {
		addresses, err := utils.ToStringSlice(v)
		if err != nil {
			return fmt.Errorf("validation error: addresses: %w", err)
		}

		if len(addresses) == 0 {
			return fmt.Errorf("validation error: addresses must contain at least one entry")
		}

		current.Addresses = addresses
	}

	if v, ok := params["scope"]; ok {
		scope, err := utils.ToStringSlice(v)
		if err != nil {
			return fmt.Errorf("validation error: scope: %w", err)
		}

		current.Scope = scope
	}

	if v, ok := params["tags"]; ok {
		tags, err := utils.ToStringSlice(v)
		if err != nil {
			return fmt.Errorf("validation error: tags: %w", err)
		}

		current.Tags = tags
	}

	return nil
}

func applyPatchHostBools(current *hoststore.Host, params map[string]any) error {
	if v, ok := params["audit_enabled"]; ok {
		b, err := utils.AsBool(v)
		if err != nil {
			return fmt.Errorf("validation error: audit_enabled: %w", err)
		}

		current.AuditEnabled = &b
	}

	if v, ok := params["tofu"]; ok {
		b, err := utils.AsBool(v)
		if err != nil {
			return fmt.Errorf("validation error: tofu: %w", err)
		}

		current.Tofu = &b
	}

	if v, ok := params["toch"]; ok {
		b, err := utils.AsBool(v)
		if err != nil {
			return fmt.Errorf("validation error: toch: %w", err)
		}

		current.Toch = &b
	}

	if v, ok := params["stand_alone_host"]; ok {
		b, err := utils.AsBool(v)
		if err != nil {
			return fmt.Errorf("validation error: stand_alone_host: %w", err)
		}

		current.StandAloneHost = b
	}

	return nil
}

func applyPatchHostSessionRecording(current *hoststore.Host, params map[string]any) error {
	v, ok := params["session_recording_options"]
	if !ok {
		return nil
	}

	opts, err := ToSessionRecordingOptions(v)
	if err != nil {
		return fmt.Errorf("validation error: session_recording_options: %w", err)
	}

	current.SessionRecordingOptions = opts

	return nil
}

func applyPatchHostServices(current *hoststore.Host, params map[string]any) error {
	v, ok := params["services"]
	if !ok {
		return nil
	}

	servicesRaw, ok := v.([]any)
	if !ok {
		return fmt.Errorf("validation error: services must be an array")
	}

	services, err := HostServicesFromSlice(servicesRaw)
	if err != nil {
		return err
	}

	current.Services = services

	return nil
}
