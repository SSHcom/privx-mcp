package hosts

import (
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// ToHostService converts a single service object from the MCP params into a
// hoststore.HostService, validating the required fields.
func ToHostService(raw any) (hoststore.HostService, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return hoststore.HostService{}, fmt.Errorf("must be an object")
	}

	service := utils.StringFromMap(m, "service")
	if service == "" {
		return hoststore.HostService{}, fmt.Errorf("missing required field: service")
	}

	address := utils.StringFromMap(m, "address")
	if address == "" {
		return hoststore.HostService{}, fmt.Errorf("missing required field: address")
	}

	port, err := utils.IntFromMap(m, "port", 0)
	if err != nil {
		return hoststore.HostService{}, fmt.Errorf("port: %w", err)
	}

	if port < 0 {
		return hoststore.HostService{}, fmt.Errorf("port must be >= 0")
	}

	return hoststore.HostService{
		Service: service,
		Address: address,
		Port:    port,
	}, nil
}

// HostServicesFromSlice converts an MCP services array into hoststore services.
func HostServicesFromSlice(servicesRaw []any) ([]hoststore.HostService, error) {
	services := make([]hoststore.HostService, 0, len(servicesRaw))
	for i, raw := range servicesRaw {
		svc, err := ToHostService(raw)
		if err != nil {
			return nil, fmt.Errorf("validation error: services[%d]: %w", i, err)
		}

		services = append(services, svc)
	}

	return services, nil
}

// ToPrincipalInput converts a single principal object from the MCP params into
// its principal name and roles slice, validating the required fields.
func ToPrincipalInput(raw any) (string, []string, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return "", nil, fmt.Errorf("must be an object")
	}

	principal := utils.StringFromMap(m, "principal")
	if principal == "" {
		return "", nil, fmt.Errorf("missing required field: principal")
	}

	roles, err := utils.ToStringSlice(m["roles"])
	if err != nil {
		return "", nil, fmt.Errorf("roles: %w", err)
	}

	return principal, roles, nil
}

// ToSessionRecordingOptions converts the MCP params value for
// session_recording_options into a hoststore.SessionRecordingOptions.
func ToSessionRecordingOptions(raw any) (*hoststore.SessionRecordingOptions, error) {
	if raw == nil {
		return nil, nil
	}

	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("must be an object")
	}

	opts := &hoststore.SessionRecordingOptions{}

	if v, ok := m["disable_clipboard_recording"]; ok {
		b, err := utils.AsBool(v)
		if err != nil {
			return nil, fmt.Errorf("disable_clipboard_recording: %w", err)
		}

		opts.DisableClipboardRecording = b
	}

	if v, ok := m["disable_file_transfer_recording"]; ok {
		b, err := utils.AsBool(v)
		if err != nil {
			return nil, fmt.Errorf("disable_file_transfer_recording: %w", err)
		}

		opts.DisableFileTransferRecording = b
	}

	return opts, nil
}
