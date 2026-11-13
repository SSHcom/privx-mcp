package hosts

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// ApplyServiceOptions overlays the MCP service_options object onto base and
// returns the result. base is never modified; it may be nil.
//
// Only keys present in raw are applied. A field that raw omits keeps its value
// from base. When base has no options for that protocol, the field starts from
// the PrivX default: enabled for every SSH option, and false/0 for the other
// protocols. A protocol object that is empty leaves that protocol unchanged.
// Unknown protocols and unknown fields are rejected so a typo is not silently
// dropped.
func ApplyServiceOptions(base *hoststore.HostServiceOptions, raw any) (*hoststore.HostServiceOptions, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("must be an object")
	}

	if err := rejectUnknownKeys("service_options", m, "ssh", "rdp", "web", "vnc", "db"); err != nil {
		return nil, err
	}

	out := hoststore.HostServiceOptions{}
	if base != nil {
		out = *base
	}

	if err := applySSHOptions(&out, m); err != nil {
		return nil, err
	}

	if err := applyRDPOptions(&out, m); err != nil {
		return nil, err
	}

	if err := applyWebOptions(&out, m); err != nil {
		return nil, err
	}

	if err := applyVNCOptions(&out, m); err != nil {
		return nil, err
	}

	if err := applyDBOptions(&out, m); err != nil {
		return nil, err
	}

	return &out, nil
}

func applySSHOptions(out *hoststore.HostServiceOptions, m map[string]any) error {
	sub, ok, err := protocolObject(m, "ssh")
	if err != nil || !ok {
		return err
	}

	// PrivX enables all six SSH options by default, so a principal with no SSH
	// options yet starts from all-enabled and the caller only turns things off.
	opts := hoststore.SSHServiceOptions{
		Shell:        true,
		FileTransfer: true,
		Exec:         true,
		Tunnels:      true,
		X11:          true,
		Other:        true,
	}
	if out.SSHServiceOptions != nil {
		opts = *out.SSHServiceOptions
	}

	err = applyBoolFields("ssh", sub, map[string]*bool{
		"shell":         &opts.Shell,
		"file_transfer": &opts.FileTransfer,
		"exec":          &opts.Exec,
		"tunnels":       &opts.Tunnels,
		"x11":           &opts.X11,
		"other":         &opts.Other,
	})
	if err != nil {
		return err
	}

	out.SSHServiceOptions = &opts

	return nil
}

func applyRDPOptions(out *hoststore.HostServiceOptions, m map[string]any) error {
	sub, ok, err := protocolObject(m, "rdp")
	if err != nil || !ok {
		return err
	}

	opts := hoststore.RDPServiceOptions{}
	if out.RDPServiceOptions != nil {
		opts = *out.RDPServiceOptions
	}

	err = applyBoolFields("rdp", sub, map[string]*bool{
		"file_transfer": &opts.FileTransfer,
		"audio":         &opts.Audio,
		"clipboard":     &opts.Clipboard,
	})
	if err != nil {
		return err
	}

	out.RDPServiceOptions = &opts

	return nil
}

func applyWebOptions(out *hoststore.HostServiceOptions, m map[string]any) error {
	sub, ok, err := protocolObject(m, "web")
	if err != nil || !ok {
		return err
	}

	opts := hoststore.WebServiceOptions{}
	if out.WebServiceOptions != nil {
		opts = *out.WebServiceOptions
	}

	err = applyBoolFields("web", sub, map[string]*bool{
		"file_transfer": &opts.FileTransfer,
		"audio":         &opts.Audio,
		"clipboard":     &opts.Clipboard,
	})
	if err != nil {
		return err
	}

	out.WebServiceOptions = &opts

	return nil
}

func applyVNCOptions(out *hoststore.HostServiceOptions, m map[string]any) error {
	sub, ok, err := protocolObject(m, "vnc")
	if err != nil || !ok {
		return err
	}

	opts := hoststore.VNCServiceOptions{}
	if out.VNCServiceOptions != nil {
		opts = *out.VNCServiceOptions
	}

	err = applyBoolFields("vnc", sub, map[string]*bool{
		"file_transfer": &opts.FileTransfer,
		"clipboard":     &opts.Clipboard,
	})
	if err != nil {
		return err
	}

	out.VNCServiceOptions = &opts

	return nil
}

func applyDBOptions(out *hoststore.HostServiceOptions, m map[string]any) error {
	sub, ok, err := protocolObject(m, "db")
	if err != nil || !ok {
		return err
	}

	opts := hoststore.DBServiceOptions{}
	if out.DBServiceOptions != nil {
		opts = *out.DBServiceOptions
	}

	err = applyInt64Fields("db", sub, map[string]*int64{
		"max_bytes_upload":   &opts.MaxBytesUpload,
		"max_bytes_download": &opts.MaxBytesDownload,
	})
	if err != nil {
		return err
	}

	out.DBServiceOptions = &opts

	return nil
}

// protocolObject returns the per-protocol object at key. ok is false when the
// key is absent or the object is empty, in which case the protocol is left
// unchanged. A present non-object is an error.
func protocolObject(m map[string]any, key string) (obj map[string]any, ok bool, err error) {
	v, present := m[key]
	if !present {
		return nil, false, nil
	}

	obj, isMap := v.(map[string]any)
	if !isMap {
		return nil, false, fmt.Errorf("%s must be an object", key)
	}

	if len(obj) == 0 {
		return nil, false, nil
	}

	return obj, true, nil
}

func applyBoolFields(scope string, m map[string]any, fields map[string]*bool) error {
	names := fieldNames(fields)

	if err := rejectUnknownKeys(scope, m, names...); err != nil {
		return err
	}

	for _, name := range names {
		v, ok, err := utils.OverlayBool(m, name)
		if err != nil {
			return fmt.Errorf("%s: %w", scope, err)
		}

		if ok {
			*fields[name] = v
		}
	}

	return nil
}

func applyInt64Fields(scope string, m map[string]any, fields map[string]*int64) error {
	names := fieldNames(fields)

	if err := rejectUnknownKeys(scope, m, names...); err != nil {
		return err
	}

	for _, name := range names {
		v, present := m[name]
		if !present {
			continue
		}

		n, err := asNonNegativeInt64(v)
		if err != nil {
			return fmt.Errorf("%s: %s %w", scope, name, err)
		}

		*fields[name] = n
	}

	return nil
}

func fieldNames[T any](fields map[string]*T) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}

// rejectUnknownKeys errors when m has a key outside allowed. Keys are sorted so
// the message is stable.
func rejectUnknownKeys(scope string, m map[string]any, allowed ...string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}

	var unknown []string

	for key := range m {
		if _, ok := allowedSet[key]; !ok {
			unknown = append(unknown, key)
		}
	}

	if len(unknown) == 0 {
		return nil
	}

	sort.Strings(unknown)

	supported := append([]string(nil), allowed...)
	sort.Strings(supported)

	return fmt.Errorf("%s: unsupported field(s) %s (supported: %s)",
		scope, strings.Join(unknown, ", "), strings.Join(supported, ", "))
}

func asNonNegativeInt64(v any) (int64, error) {
	errInvalid := fmt.Errorf("must be a non-negative integer")

	switch typed := v.(type) {
	case float64:
		if typed != math.Trunc(typed) || typed < 0 || typed >= math.MaxInt64 {
			return 0, errInvalid
		}

		return int64(typed), nil
	case int:
		if typed < 0 {
			return 0, errInvalid
		}

		return int64(typed), nil
	case int64:
		if typed < 0 {
			return 0, errInvalid
		}

		return typed, nil
	case json.Number:
		n, err := typed.Int64()
		if err != nil || n < 0 {
			return 0, errInvalid
		}

		return n, nil
	default:
		return 0, errInvalid
	}
}
