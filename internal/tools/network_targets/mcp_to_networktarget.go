package network_targets

import (
	"fmt"
	"strings"

	"github.com/SSHcom/privx-sdk-go/v2/api/networkaccessmanager"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// ToDestination converts a single destination object from MCP params into a
// networkaccessmanager.Destination, validating required fields and the
// proto=All constraints (no port, no NAT).
func ToDestination(raw any) (networkaccessmanager.Destination, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return networkaccessmanager.Destination{}, fmt.Errorf("must be an object")
	}

	selectorRaw, ok := m["selector"]
	if !ok || selectorRaw == nil {
		return networkaccessmanager.Destination{}, fmt.Errorf("missing required field: selector")
	}

	selectorMap, ok := selectorRaw.(map[string]any)
	if !ok {
		return networkaccessmanager.Destination{}, fmt.Errorf("selector must be an object")
	}

	ipRaw, ok := selectorMap["ip"]
	if !ok || ipRaw == nil {
		return networkaccessmanager.Destination{}, fmt.Errorf("missing required field: selector.ip")
	}

	ipMap, ok := ipRaw.(map[string]any)
	if !ok {
		return networkaccessmanager.Destination{}, fmt.Errorf("selector.ip must be an object")
	}

	ipStart := utils.StringFromMap(ipMap, "start")
	if ipStart == "" {
		return networkaccessmanager.Destination{}, fmt.Errorf("missing required field: selector.ip.start")
	}

	ipEnd := utils.StringFromMap(ipMap, "end")
	if ipEnd == "" {
		ipEnd = ipStart
	}

	proto := utils.StringFromMap(selectorMap, "proto")
	protoAll := strings.EqualFold(proto, "All")

	var port *networkaccessmanager.PortRange

	if portRaw, ok := selectorMap["port"]; ok && portRaw != nil {
		if protoAll {
			return networkaccessmanager.Destination{}, fmt.Errorf(`selector.port is not allowed when proto is "All"`)
		}

		portMap, ok := portRaw.(map[string]any)
		if !ok {
			return networkaccessmanager.Destination{}, fmt.Errorf("selector.port must be an object")
		}

		if _, ok := portMap["start"]; !ok {
			return networkaccessmanager.Destination{}, fmt.Errorf("missing required field: selector.port.start")
		}

		start, err := utils.IntFromMap(portMap, "start", 0)
		if err != nil {
			return networkaccessmanager.Destination{}, fmt.Errorf("selector.port.start: %w", err)
		}

		if start < 0 || start > 65535 {
			return networkaccessmanager.Destination{}, fmt.Errorf("selector.port.start must be between 0 and 65535")
		}

		end := start
		if _, ok := portMap["end"]; ok {
			end, err = utils.IntFromMap(portMap, "end", start)
			if err != nil {
				return networkaccessmanager.Destination{}, fmt.Errorf("selector.port.end: %w", err)
			}

			if end < 0 || end > 65535 {
				return networkaccessmanager.Destination{}, fmt.Errorf("selector.port.end must be between 0 and 65535")
			}
		}

		port = &networkaccessmanager.PortRange{Start: start, End: end}
	}

	var nat *networkaccessmanager.NATParameters

	if natRaw, ok := m["nat"]; ok && natRaw != nil {
		if protoAll {
			return networkaccessmanager.Destination{}, fmt.Errorf(`nat is not allowed when proto is "All"`)
		}

		natMap, ok := natRaw.(map[string]any)
		if !ok {
			return networkaccessmanager.Destination{}, fmt.Errorf("nat must be an object")
		}

		addr := utils.StringFromMap(natMap, "addr")
		if addr == "" {
			return networkaccessmanager.Destination{}, fmt.Errorf("missing required field: nat.addr")
		}

		nat = &networkaccessmanager.NATParameters{Addr: addr}

		if _, ok := natMap["port"]; ok {
			natPort, err := utils.IntFromMap(natMap, "port", 0)
			if err != nil {
				return networkaccessmanager.Destination{}, fmt.Errorf("nat.port: %w", err)
			}

			if natPort < 0 || natPort > 65535 {
				return networkaccessmanager.Destination{}, fmt.Errorf("nat.port must be between 0 and 65535")
			}

			nat.Port = natPort
		}
	}

	return networkaccessmanager.Destination{
		Sel: networkaccessmanager.Selector{
			IP:       networkaccessmanager.IPRange{Start: ipStart, End: ipEnd},
			Protocol: proto,
			Port:     port,
		},
		NAT: nat,
	}, nil
}

// ToDestinations converts an MCP destinations array.
func ToDestinations(raw any) ([]networkaccessmanager.Destination, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("must be an array")
	}

	out := make([]networkaccessmanager.Destination, 0, len(items))
	for i, item := range items {
		dst, err := ToDestination(item)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}

		out = append(out, dst)
	}

	return out, nil
}

// ToRoleHandle converts a single role object from MCP params. Only id is
// required; name is optional.
func ToRoleHandle(raw any) (networkaccessmanager.RoleHandle, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return networkaccessmanager.RoleHandle{}, fmt.Errorf("must be an object")
	}

	id := utils.StringFromMap(m, "id")
	if id == "" {
		return networkaccessmanager.RoleHandle{}, fmt.Errorf("missing required field: id")
	}

	return networkaccessmanager.RoleHandle{
		ID:   id,
		Name: utils.StringFromMap(m, "name"),
	}, nil
}

// ToRoles converts an MCP roles array.
func ToRoles(raw any) ([]networkaccessmanager.RoleHandle, error) {
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("must be an array")
	}

	out := make([]networkaccessmanager.RoleHandle, 0, len(items))
	for i, item := range items {
		role, err := ToRoleHandle(item)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}

		out = append(out, role)
	}

	return out, nil
}
