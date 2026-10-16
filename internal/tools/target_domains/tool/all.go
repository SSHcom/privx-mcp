package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns target-domain tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		List(),
		Get(),
		Create(),
		Update(),
		Delete(),
		Scan(),
		AccountSearch(),
		ManagedAccountList(),
		ManagedAccountGet(),
		ManagedAccountCreate(),
		ManagedAccountUpdate(),
		ManagedAccountDelete(),
		ManagedAccountRotate(),
		ManagedAccountCheckout(),
	}
}
