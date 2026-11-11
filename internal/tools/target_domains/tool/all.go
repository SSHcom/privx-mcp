package tool

import "github.com/pmsshintegration/privx-mcp/internal/mcp/registry"

// All returns target-domain tools for registration.
func All() []registry.Tool {
	return []registry.Tool{
		List(),
		Get(),
		Create(),
		Update(),
		// Delete stays implemented but is not registered.
		// Rationale: A wrong domain deletion has too large a blast radius.
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
