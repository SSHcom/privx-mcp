package http

import (
	"fmt"
	stdhttp "net/http"
)

// RouteRegistrar registers one logical route group to a shared ServeMux.
type RouteRegistrar func(mux *stdhttp.ServeMux) error

// NewMux creates a shared mux and applies route registrars in order.
func NewMux(registrars ...RouteRegistrar) (*stdhttp.ServeMux, error) {
	mux := stdhttp.NewServeMux()

	for idx, register := range registrars {
		if register == nil {
			return nil, fmt.Errorf("route registrar %d is nil", idx)
		}

		if err := register(mux); err != nil {
			return nil, fmt.Errorf("register routes %d: %w", idx, err)
		}
	}

	return mux, nil
}
