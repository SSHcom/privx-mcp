package http

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultReadHeaderTimeout = 5 * time.Second
	defaultShutdownTimeout   = 5 * time.Second
)

// Options configures the shared HTTP server lifecycle.
type Options struct {
	Addr              string
	Handler           http.Handler
	ReadHeaderTimeout time.Duration
	ShutdownTimeout   time.Duration
}

// NewHTTPServer builds an HTTP server and returns a graceful shutdown cleanup function.
func NewHTTPServer(opts Options) (*http.Server, func(), error) {
	if opts.Handler == nil {
		return nil, nil, fmt.Errorf("http handler is required")
	}

	readHeaderTimeout := opts.ReadHeaderTimeout
	if readHeaderTimeout <= 0 {
		readHeaderTimeout = defaultReadHeaderTimeout
	}

	shutdownTimeout := opts.ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = defaultShutdownTimeout
	}

	server := &http.Server{
		Addr:              opts.Addr,
		Handler:           opts.Handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return
		}
	}

	return server, cleanup, nil
}
