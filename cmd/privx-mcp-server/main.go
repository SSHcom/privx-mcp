package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/pmsshintegration/privx-mcp/internal/bootstrap"
	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
	"github.com/pmsshintegration/privx-mcp/internal/version"
)

func main() {
	os.Exit(run())
}

// run holds the server lifecycle so that deferred cleanup still executes on the
// failure paths; it returns the process exit code.
func run() int {
	if hasArg(os.Args[1:], "--version") {
		if err := version.Fprint(os.Stdout, version.Server); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)

			return 1
		}

		return 0
	}

	configPath := config.ResolveConfigPath(config.DefaultConfigFileName)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)

		return 1
	}

	logCleanup, err := logging.Setup(cfg.Server.LogFile, cfg.Server.LogLevel)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to initialize logging: %v\n", err)

		return 1
	}
	defer logCleanup()

	logDest := "stdout"
	if cfg.Server.LogFile != "" {
		logDest = cfg.Server.LogFile
	}

	if configPath == "" {
		logging.Info("no config file found, using defaults and environment overrides")
	} else {
		logging.Info("using config file", "path", configPath)
	}

	logging.Info("logging initialized", "destination", logDest, "level", cfg.Server.LogLevel)

	if !config.PublicURLIsHTTPS(cfg.Server.PublicURL) {
		logging.Warn("INSECURE: public_url is NOT HTTPS; credentials travel in CLEARTEXT", "public_url", cfg.Server.PublicURL)
	}

	server, cleanup, err := bootstrap.NewServerFromConfig(cfg)
	if err != nil {
		logging.Error("failed to initialize server", "err", err)

		return 1
	}

	defer cleanup()

	logging.Info("HTTP server listening",
		"addr", server.Addr,
		"routes", "/.well-known/oauth-protected-resource, /mcp",
	)

	serve := server.ListenAndServe

	if cfg.Server.TLSCertFile != "" && cfg.Server.TLSKeyFile != "" {
		logging.Info("TLS enabled", "cert", cfg.Server.TLSCertFile, "key", cfg.Server.TLSKeyFile)

		serve = func() error {
			return server.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		}
	}

	if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logging.Error("server error", "err", err)

		return 1
	}

	return 0
}

func hasArg(args []string, names ...string) bool {
	for _, arg := range args {
		for _, name := range names {
			if arg == name {
				return true
			}
		}
	}

	return false
}
