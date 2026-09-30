package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

const (
	// DefaultConfigFileName is the default TOML config file name searched by main.
	DefaultConfigFileName = "privx-mcp-config.toml"
	// SystemConfigPath is the system-wide config location consulted after env/CLI.
	SystemConfigPath = "/etc/privx-mcp/config.toml"
	// ConfigFlagName is the CLI flag used to pass an explicit config file path.
	ConfigFlagName = "--config"
)

// ResolveConfigPath returns the first existing config file path in this order:
//  1. PRIVX_MCP_CONFIG env var (if set)
//  2. "--config <path>" CLI argument (if present)
//  3. /etc/privx-mcp/config.toml
//  4. <current working directory>/privx-mcp-config.toml
//
// Missing candidates are skipped. Returns "" if none exist.
func ResolveConfigPath(fileName string) string {
	if fileName == "" {
		fileName = DefaultConfigFileName
	}

	for _, candidate := range resolveConfigCandidates(fileName) {
		if utils.FileExists(candidate) {
			return candidate
		}
	}

	return ""
}

// resolveConfigCandidates builds the ordered list of config file candidates.
func resolveConfigCandidates(fileName string) []string {
	lookedPaths := make([]string, 0, 4)

	if v := os.Getenv("PRIVX_MCP_CONFIG"); v != "" {
		lookedPaths = append(lookedPaths, v)
	}

	if cliPath, ok := configFlagFromArgs(os.Args); ok {
		lookedPaths = append(lookedPaths, cliPath)
	}

	lookedPaths = append(lookedPaths, SystemConfigPath)

	if wd, err := os.Getwd(); err == nil {
		lookedPaths = append(lookedPaths, filepath.Join(wd, fileName))
	}

	return lookedPaths
}

// configFlagFromArgs scans args for "--config <path>" or "--config=<path>".
func configFlagFromArgs(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == ConfigFlagName:
			if i+1 < len(args) {
				return args[i+1], true
			}

			return "", false
		case strings.HasPrefix(arg, ConfigFlagName+"="):
			return strings.TrimPrefix(arg, ConfigFlagName+"="), true
		}
	}

	return "", false
}
