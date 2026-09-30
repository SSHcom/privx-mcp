package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EnvAuthDir overrides the default token directory when set.
const EnvAuthDir = "PRIVX_MCP_PROXY_AUTH_DIR"

const (
	layoutName   = "privx-mcp-proxy-v1"
	expirySkew   = 60 * time.Second
	tokenFileMod = 0o600
	tokenDirMod  = 0o700
)

// ErrNotFound is returned when no token file exists for the store key.
var ErrNotFound = errors.New("tokens not found")

// Tokens is the on-disk OAuth token set. RefreshToken is omitted when empty.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Usable reports whether access_token can be used without refresh.
func (t Tokens) Usable(now time.Time) bool {
	if t.AccessToken == "" || t.ExpiresAt.IsZero() {
		return false
	}

	return t.ExpiresAt.After(now.Add(expirySkew))
}

// Dir is $PRIVX_MCP_PROXY_AUTH_DIR or $HOME/.mcp-auth/privx-mcp-proxy-v1.
func Dir() (string, error) {
	if d := strings.TrimSpace(os.Getenv(EnvAuthDir)); d != "" {
		return d, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home directory: %w", err)
	}

	return filepath.Join(home, ".mcp-auth", layoutName), nil
}

// Key is hex SHA-256 of mcp_url, resource, and client_id (newline-separated).
func Key(mcpURL, resource, clientID string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, mcpURL)
	_, _ = io.WriteString(h, "\n")
	_, _ = io.WriteString(h, resource)
	_, _ = io.WriteString(h, "\n")
	_, _ = io.WriteString(h, clientID)

	return hex.EncodeToString(h.Sum(nil))
}

// Load reads {key}_tokens.json from dir.
func Load(dir, key string) (Tokens, error) {
	path := tokenPath(dir, key)

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Tokens{}, ErrNotFound
		}

		return Tokens{}, fmt.Errorf("read tokens: %w", err)
	}

	var tok Tokens
	if err := json.Unmarshal(data, &tok); err != nil {
		return Tokens{}, fmt.Errorf("decode tokens: %w", err)
	}

	return tok, nil
}

// Save writes {key}_tokens.json atomically with mode 0600.
func Save(dir, key string, tok Tokens) error {
	if err := os.MkdirAll(dir, tokenDirMod); err != nil {
		return fmt.Errorf("create token dir: %w", err)
	}

	body, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return fmt.Errorf("encode tokens: %w", err)
	}

	body = append(body, '\n')

	tmp, err := os.CreateTemp(dir, key+"_tokens.json.*")
	if err != nil {
		return fmt.Errorf("create temp tokens file: %w", err)
	}

	tmpName := tmp.Name()

	cleanup := true

	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(tokenFileMod); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("chmod tokens file: %w", err)
	}

	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()

		return fmt.Errorf("write tokens: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tokens: %w", err)
	}

	if err := os.Rename(tmpName, tokenPath(dir, key)); err != nil {
		return fmt.Errorf("rename tokens: %w", err)
	}

	cleanup = false

	return nil
}

// Delete removes {key}_tokens.json. Missing files are not an error.
func Delete(dir, key string) error {
	err := os.Remove(tokenPath(dir, key))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete tokens: %w", err)
	}

	return nil
}

func tokenPath(dir, key string) string {
	return filepath.Join(dir, key+"_tokens.json")
}
