package store

import (
	"fmt"
	"os"
	"path/filepath"
)

// WithLock runs fn while holding an exclusive lock for key's token file.
// The lock is not reentrant. Refresh takes it for the token request and the
// following save or delete, so two proxies cannot refresh at once or remove
// a token file the other proxy has just replaced.
func WithLock(dir, key string, fn func() error) error {
	if err := os.MkdirAll(dir, tokenDirMod); err != nil {
		return fmt.Errorf("create token dir: %w", err)
	}

	f, err := os.OpenFile(lockPath(dir, key), os.O_CREATE|os.O_RDWR, tokenFileMod)
	if err != nil {
		return fmt.Errorf("open token lock: %w", err)
	}

	defer func() { _ = f.Close() }()

	if err := f.Chmod(tokenFileMod); err != nil {
		return fmt.Errorf("chmod token lock: %w", err)
	}

	if err := lockFile(f); err != nil {
		return fmt.Errorf("lock tokens: %w", err)
	}

	defer func() { _ = unlockFile(f) }()

	return fn()
}

func lockPath(dir, key string) string {
	return filepath.Join(dir, key+"_tokens.lock")
}
