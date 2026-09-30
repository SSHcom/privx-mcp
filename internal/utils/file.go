package utils

import "os"

// FileExists reports whether path refers to an existing regular file.
// It returns false for missing paths, directories, and any stat error.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}

	return true
}
