package oauth

import (
	"fmt"
	"os/exec"
	"runtime"
)

func openBrowser(rawURL string) error {
	cmd, err := browserCommand(rawURL)
	if err != nil {
		return err
	}

	_, err = startAndReap(cmd)

	return err
}

func browserCommand(rawURL string) (*exec.Cmd, error) {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", rawURL), nil
	case "darwin":
		return exec.Command("open", rawURL), nil
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL), nil
	default:
		return nil, fmt.Errorf("unsupported platform %q", runtime.GOOS)
	}
}

// startAndReap starts cmd and waits for it in the background so a short-lived
// helper such as xdg-open does not stay a zombie.
func startAndReap(cmd *exec.Cmd) (<-chan struct{}, error) {
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("open browser: %w", err)
	}

	done := make(chan struct{})

	go func() {
		_ = cmd.Wait()

		close(done)
	}()

	return done, nil
}
