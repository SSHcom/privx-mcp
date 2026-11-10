package oauth

import (
	"os/exec"
	"testing"
	"time"
)

func TestStartAndReap_WaitsForExit(t *testing.T) {
	t.Parallel()

	path, err := exec.LookPath("true")
	if err != nil {
		t.Skip("true not installed")
	}

	done, err := startAndReap(exec.Command(path))
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("process was not reaped")
	}
}
