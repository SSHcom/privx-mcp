package hosts

import (
	"testing"
)

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestToHostService(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		svc, err := ToHostService(map[string]any{"service": "SSH", "address": "10.0.0.1", "port": float64(22)})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if svc.Service != "SSH" || svc.Address != "10.0.0.1" || svc.Port != 22 {
			t.Errorf("got %+v", svc)
		}
	})
	t.Run("not an object", func(t *testing.T) {
		_, err := ToHostService("x")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("missing service", func(t *testing.T) {
		_, err := ToHostService(map[string]any{"address": "a", "port": float64(1)})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("missing address", func(t *testing.T) {
		_, err := ToHostService(map[string]any{"service": "SSH", "port": float64(1)})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("negative port", func(t *testing.T) {
		_, err := ToHostService(map[string]any{"service": "SSH", "address": "a", "port": float64(-1)})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("non-integer port", func(t *testing.T) {
		_, err := ToHostService(map[string]any{"service": "SSH", "address": "a", "port": 1.5})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestToPrincipalInput(t *testing.T) {
	t.Run("happy with roles", func(t *testing.T) {
		p, roles, err := ToPrincipalInput(map[string]any{"principal": "root", "roles": []any{"admin"}})
		if err != nil || p != "root" {
			t.Fatalf("p=%q roles=%v err=%v", p, roles, err)
		}
		if !equalStrings(roles, []string{"admin"}) {
			t.Errorf("roles = %v", roles)
		}
	})
	t.Run("empty roles allowed", func(t *testing.T) {
		p, roles, err := ToPrincipalInput(map[string]any{"principal": "root", "roles": []any{}})
		if err != nil || p != "root" || len(roles) != 0 {
			t.Fatalf("p=%q roles=%v err=%v", p, roles, err)
		}
	})
	t.Run("not an object", func(t *testing.T) {
		_, _, err := ToPrincipalInput(42)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("missing principal", func(t *testing.T) {
		_, _, err := ToPrincipalInput(map[string]any{"roles": []any{}})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("bad roles", func(t *testing.T) {
		_, _, err := ToPrincipalInput(map[string]any{"principal": "root", "roles": "admin"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestToSessionRecordingOptions(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		got, err := ToSessionRecordingOptions(nil)
		if err != nil || got != nil {
			t.Fatalf("got %v, err %v", got, err)
		}
	})
	t.Run("not object", func(t *testing.T) {
		_, err := ToSessionRecordingOptions("x")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("happy", func(t *testing.T) {
		got, err := ToSessionRecordingOptions(map[string]any{
			"disable_clipboard_recording":     true,
			"disable_file_transfer_recording": "false",
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !got.DisableClipboardRecording {
			t.Error("clipboard should be true")
		}
		if got.DisableFileTransferRecording {
			t.Error("file transfer should be false")
		}
	})
	t.Run("bad value", func(t *testing.T) {
		_, err := ToSessionRecordingOptions(map[string]any{"disable_clipboard_recording": 42})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestHostServicesFromSlice(t *testing.T) {
	services, err := HostServicesFromSlice([]any{
		map[string]any{"service": "SSH", "address": "10.0.0.1", "port": float64(22)},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(services) != 1 || services[0].Service != "SSH" {
		t.Fatalf("services = %+v", services)
	}

	_, err = HostServicesFromSlice([]any{map[string]any{"service": "SSH"}})
	if err == nil {
		t.Fatal("expected error for incomplete service")
	}
}
