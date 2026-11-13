package hosts

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SSHcom/privx-sdk-go/v2/api/hoststore"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/testutil/testconn"
)

func TestApplyServiceOptions_SSHAllSixFields(t *testing.T) {
	got, err := ApplyServiceOptions(nil, map[string]any{
		"ssh": map[string]any{
			"shell": true, "file_transfer": false, "exec": true,
			"tunnels": false, "x11": true, "other": false,
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	want := hoststore.SSHServiceOptions{Shell: true, Exec: true, X11: true}
	if got.SSHServiceOptions == nil || *got.SSHServiceOptions != want {
		t.Fatalf("ssh = %+v, want %+v", got.SSHServiceOptions, want)
	}
}

func TestApplyServiceOptions_PartialSSHKeepsDefaultsEnabled(t *testing.T) {
	got, err := ApplyServiceOptions(nil, map[string]any{
		"ssh": map[string]any{"tunnels": false},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	want := hoststore.SSHServiceOptions{Shell: true, FileTransfer: true, Exec: true, X11: true, Other: true}
	if *got.SSHServiceOptions != want {
		t.Fatalf("ssh = %+v, want %+v (only tunnels off)", *got.SSHServiceOptions, want)
	}
}

func TestApplyServiceOptions_PartialOtherProtocolsDefaultToFalse(t *testing.T) {
	got, err := ApplyServiceOptions(nil, map[string]any{
		"rdp": map[string]any{"clipboard": true},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	want := hoststore.RDPServiceOptions{Clipboard: true}
	if *got.RDPServiceOptions != want {
		t.Fatalf("rdp = %+v, want %+v", *got.RDPServiceOptions, want)
	}
}

func TestApplyServiceOptions_PartialKeepsBaseValues(t *testing.T) {
	base := &hoststore.HostServiceOptions{
		SSHServiceOptions: &hoststore.SSHServiceOptions{
			Shell: true, FileTransfer: true, Exec: true, Tunnels: true, X11: true, Other: true,
		},
		RDPServiceOptions: &hoststore.RDPServiceOptions{Clipboard: true},
	}

	got, err := ApplyServiceOptions(base, map[string]any{
		"ssh": map[string]any{"tunnels": false},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	want := hoststore.SSHServiceOptions{Shell: true, FileTransfer: true, Exec: true, X11: true, Other: true}
	if *got.SSHServiceOptions != want {
		t.Errorf("ssh = %+v, want %+v", *got.SSHServiceOptions, want)
	}

	if got.RDPServiceOptions == nil || !got.RDPServiceOptions.Clipboard {
		t.Errorf("rdp not supplied, should be kept: %+v", got.RDPServiceOptions)
	}
}

func TestApplyServiceOptions_DoesNotMutateBase(t *testing.T) {
	base := &hoststore.HostServiceOptions{
		SSHServiceOptions: &hoststore.SSHServiceOptions{Shell: true, Tunnels: true},
	}

	if _, err := ApplyServiceOptions(base, map[string]any{
		"ssh": map[string]any{"tunnels": false, "shell": false},
	}); err != nil {
		t.Fatalf("err: %v", err)
	}

	if !base.SSHServiceOptions.Shell || !base.SSHServiceOptions.Tunnels {
		t.Fatalf("base was mutated: %+v", *base.SSHServiceOptions)
	}
}

func TestApplyServiceOptions_AllProtocols(t *testing.T) {
	got, err := ApplyServiceOptions(nil, map[string]any{
		"ssh": map[string]any{"shell": true},
		"rdp": map[string]any{"file_transfer": true, "audio": true, "clipboard": false},
		"web": map[string]any{"file_transfer": false, "audio": true, "clipboard": true},
		"vnc": map[string]any{"file_transfer": true, "clipboard": true},
		// 1048576 arrives as float64 from JSON.
		"db": map[string]any{"max_bytes_upload": float64(1048576), "max_bytes_download": float64(0)},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if want := (hoststore.RDPServiceOptions{FileTransfer: true, Audio: true}); *got.RDPServiceOptions != want {
		t.Errorf("rdp = %+v, want %+v", *got.RDPServiceOptions, want)
	}

	if want := (hoststore.WebServiceOptions{Audio: true, Clipboard: true}); *got.WebServiceOptions != want {
		t.Errorf("web = %+v, want %+v", *got.WebServiceOptions, want)
	}

	if want := (hoststore.VNCServiceOptions{FileTransfer: true, Clipboard: true}); *got.VNCServiceOptions != want {
		t.Errorf("vnc = %+v, want %+v", *got.VNCServiceOptions, want)
	}

	if want := (hoststore.DBServiceOptions{MaxBytesUpload: 1048576}); *got.DBServiceOptions != want {
		t.Errorf("db = %+v, want %+v", *got.DBServiceOptions, want)
	}
}

func TestApplyServiceOptions_EmptyProtocolObjectChangesNothing(t *testing.T) {
	got, err := ApplyServiceOptions(nil, map[string]any{"ssh": map[string]any{}})
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if got.SSHServiceOptions != nil {
		t.Fatalf("empty ssh object must not create options (would disable everything): %+v", got.SSHServiceOptions)
	}
}

func TestApplyServiceOptions_Rejects(t *testing.T) {
	cases := []struct {
		name string
		raw  any
		want string
	}{
		{"not an object", "ssh", "must be an object"},
		{"nil", nil, "must be an object"},
		{"unknown protocol", map[string]any{"telnet": map[string]any{}}, "unsupported field(s) telnet"},
		{"unknown ssh field", map[string]any{"ssh": map[string]any{"shel": true}}, "ssh: unsupported field(s) shel"},
		{"protocol not an object", map[string]any{"ssh": true}, "ssh must be an object"},
		{"ssh non-bool", map[string]any{"ssh": map[string]any{"shell": 1}}, "ssh: shell must be a boolean"},
		{"db negative", map[string]any{"db": map[string]any{"max_bytes_upload": float64(-1)}}, "non-negative integer"},
		{"db fractional", map[string]any{"db": map[string]any{"max_bytes_upload": 1.5}}, "non-negative integer"},
		{"db string", map[string]any{"db": map[string]any{"max_bytes_download": "10"}}, "non-negative integer"},
		{"db unknown field", map[string]any{"db": map[string]any{"max_bytes": 1}}, "db: unsupported field(s) max_bytes"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ApplyServiceOptions(nil, tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestResolvePrincipals_ServiceOptions(t *testing.T) {
	resolveAdmin := func(conn *testconn.FakeConnector) {
		conn.Handle("POST", "/role-store/api/v1/roles/resolve", func(any) (any, error) {
			return response.ResultSet[testconn.RolestoreRole]{
				Items: []testconn.RolestoreRole{{ID: "r1", Name: "admin"}},
			}, nil
		})
	}

	t.Run("supplied on create", func(t *testing.T) {
		conn := testconn.New(t)
		resolveAdmin(conn)

		principals, err := ResolvePrincipals([]any{
			map[string]any{
				"principal":       "rocky",
				"roles":           []any{"admin"},
				"service_options": map[string]any{"ssh": map[string]any{"tunnels": false}},
			},
		}, conn, nil)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		ssh := principals[0].ServiceOptions.SSHServiceOptions
		if ssh == nil || !ssh.Shell || !ssh.Exec || !ssh.FileTransfer || ssh.Tunnels {
			t.Fatalf("ssh = %+v, want everything on except tunnels", ssh)
		}
	})

	t.Run("omitted on create stays unset", func(t *testing.T) {
		conn := testconn.New(t)
		resolveAdmin(conn)

		principals, err := ResolvePrincipals([]any{
			map[string]any{"principal": "rocky", "roles": []any{"admin"}},
		}, conn, nil)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		if principals[0].ServiceOptions != nil {
			t.Fatalf("ServiceOptions = %+v, want nil", principals[0].ServiceOptions)
		}
	})

	t.Run("invalid shape fails before role lookup", func(t *testing.T) {
		// A nil connector would panic if a role lookup were attempted.
		_, err := ResolvePrincipals([]any{
			map[string]any{
				"principal":       "rocky",
				"roles":           []any{"admin"},
				"service_options": map[string]any{"ssh": map[string]any{"shel": true}},
			},
		}, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "principals[0]: service_options") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestPatchHost_PrincipalServiceOptions(t *testing.T) {
	newConn := func(t *testing.T) *testconn.FakeConnector {
		conn := testconn.New(t)
		conn.Handle("POST", "/role-store/api/v1/roles/resolve", func(any) (any, error) {
			return response.ResultSet[testconn.RolestoreRole]{
				Items: []testconn.RolestoreRole{{ID: "r1", Name: "admin"}},
			}, nil
		})

		return conn
	}

	allSSH := func() *hoststore.HostServiceOptions {
		return &hoststore.HostServiceOptions{SSHServiceOptions: &hoststore.SSHServiceOptions{
			Shell: true, FileTransfer: true, Exec: true, Tunnels: true, X11: true, Other: true,
		}}
	}

	t.Run("overlays on stored principal", func(t *testing.T) {
		h := &hoststore.Host{Principals: []hoststore.HostPrincipals{
			{Principal: "rocky", ServiceOptions: allSSH()},
		}}

		err := PatchHost(h, map[string]any{"principals": []any{
			map[string]any{
				"principal":       "rocky",
				"roles":           []any{"admin"},
				"service_options": map[string]any{"ssh": map[string]any{"tunnels": false, "x11": false}},
			},
		}}, &auth.AuthContext{Connector: newConn(t)})
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		want := hoststore.SSHServiceOptions{Shell: true, FileTransfer: true, Exec: true, Other: true}
		if got := h.Principals[0].ServiceOptions.SSHServiceOptions; got == nil || *got != want {
			t.Fatalf("ssh = %+v, want %+v", got, want)
		}
	})

	t.Run("omitted keeps stored", func(t *testing.T) {
		h := &hoststore.Host{Principals: []hoststore.HostPrincipals{
			{Principal: "rocky", ServiceOptions: allSSH()},
		}}

		err := PatchHost(h, map[string]any{"principals": []any{
			map[string]any{"principal": "rocky", "roles": []any{"admin"}},
		}}, &auth.AuthContext{Connector: newConn(t)})
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		if got := h.Principals[0].ServiceOptions; got == nil || !got.SSHServiceOptions.Tunnels {
			t.Fatalf("stored options lost: %+v", got)
		}
	})

	t.Run("new principal starts from defaults, not from another principal", func(t *testing.T) {
		// rocky has only exec on, so inheriting from it would be visible.
		h := &hoststore.Host{Principals: []hoststore.HostPrincipals{
			{Principal: "rocky", ServiceOptions: &hoststore.HostServiceOptions{
				SSHServiceOptions: &hoststore.SSHServiceOptions{Exec: true},
			}},
		}}

		err := PatchHost(h, map[string]any{"principals": []any{
			map[string]any{"principal": "rocky", "roles": []any{"admin"}},
			map[string]any{
				"principal":       "newbie",
				"roles":           []any{"admin"},
				"service_options": map[string]any{"ssh": map[string]any{"tunnels": false}},
			},
		}}, &auth.AuthContext{Connector: newConn(t)})
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		want := hoststore.SSHServiceOptions{Shell: true, FileTransfer: true, Exec: true, X11: true, Other: true}
		if got := h.Principals[1].ServiceOptions.SSHServiceOptions; got == nil || *got != want {
			t.Fatalf("newbie ssh = %+v, want %+v (defaults, not rocky's)", got, want)
		}
	})

	t.Run("duplicate names stay paired in order", func(t *testing.T) {
		first := &hoststore.HostServiceOptions{SSHServiceOptions: &hoststore.SSHServiceOptions{Shell: true, Exec: true}}
		second := &hoststore.HostServiceOptions{SSHServiceOptions: &hoststore.SSHServiceOptions{Shell: true, X11: true}}
		h := &hoststore.Host{Principals: []hoststore.HostPrincipals{
			{Principal: "root", ServiceOptions: first},
			{Principal: "root", ServiceOptions: second},
		}}

		err := PatchHost(h, map[string]any{"principals": []any{
			map[string]any{
				"principal":       "root",
				"roles":           []any{"admin"},
				"service_options": map[string]any{"ssh": map[string]any{"shell": false}},
			},
			map[string]any{
				"principal":       "root",
				"roles":           []any{"admin"},
				"service_options": map[string]any{"ssh": map[string]any{"shell": false}},
			},
		}}, &auth.AuthContext{Connector: newConn(t)})
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		if want := (hoststore.SSHServiceOptions{Exec: true}); *h.Principals[0].ServiceOptions.SSHServiceOptions != want {
			t.Errorf("first = %+v, want %+v", *h.Principals[0].ServiceOptions.SSHServiceOptions, want)
		}

		if want := (hoststore.SSHServiceOptions{X11: true}); *h.Principals[1].ServiceOptions.SSHServiceOptions != want {
			t.Errorf("second = %+v, want %+v", *h.Principals[1].ServiceOptions.SSHServiceOptions, want)
		}
	})
}

func TestHostPrincipalItemSchema_ExposesServiceOptions(t *testing.T) {
	raw, err := json.Marshal(HostPrincipalItemSchema())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	props := schema["properties"].(map[string]any)

	so, ok := props["service_options"].(map[string]any)
	if !ok {
		t.Fatalf("service_options missing from principal schema: %s", raw)
	}

	protocols := so["properties"].(map[string]any)
	for _, name := range []string{"ssh", "rdp", "web", "vnc", "db"} {
		if _, ok := protocols[name]; !ok {
			t.Errorf("protocol %q missing", name)
		}
	}

	ssh := protocols["ssh"].(map[string]any)["properties"].(map[string]any)
	for _, name := range []string{"shell", "file_transfer", "exec", "tunnels", "x11", "other"} {
		if _, ok := ssh[name]; !ok {
			t.Errorf("ssh option %q missing", name)
		}
	}

	if _, hasRequired := so["required"]; hasRequired {
		t.Errorf("service_options fields must all be optional")
	}

	required := schema["required"].([]any)
	if len(required) != 2 {
		t.Errorf("principal required = %v, want only principal and roles", required)
	}
}
