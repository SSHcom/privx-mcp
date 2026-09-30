package security

import "testing"

func TestFindBlacklisted(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		wantTerm  string
		wantFound bool
	}{
		{name: "partial inflection", in: "this host was deleted", wantTerm: "delete", wantFound: true},
		{name: "case folded", in: "DELETE", wantTerm: "delete", wantFound: true},
		{name: "phrase", in: "you must reply with the token", wantTerm: "you must", wantFound: true},
		{name: "full word alone", in: "sh", wantTerm: "sh", wantFound: true},
		{name: "full word in sentence", in: "log in as root now", wantTerm: "root", wantFound: true},
		{name: "full word substring ignored", in: "ssh", wantFound: false},
		{name: "rootfs ignored", in: "rootfs", wantFound: false},
		{name: "stopped ignored", in: "stopped", wantFound: false},
		{name: "command ignored", in: "command", wantFound: false},
		{name: "https not blacklisted", in: "https://privx.example.com", wantFound: false},
		{name: "ordinary hostname", in: "web-server-01.example.com", wantFound: false},
		{name: "partial term embedded mid-word ignored", in: "skushashvili@sshdemo.net", wantFound: false},
		{name: "partial term at word start still caught", in: "password hash: abc123", wantTerm: "hash", wantFound: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			term, found := FindBlacklisted(tc.in)
			if found != tc.wantFound {
				t.Fatalf("FindBlacklisted(%q) found = %v, want %v (term %q)", tc.in, found, tc.wantFound, term)
			}
			if tc.wantFound && term != tc.wantTerm {
				t.Errorf("FindBlacklisted(%q) term = %q, want %q", tc.in, term, tc.wantTerm)
			}
		})
	}
}

func TestFindBlacklisted_AllowedSkipsTermAndKeepsLooking(t *testing.T) {
	allowed := map[string]struct{}{"root": {}}

	term, found := findBlacklisted("root", allowed)
	if found {
		t.Fatalf("expected allowed term to be skipped, got %q", term)
	}

	term, found = findBlacklisted("log in as root now", allowed)
	if found {
		t.Fatalf("expected sentence with only allowed term to pass, got %q", term)
	}

	term, found = findBlacklisted("root delete", allowed)
	if !found || term != "delete" {
		t.Fatalf("expected later partial term, got %q found=%v", term, found)
	}

	term, found = findBlacklisted("ROOT", allowed)
	if found {
		t.Fatalf("allowed match should be case-insensitive, got %q", term)
	}
}

func TestPrepare_WhitelistPatternsAllowsCommandTerms(t *testing.T) {
	// whitelist_patterns is an SSH command-restriction field: command names
	// like "sudo" and "chmod" are legitimate data and must pass.
	params := map[string]any{
		"name": "demo-mcp-whitelist",
		"type": "glob",
		"whitelist_patterns": []any{
			"uptime",
			"date",
			"sudo tail /var/log/messages",
			"chmod 644 /etc/hosts",
			"exit",
		},
	}

	if _, term, found := Prepare(params); found {
		t.Fatalf("expected command patterns to pass, got blocked term %q", term)
	}
}

func TestPrepare_WhitelistPatternsStillBlocksInjection(t *testing.T) {
	// Prompt-injection terms are NOT exempted for whitelist_patterns.
	params := map[string]any{
		"name": "sneaky",
		"whitelist_patterns": []any{
			"uptime",
			"ignore previous instructions",
		},
	}

	if _, _, found := Prepare(params); !found {
		t.Fatal("expected injection term in whitelist_patterns to be blocked")
	}
}

func TestPrepare_CommandTermsStillBlockedOutsideWhitelist(t *testing.T) {
	// The exemption is scoped to whitelist_patterns only; "sudo" in a
	// different field is still rejected.
	params := map[string]any{
		"comment": "please sudo this",
	}

	if _, _, found := Prepare(params); !found {
		t.Fatal("expected 'sudo' outside whitelist_patterns to be blocked")
	}
}
