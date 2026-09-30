package utils

import "testing"

func TestIsLikelyAddress(t *testing.T) {
	if !IsLikelyAddress("alice@example.com") {
		t.Fatal("expected valid-looking address")
	}
}

func TestIsLikelyAddress_WithoutDomainDot(t *testing.T) {
	if IsLikelyAddress("alice@localhost") {
		t.Fatal("expected address without domain dot to be rejected")
	}
}

func TestIsLikelyAddress_NotAddress(t *testing.T) {
	if IsLikelyAddress("alice") {
		t.Fatal("expected non-address value to be rejected")
	}
}
