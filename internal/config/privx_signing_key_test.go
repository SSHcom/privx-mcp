package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempKey(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing.pem")
	if err := os.WriteFile(path, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() failed: %v", err)
	}
	return path
}

func TestResolvePrivXSigningKeyFile(t *testing.T) {
	want := writeTempKey(t)
	path, err := resolvePrivXSigningKeyFile(want)
	if err != nil {
		t.Fatalf("resolvePrivXSigningKeyFile returned unexpected error: %v", err)
	}
	if path != want {
		t.Fatalf("resolvePrivXSigningKeyFile path = %q, want %q", path, want)
	}
}

func TestResolvePrivXSigningKeyFile_MissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.pem")
	_, err := resolvePrivXSigningKeyFile(missing)
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected error to mention \"not found\", got: %v", err)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Fatalf("expected error to include path %q, got: %v", missing, err)
	}
}

func TestResolvePrivXSigningKeyFile_EmptyFile(t *testing.T) {
	_, err := resolvePrivXSigningKeyFile("")
	if err == nil {
		t.Fatal("expected error for empty key file path")
	}
	if !strings.Contains(err.Error(), "rsa_key_file") {
		t.Fatalf("expected error to mention rsa_key_file, got: %v", err)
	}
}

// generateTestRSAKeyPairFiles writes a fresh RSA keypair to temp files and
// returns the private and public key paths. When pkcs1 is true the private key
// is encoded as PKCS1, otherwise PKCS8. The public key is always PKIX
// ("PUBLIC KEY"), matching `openssl rsa -pubout` output.
func generateTestRSAKeyPairFiles(t *testing.T, pkcs1 bool) (privPath, pubPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	dir := t.TempDir()
	privPath = filepath.Join(dir, "private-key.pem")
	var privPEM []byte
	if pkcs1 {
		privPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		})
	} else {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
		}
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey: %v", err)
	}
	pubPath = filepath.Join(dir, "public-key.pem")
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return privPath, pubPath
}

func TestVerifyPrivXSigningKeyPair_MatchingPKCS8(t *testing.T) {
	priv, pub := generateTestRSAKeyPairFiles(t, false)
	if err := verifyPrivXSigningKeyPair(priv, pub); err != nil {
		t.Fatalf("expected matching pair to verify, got: %v", err)
	}
}

func TestVerifyPrivXSigningKeyPair_MatchingPKCS1(t *testing.T) {
	priv, pub := generateTestRSAKeyPairFiles(t, true)
	if err := verifyPrivXSigningKeyPair(priv, pub); err != nil {
		t.Fatalf("expected matching pair to verify, got: %v", err)
	}
}

func TestVerifyPrivXSigningKeyPair_Mismatch(t *testing.T) {
	priv1, _ := generateTestRSAKeyPairFiles(t, false)
	_, pub2 := generateTestRSAKeyPairFiles(t, false)
	err := verifyPrivXSigningKeyPair(priv1, pub2)
	if err == nil {
		t.Fatal("expected mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "do not form a matching keypair") {
		t.Fatalf("expected mismatch message, got: %v", err)
	}
}

func TestVerifyPrivXSigningKeyPair_MissingPublicKey(t *testing.T) {
	priv, _ := generateTestRSAKeyPairFiles(t, false)
	missing := filepath.Join(t.TempDir(), "does-not-exist.pem")
	err := verifyPrivXSigningKeyPair(priv, missing)
	if err == nil {
		t.Fatal("expected error for missing public key, got nil")
	}
	if !strings.Contains(err.Error(), "read public key") {
		t.Fatalf("expected error to mention reading public key, got: %v", err)
	}
}
