package config

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// resolvePrivXSigningKeyFile verifies that privx_auth.rsa_key_file exists so
// misconfigurations (e.g. a wrong path) surface at config load rather than
// failing later during a tool call with an opaque error. The return value is
// the path that should be used as privx_auth.rsa_key_file.
func resolvePrivXSigningKeyFile(keyFile string) (string, error) {
	if strings.TrimSpace(keyFile) == "" {
		return "", fmt.Errorf("missing required configuration field: privx_auth.rsa_key_file")
	}

	if !utils.FileExists(keyFile) {
		return "", fmt.Errorf("privx_auth.rsa_key_file not found: %q", keyFile)
	}

	return keyFile, nil
}

// verifyPrivXSigningKeyPair loads the RSA private key from privateKeyFile and
// the public key from publicKeyFile, derives the public counterpart of the
// private key, and reports an error if the two public keys are not
// byte-identical.
//
// The public key registered in PrivX's External Token Provider must match the
// private key used to sign JWTs. This check catches local keypair drift — e.g.
// one file regenerated without the other — at config load time rather than
// surfacing later as an opaque PrivX "invalid_request". It only verifies the
// two files on disk; it does not verify the key registered in PrivX itself.
func verifyPrivXSigningKeyPair(privateKeyFile, publicKeyFile string) error {
	priv, err := loadRSAPrivateKey(privateKeyFile)
	if err != nil {
		return err
	}

	pub, err := loadRSAPublicKey(publicKeyFile)
	if err != nil {
		return err
	}

	derivedDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal derived public key: %w", err)
	}

	fileDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key from %q: %w", publicKeyFile, err)
	}

	if !bytes.Equal(derivedDER, fileDER) {
		return fmt.Errorf(
			"privx_auth.rsa_key_file %q and privx_auth.rsa_public_key_file %q do not form a matching keypair; "+
				"regenerate the pair together (openssl genrsa then openssl rsa -pubout) and re-register the public key in PrivX",
			privateKeyFile, publicKeyFile,
		)
	}

	return nil
}

// loadRSAPrivateKey reads and parses an RSA private key (PKCS1 or PKCS8) from a
// PEM file.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode PEM block from signing key %q", path)
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS1 private key from %q: %w", path, err)
		}

		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS8 private key from %q: %w", path, err)
		}

		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signing key in %q is not an RSA private key", path)
		}

		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q in %q", block.Type, path)
	}
}

// loadRSAPublicKey reads and parses an RSA public key from a PEM file. Accepts
// both PKIX ("PUBLIC KEY", produced by `openssl rsa -pubout`) and PKCS1
// ("RSA PUBLIC KEY") encodings.
func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode PEM block from public key %q", path)
	}

	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key from %q: %w", path, err)
		}

		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key in %q is not an RSA public key", path)
		}

		return rsaPub, nil
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS1 public key from %q: %w", path, err)
		}

		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q in %q", block.Type, path)
	}
}
