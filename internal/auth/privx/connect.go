package privx

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	sdkoauth "github.com/SSHcom/privx-sdk-go/v2/oauth"
	"github.com/SSHcom/privx-sdk-go/v2/restapi"
	"github.com/pmsshintegration/privx-mcp/internal/auth/m2m"
	"github.com/pmsshintegration/privx-mcp/internal/auth/oauth"
	"github.com/pmsshintegration/privx-mcp/internal/config"
	"github.com/pmsshintegration/privx-mcp/internal/service/logging"
)

// ConnectWithExternalJWT maps IdP claims to a username, mints an external JWT,
// and exchanges it for an authenticated PrivX connector.
// It returns the connector together with the resolved PrivX username.
func ConnectWithExternalJWT(ctx context.Context, cfg *config.Config, claims *oauth.IdentityClaims) (restapi.Connector, string, error) {
	if cfg == nil {
		return nil, "", fmt.Errorf("config is required")
	}

	if claims == nil {
		return nil, "", fmt.Errorf("claims are required")
	}

	username, err := usernameFromClaims(cfg, claims)
	if err != nil {
		return nil, "", err
	}

	minter, err := NewJWTMinter(
		cfg.PrivXAuth.RSAKeyFile,
		cfg.PrivXAuth.RSAKeyID,
		cfg.PrivXAuth.TokenIssuer,
		cfg.PrivXAuth.PrivXJWTAudience,
		cfg.PrivXAuth.SubjectFormat,
	)
	if err != nil {
		return nil, "", fmt.Errorf("create JWT minter: %w", err)
	}

	logging.Debug(
		"minting JWT for mapped username",
		"username", username,
		"identity_claim_field", cfg.OAuth.IdentityClaimField,
		"identity_mapping_rule", cfg.OAuth.IdentityMappingRule,
	)

	mintedJWT, err := minter.Mint(username)
	if err != nil {
		return nil, "", fmt.Errorf("mint external JWT: %w", err)
	}

	exchanger, err := NewPrivXTokenExchanger(ExchangerConfig{
		PrivXBaseURL: cfg.PrivXAuth.PrivXBaseURL,
	})
	if err != nil {
		return nil, "", fmt.Errorf("create PrivX token exchanger: %w", err)
	}

	connector, err := exchanger.Exchange(ctx, mintedJWT)
	if err != nil {
		return nil, "", fmt.Errorf("exchange external JWT with PrivX: %w", err)
	}

	return connector, username, nil
}

// usernameFromClaims resolves the PrivX username. A service-secret caller is
// the configured subject. An OAuth caller goes through identity mapping.
func usernameFromClaims(cfg *config.Config, claims *oauth.IdentityClaims) (string, error) {
	if claims.Issuer == m2m.Issuer {
		if claims.Subject == "" {
			return "", fmt.Errorf("m2m subject is required")
		}

		return claims.Subject, nil
	}

	mapper := oauth.NewIdentityMapper(cfg.OAuth.IdentityClaimField, cfg.OAuth.IdentityMappingRule)

	username, err := mapper.Map(claims)
	if err != nil {
		return "", fmt.Errorf("map IdP claims to username: %w", err)
	}

	return username, nil
}

// ConnectWithAPICredentials creates an authenticated PrivX connector using API credentials.
// This flow is suitable for service-level integrations that do not exchange end-user JWTs.
func ConnectWithAPICredentials(cfg *config.Config) (restapi.Connector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}

	if cfg.PrivXAuth.PrivXBaseURL == "" {
		return nil, fmt.Errorf("privx_auth.privx_base_url is required")
	}

	if cfg.PrivXAuth.APIOAuthClientID == "" {
		return nil, fmt.Errorf("privx_auth.api_oauth_client_id is required")
	}

	if cfg.PrivXAuth.APIOAuthClientSecret == "" {
		return nil, fmt.Errorf("privx_auth.api_oauth_client_secret is required")
	}

	if cfg.PrivXAuth.APIClientID == "" {
		return nil, fmt.Errorf("privx_auth.api_client_id is required")
	}

	if cfg.PrivXAuth.APIClientSecret == "" {
		return nil, fmt.Errorf("privx_auth.api_client_secret is required")
	}

	baseOptions := []restapi.Option{
		restapi.BaseURL(cfg.PrivXAuth.PrivXBaseURL),
	}
	if cert, err := loadCACertificate(cfg.PrivXAuth.CACert); err != nil {
		return nil, fmt.Errorf("parse privx_auth.ca_cert: %w", err)
	} else if cert != nil {
		baseOptions = append(baseOptions, restapi.TrustAnchor(cert))
	}

	baseConnector := restapi.New(baseOptions...)
	authorizer := sdkoauth.WithClientID(
		baseConnector,
		sdkoauth.AuthClientId(cfg.PrivXAuth.APIOAuthClientID),
		sdkoauth.Digest(cfg.PrivXAuth.APIOAuthClientID, cfg.PrivXAuth.APIOAuthClientSecret),
		sdkoauth.Access(cfg.PrivXAuth.APIClientID),
		sdkoauth.Secret(cfg.PrivXAuth.APIClientSecret),
	)

	// Validate credentials eagerly so startup/auth failures surface immediately.
	if _, err := authorizer.AccessToken(); err != nil {
		return nil, fmt.Errorf("authenticate with api credentials: %w", err)
	}

	return restapi.New(append(baseOptions, restapi.Auth(authorizer))...), nil
}

func loadCACertificate(caCert string) (*x509.Certificate, error) {
	if strings.TrimSpace(caCert) == "" {
		return nil, nil
	}

	raw := []byte(caCert)
	if info, err := os.Stat(caCert); err == nil && !info.IsDir() {
		fileBytes, readErr := os.ReadFile(caCert)
		if readErr != nil {
			return nil, fmt.Errorf("read certificate file: %w", readErr)
		}

		raw = fileBytes
	}

	parsed, err := x509.ParseCertificate(raw)
	if err == nil {
		return parsed, nil
	}

	certs, certErr := x509.ParseCertificates(raw)
	if certErr == nil && len(certs) > 0 {
		return certs[0], nil
	}

	block, _ := pem.Decode(raw)
	if block != nil {
		parsedPEM, pemErr := x509.ParseCertificate(block.Bytes)
		if pemErr != nil {
			return nil, fmt.Errorf("parse PEM certificate: %w", pemErr)
		}

		return parsedPEM, nil
	}

	return nil, fmt.Errorf("certificate must be valid PEM or DER")
}
