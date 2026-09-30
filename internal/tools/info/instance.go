package info

import "github.com/pmsshintegration/privx-mcp/internal/config"

// InstanceSnapshot holds non-secret PrivX/MCP connection metadata exposed by mcp-info.
type InstanceSnapshot struct {
	PrivXBaseURL       string
	SourceType         string
	IdentityClaimField string
	OAuthIssuer        string
}

// SnapshotFromConfig builds an InstanceSnapshot from server config.
func SnapshotFromConfig(cfg *config.Config) InstanceSnapshot {
	if cfg == nil {
		return InstanceSnapshot{}
	}

	return InstanceSnapshot{
		PrivXBaseURL:       cfg.PrivXAuth.PrivXBaseURL,
		SourceType:         cfg.Permissions.SourceType,
		IdentityClaimField: cfg.OAuth.IdentityClaimField,
		OAuthIssuer:        cfg.OAuth.IssuerURL,
	}
}

// authAbout explains the auth fields exposed under privx.auth.
const authAbout = "source_type is the type of PrivX user that can be authenticated; " +
	"it corresponds to the identity platform integrated with PrivX that this MCP server supports. " +
	"identity_claim_field is the OAuth claim used to identify the PrivX user corresponding to the OIDC provider. " +
	"oauth_issuer is the issuer URL of the OAuth/OIDC provider that authenticates MCP clients."

type privxAuthInfo struct {
	About              string `json:"about"`
	SourceType         string `json:"source_type"`
	IdentityClaimField string `json:"identity_claim_field"`
	OAuthIssuer        string `json:"oauth_issuer"`
}

type privxInfo struct {
	PrivXBaseURL string        `json:"privx_base_url"`
	Auth         privxAuthInfo `json:"auth"`
}

func (s InstanceSnapshot) toPrivXInfo() privxInfo {
	return privxInfo{
		PrivXBaseURL: s.PrivXBaseURL,
		Auth: privxAuthInfo{
			About:              authAbout,
			SourceType:         s.SourceType,
			IdentityClaimField: s.IdentityClaimField,
			OAuthIssuer:        s.OAuthIssuer,
		},
	}
}
