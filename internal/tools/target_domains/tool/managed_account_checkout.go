package tool

import (
	"context"
	"fmt"
	"strings"

	"github.com/SSHcom/privx-sdk-go/v2/api/authorizer"
	"github.com/SSHcom/privx-sdk-go/v2/api/filters"
	"github.com/SSHcom/privx-sdk-go/v2/api/secretsmanager"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/tools/target_domains"
)

const (
	targetDomainSecretType = "TARGET_DOMAIN_SECRET"
	secretSearchLimit      = 25
)

// ManagedAccountCheckout returns the target-domain-managed-account-checkout tool definition.
// Trusted and sensitive: the password and the other checkout fields are returned
// as PrivX sent them. The response word filter does not apply.
func ManagedAccountCheckout() registry.Tool {
	description := "Check out the current password of one managed account under a PrivX target domain. " +
		"Call with the target domain id and the account id or username. A value containing @ is the username. " +
		"Returns only the latest password for that account under this target domain. " +
		"Secrets for the same account under other target domains are not included. " +
		"If explicit_checkout or rotation_enabled is not enabled, ask the user before setting them. " +
		"If the user declines, secrets are not available for that account. " +
		"The account must be added to a host with a role. " +
		"Releasing every checkout rotates the password again when the policy has rotate-on-release. " +
		"The result contains the password and must not be written into logs, tickets, or chat transcripts. " +
		target_domains.SensitiveDataGuidance + " " +
		common.PresentationGuidance

	return registry.Tool{
		Name:        "target-domain-managed-account-checkout",
		Description: description,
		Writes:      true,
		Sensitive:   true,
		Trusted:     true,
		InputSchema: managedAccountCheckoutSchema(),
		Handler:     checkoutManagedAccountHandler,
	}
}

func managedAccountCheckoutSchema() *registry.OrderedMap {
	properties := registry.NewOrderedMap().
		Set("id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "The id of the target domain that owns the managed account.",
		}).
		Set("account_id", map[string]any{
			"type":      "string",
			"minLength": 1,
			"description": "The managed account id, or its username. A value containing @ is the username (email). " +
				"Only the secret under the given target domain is returned.",
		})

	return registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties).
		Set("required", []string{"id", "account_id"}).
		Set("additionalProperties", false)
}

func checkoutManagedAccountHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	domainID, accountRef, errResult := managedAccountIDs(params)
	if errResult != nil {
		return errResult, nil
	}

	accounts := secretsmanager.New(authCtx.Connector)

	account, err := loadCheckoutAccount(accounts, domainID, accountRef)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch managed account: %v", err)), nil
	}

	if !account.ExplicitCheckout {
		return registry.ErrorResult("explicit checkout is disabled for this managed account"), nil
	}

	if account.Username == "" {
		return registry.ErrorResult("managed account has no username"), nil
	}

	accountID := account.ID
	if accountID == "" {
		accountID = accountRef
	}

	secrets := authorizer.New(authCtx.Connector)

	path, err := findTargetDomainSecretPath(secrets, domainID, account.Username)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to search account secrets: %v", err)), nil
	}

	if path == "" {
		return registry.ErrorResult("managed account is not available for checkout; it must be added to a host with a role"), nil
	}

	// CheckoutAccountSecret decodes a ResultSet. This PrivX returns one checkout object.
	var checkout authorizer.Checkout

	_, err = authCtx.Connector.
		URL("/authorizer/api/v1/secrets/checkouts").
		Post(authorizer.CheckoutRequest{Path: path}, &checkout)
	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to check out managed account: %v", err)), nil
	}

	if !checkoutBelongsToDomain(checkout, domainID, accountID) {
		return registry.ErrorResult("checkout secret is not under this target domain"), nil
	}

	latest, ok := latestSecret(checkout.Secrets)
	if !ok || latest.Secret == "" {
		return registry.ErrorResult("checkout returned no password"), nil
	}

	return common.JSONResult(map[string]any{
		"managed_account_id": accountID,
		"username":           checkout.Username,
		"path":               checkout.Path,
		"expires":            checkout.Expires,
		"version":            latest.Version,
		"secret":             latest.Secret,
	}), nil
}

// A value containing @ is a username (email). Managed account ids do not contain @.
func loadCheckoutAccount(
	client *secretsmanager.SecretsManager,
	domainID string,
	ref string,
) (*secretsmanager.ManagedAccount, error) {
	if strings.Contains(ref, "@") {
		return findManagedAccountByUsername(client, domainID, ref)
	}

	account, err := client.GetManagedAccount(domainID, ref)
	if err != nil {
		return nil, err
	}

	if account.TargetDomain.ID != "" && account.TargetDomain.ID != domainID {
		return nil, fmt.Errorf("managed account is not under this target domain")
	}

	return account, nil
}

func findManagedAccountByUsername(
	client *secretsmanager.SecretsManager,
	domainID string,
	username string,
) (*secretsmanager.ManagedAccount, error) {
	offset := 0

	var found secretsmanager.ManagedAccount

	matched := false

	for {
		result, err := client.SearchManagedAccounts(
			domainID,
			secretsmanager.ManagedAccountsSearch{Keywords: username},
			filters.Paging(offset, secretSearchLimit),
		)
		if err != nil {
			return nil, err
		}

		for _, item := range result.Items {
			if item.TargetDomain.ID != "" && item.TargetDomain.ID != domainID {
				continue
			}

			if !strings.EqualFold(item.Username, username) && !strings.EqualFold(item.Email, username) {
				continue
			}

			if matched && found.ID != item.ID {
				return nil, fmt.Errorf("multiple managed accounts match %q under this target domain", username)
			}

			found = item
			matched = true
		}

		offset += len(result.Items)
		if len(result.Items) == 0 || offset >= result.Count {
			break
		}
	}

	if !matched {
		return nil, fmt.Errorf("managed account %q was not found under this target domain", username)
	}

	return &found, nil
}

// SearchAccountSecrets filters by username only. The same username can be
// managed under other target domains; keep the secret for this domain.
func findTargetDomainSecretPath(client *authorizer.Authorizer, domainID, username string) (string, error) {
	prefix := targetDomainSecretPrefix(domainID)

	offset := 0
	for {
		result, err := client.SearchAccountSecrets(
			&authorizer.AccountSecretSearch{Username: username},
			filters.Paging(offset, secretSearchLimit),
		)
		if err != nil {
			return "", err
		}

		for _, item := range result.Items {
			if item.Type != targetDomainSecretType || item.TargetDomain.ID != domainID {
				continue
			}

			if item.Username != username || !strings.HasPrefix(item.Path, prefix) {
				continue
			}

			return item.Path, nil
		}

		offset += len(result.Items)
		if len(result.Items) == 0 || offset >= result.Count {
			return "", nil
		}
	}
}

func targetDomainSecretPrefix(domainID string) string {
	return "targetdomainsecrets/" + domainID + "/"
}

func checkoutBelongsToDomain(checkout authorizer.Checkout, domainID, accountID string) bool {
	if checkout.Path == "" || !strings.HasPrefix(checkout.Path, targetDomainSecretPrefix(domainID)) {
		return false
	}

	if checkout.TargetDomain.ID != "" && checkout.TargetDomain.ID != domainID {
		return false
	}

	if checkout.ManagedAccountID != "" && checkout.ManagedAccountID != accountID {
		return false
	}

	return true
}

func latestSecret(secrets []authorizer.Secrets) (authorizer.Secrets, bool) {
	if len(secrets) == 0 {
		return authorizer.Secrets{}, false
	}

	best := secrets[0]
	for _, item := range secrets[1:] {
		if item.Version > best.Version {
			best = item
		}
	}

	return best, true
}
