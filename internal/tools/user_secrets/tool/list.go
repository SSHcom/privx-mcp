package tool

import (
	"context"
	"fmt"

	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/api/vault"
	"github.com/pmsshintegration/privx-mcp/internal/auth"
	"github.com/pmsshintegration/privx-mcp/internal/mcp/registry"
	"github.com/pmsshintegration/privx-mcp/internal/tools/common"
	"github.com/pmsshintegration/privx-mcp/internal/utils"
)

// List returns the user-secret-list tool definition.
func List() registry.Tool {
	description := "List PrivX secrets, with pagination. " +
		"Omit user_id for global secrets. With user_id, list that user's personal secrets. " +
		"Sorted by created DESC by default. " +
		"Page with offset+limit while pagesRemaining > 0. " +
		"Returns each secret as PrivX sent it, including data. " +
		sensitiveDataGuidance + " " +
		common.PresentationGuidance

	properties := registry.NewOrderedMap().
		Set("user_id", map[string]any{
			"type":        "string",
			"minLength":   1,
			"description": "PrivX user id. Omit for global secrets.",
		}).
		Set("limit", common.LimitSchema(common.UserSecretsListLimit, common.UserSecretsListMax, "")).
		Set("offset", map[string]any{
			"type":        "integer",
			"minimum":     0,
			"description": "Zero-based index of the first secret to include in the page.",
		}).
		Set("sortKey", common.SortKeySchema()).
		Set("sortDir", common.SortDirSchema())

	inputSchema := registry.NewOrderedMap().
		Set("type", "object").
		Set("properties", properties)

	return registry.Tool{
		Name:        "user-secret-list",
		Description: description,
		Writes:      false,
		Sensitive:   true,
		InputSchema: inputSchema,
		Handler:     listHandler,
	}
}

func listHandler(ctx context.Context, params map[string]any) (*registry.ToolResult, error) {
	authCtx := auth.FromContext(ctx)
	if authCtx == nil || authCtx.Connector == nil {
		return registry.ErrorResult("authentication error: missing PrivX connector in context"), nil
	}

	paging, errResult := common.ParsePaging(params, common.UserSecretsListLimit, common.UserSecretsListMax)
	if errResult != nil {
		return errResult, nil
	}

	client := vault.New(authCtx.Connector)
	userID := utils.StringFromMap(params, "user_id")
	opts := paging.FilterOptions()

	var (
		result *response.ResultSet[vault.Secret]
		err    error
	)
	if userID == "" {
		result, err = client.GetSecrets(opts...)
	} else {
		result, err = client.GetUserSecrets(userID, opts...)
	}

	if err != nil {
		return registry.ErrorResult(fmt.Sprintf("failed to fetch secrets: %v", err)), nil
	}

	return common.JSONPage(paging, result.Items, result.Count, len(result.Items)), nil
}
