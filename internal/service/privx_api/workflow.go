package api

import (
	"fmt"
	"net/url"

	"github.com/SSHcom/privx-sdk-go/v2/api/filters"
	"github.com/SSHcom/privx-sdk-go/v2/api/response"
	"github.com/SSHcom/privx-sdk-go/v2/restapi"
)

const requestableRolesPageLimit = 1000

// RequestableRole is a role the caller may request via the workflow engine.
type RequestableRole struct {
	ID                        string   `json:"id"`
	Name                      string   `json:"name"`
	Action                    string   `json:"action,omitempty"`
	GrantTypes                []string `json:"grant_types,omitempty"`
	MaxFloatingDuration       int64    `json:"max_floating_duration,omitempty"`
	MaxTimeRestrictedDuration int64    `json:"max_time_restricted_duration,omitempty"`
}

// WorkflowService wraps workflow-engine operations missing from the PrivX SDK.
type WorkflowService struct {
	api restapi.Connector
}

// NewWorkflowService creates a workflow API service for PrivX requests.
func NewWorkflowService(client restapi.Connector) *WorkflowService {
	if client == nil {
		return &WorkflowService{}
	}

	return &WorkflowService{api: client}
}

// ListRequestableRoles lists roles the caller can request (one page).
func (s *WorkflowService) ListRequestableRoles(opts ...filters.Option) (*response.ResultSet[RequestableRole], error) {
	if s == nil || s.api == nil {
		return nil, fmt.Errorf("workflow service is not initialized")
	}

	roles := &response.ResultSet[RequestableRole]{}

	params := url.Values{}
	for _, opt := range opts {
		opt(&params)
	}

	_, err := s.api.
		URL("/workflow-engine/api/v1/workflows/roles").
		Query(params).
		Get(&roles)

	return roles, err
}

// ListAllRequestableRoles fetches every requestable role using paged GETs.
func (s *WorkflowService) ListAllRequestableRoles() ([]RequestableRole, error) {
	if s == nil || s.api == nil {
		return nil, fmt.Errorf("workflow service is not initialized")
	}

	roles := make([]RequestableRole, 0)
	offset := 0

	for {
		page, err := s.ListRequestableRoles(
			filters.Limit(requestableRolesPageLimit),
			filters.Offset(offset),
		)
		if err != nil {
			return nil, err
		}

		if page == nil || len(page.Items) == 0 {
			break
		}

		roles = append(roles, page.Items...)
		offset += len(page.Items)

		if !hasMoreRequestableRoles(page, offset) {
			break
		}
	}

	return roles, nil
}

func hasMoreRequestableRoles(page *response.ResultSet[RequestableRole], fetched int) bool {
	if page == nil {
		return false
	}

	if page.Count > 0 {
		return fetched < page.Count
	}

	return len(page.Items) == requestableRolesPageLimit
}
