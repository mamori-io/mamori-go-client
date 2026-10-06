package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// SQLMaskingTableType says whether a masking rule applies to a table or a
// result set.
type SQLMaskingTableType string

// Masking rule table types.
const (
	SQLMaskingTableTypeTable     SQLMaskingTableType = "table"
	SQLMaskingTableTypeResultset SQLMaskingTableType = "resultset"
)

// SQLMaskingPolicy is a named set of column masking rules that can be
// granted to users and roles.
type SQLMaskingPolicy struct {
	// ID is the server id, set once the policy exists.
	ID *int64 `json:"id"`
	// Name is the unique policy name.
	Name string `json:"name"`
	// Priority orders policies; nil leaves the server default.
	Priority *int  `json:"priority"`
	Rules    []any `json:"rules"`
}

// NewSQLMaskingPolicy returns a policy with the given name.
func NewSQLMaskingPolicy(name string) *SQLMaskingPolicy {
	return &SQLMaskingPolicy{Name: name, Rules: []any{}}
}

// List searches SQL masking policies.
func (s *SQLMaskingPolicyService) List(ctx context.Context, opts SearchOptions) (*SearchResult[Params], error) {
	var res SearchResult[Params]
	if err := s.client.CallInto(ctx, http.MethodPut, "/v1/policies/dbpolicy/search", opts.params(), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Get returns the named policy, or ErrNotFound.
func (s *SQLMaskingPolicyService) Get(ctx context.Context, name string) (*SQLMaskingPolicy, error) {
	var list []*SQLMaskingPolicy
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/policies/dbpolicy/"+pathEscape(name), nil, &list); err != nil {
		return nil, err
	}
	if len(list) == 0 || list[0] == nil {
		return nil, fmt.Errorf("mamori: SQL masking policy %q: %w", name, ErrNotFound)
	}
	return list[0], nil
}

// ListColumnRules returns the column rules of the named policy.
func (s *SQLMaskingPolicyService) ListColumnRules(ctx context.Context, name string) (json.RawMessage, error) {
	payload := Params{"filter": Filters{F("name", FilterEqualsString, name)}.GridFilter()}
	return s.client.Call(ctx, http.MethodPut, "/v1/policies/get_policy_column_rules", payload)
}

func (s *SQLMaskingPolicyService) setProjection(ctx context.Context, policy, table, column, expression string, tableType SQLMaskingTableType) (json.RawMessage, error) {
	if expression == "" {
		expression = "masked"
	}
	if policy == "" {
		policy = "default"
	}
	if tableType == "" {
		tableType = SQLMaskingTableTypeTable
	}
	return s.client.Call(ctx, http.MethodPut, "/v1/policies/set_policy_projection", Params{
		"table_name":            table,
		"column_name":           column,
		"projection_expression": expression,
		"policy_name":           policy,
		"table_type":            tableType,
	})
}

// AddColumnRule adds a masking rule for table.column to the named policy,
// e.g. expression "masked by full()". tableType defaults to table. The
// first element of the server response is returned.
func (s *SQLMaskingPolicyService) AddColumnRule(ctx context.Context, policy, table, column, expression string, tableType SQLMaskingTableType) (json.RawMessage, error) {
	return firstElement(s.setProjection(ctx, policy, table, column, expression, tableType))
}

// DeleteColumnRule removes the masking rule for table.column from the
// named policy (sets it to REVEAL).
func (s *SQLMaskingPolicyService) DeleteColumnRule(ctx context.Context, policy, table, column string, tableType SQLMaskingTableType) (json.RawMessage, error) {
	return s.setProjection(ctx, policy, table, column, "REVEAL", tableType)
}

// Create creates the policy.
func (s *SQLMaskingPolicyService) Create(ctx context.Context, p *SQLMaskingPolicy) (json.RawMessage, error) {
	opts := Params{"name": p.Name, "description": ""}
	if p.Priority != nil && *p.Priority != 0 {
		opts["priority"] = *p.Priority
	}
	return s.client.Call(ctx, http.MethodPost, "/v1/policies/dbpolicy", opts)
}

// Update updates the policy's name and priority. p.ID must be set.
func (s *SQLMaskingPolicyService) Update(ctx context.Context, p *SQLMaskingPolicy) (json.RawMessage, error) {
	if p.ID == nil {
		return nil, fmt.Errorf("mamori: SQL masking policy %q has no id", p.Name)
	}
	data := Params{"id": *p.ID, "name": p.Name}
	if p.Priority != nil && *p.Priority != 0 {
		data["priority"] = *p.Priority
	}
	return s.client.Call(ctx, http.MethodPut, fmt.Sprintf("/v1/policies/dbpolicy/%d", *p.ID), data)
}

// Delete deletes the named policy and any grants of it.
func (s *SQLMaskingPolicyService) Delete(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/policies/dbpolicy/"+pathEscape(name), nil)
}

// GrantTo grants the named policy to grantee.
func (s *SQLMaskingPolicyService) GrantTo(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Grant(ctx, NewPolicyPermission(name, grantee))
	return err
}

// RevokeFrom revokes the named policy from grantee.
func (s *SQLMaskingPolicyService) RevokeFrom(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Revoke(ctx, NewPolicyPermission(name, grantee))
	return err
}
