package mamori

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

//
// Policies
//

// DeletePolicy deletes a policy.
func (c *Client) DeletePolicy(ctx context.Context, policy string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/policies/"+pathEscape(strings.ToLower(policy)), nil)
}

// PoliciesGetProcedures searches on-demand policy procedures.
func (c *Client) PoliciesGetProcedures(ctx context.Context, query any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/policies/get_procedures", query)
}

// PoliciesGetRequests searches on-demand policy requests.
func (c *Client) PoliciesGetRequests(ctx context.Context, query any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/policies/get_requests", query)
}

// PoliciesGetRequestsToEndorse searches the requests the current user can
// endorse.
func (c *Client) PoliciesGetRequestsToEndorse(ctx context.Context, query any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/policies/endorse", query)
}

// PoliciesGetProcedureSQL returns the SQL of a policy procedure.
func (c *Client) PoliciesGetProcedureSQL(ctx context.Context, procedureName string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/policies/get_procedure_sql/"+procedureName, nil)
}

// PoliciesGetProcedureParameters returns the parameters of a policy procedure.
func (c *Client) PoliciesGetProcedureParameters(ctx context.Context, procedureName string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/policies/get_procedure_parameters/"+procedureName, nil)
}

// PoliciesGetProcedureOptions returns the options of a policy procedure.
func (c *Client) PoliciesGetProcedureOptions(ctx context.Context, procedureName string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/policies/get_procedure_options/"+procedureName, nil)
}

// PoliciesGetRequestParameters returns the parameters of a policy request.
func (c *Client) PoliciesGetRequestParameters(ctx context.Context, requestKey string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/policies/get_request_parameters/"+requestKey, nil)
}

// PoliciesRequestExecute requests execution of a policy procedure.
func (c *Client) PoliciesRequestExecute(ctx context.Context, procedureName string, parameters any, message string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/policies/request_execute", Params{
		"procedure_name": procedureName,
		"parameters":     parameters,
		"message":        message,
	})
}

// PoliciesRequestAction performs an action (for example endorse, deny,
// cancel or execute) on a policy request.
func (c *Client) PoliciesRequestAction(ctx context.Context, action, requestKey, message string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/policies/request_action", Params{
		"action":      action,
		"request_key": requestKey,
		"message":     message,
	})
}

// PoliciesDropProcedure drops a policy procedure.
func (c *Client) PoliciesDropProcedure(ctx context.Context, procedureName string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/policies/drop_procedure/"+procedureName, nil)
}

// ProcedureSpec describes an on-demand policy procedure for
// [Client.PoliciesCreateProcedure]. Empty string fields take the server
// defaults noted on each field.
type ProcedureSpec struct {
	ProcedureName string
	// Parameters are the procedure parameters; nil for none.
	Parameters any
	// Requires defaults to "".
	Requires string
	// Type defaults to "policy".
	Type string
	// Description defaults to ProcedureName.
	Description                   string
	RequestRole                   string
	RequestAlert                  string
	RequestDefaultMessage         string
	RequestDefaultMessageRequired string // "true"/"false", default "false"
	RequestPriorityRequired       string // "true"/"false", default "false"
	ExternalTicketNumberRequired  string // "true"/"false", default "false"
	ApprovalMessageRequired       string // "true"/"false", default "false"
	// TicketNumberRegex defaults to `TK-\d{6}`.
	TicketNumberRegex            string
	TicketNumberRegexDisplayHint string
	TicketNumberValidation       string
	EndorseAlert                 string
	EndorseDefaultMessage        string
	// EndorseAgentCount is sent as is (typically a string such as "1").
	EndorseAgentCount any
	DenyAlert         string
	ExecuteOnEndorse  string // "true"/"false", default "false"
	ExecuteAlert      string
	// ApprovalExpiry is omitted from the request when empty.
	ApprovalExpiry   string
	AllowSelfEndorse string // "true"/"false", default "false"
	// RequestExpiry is omitted from the request when empty.
	RequestExpiry string
	ExecuteAs     string
	SQL           string
}

func policiesOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// params builds the create_procedure request body, applying defaults.
func (s ProcedureSpec) params() Params {
	p := Params{
		"procedure_name":                   s.ProcedureName,
		"parameters":                       s.Parameters,
		"requires":                         s.Requires,
		"type":                             policiesOr(s.Type, "policy"),
		"description":                      policiesOr(s.Description, s.ProcedureName),
		"request_role":                     s.RequestRole,
		"request_alert":                    s.RequestAlert,
		"request_default_message":          s.RequestDefaultMessage,
		"request_default_message_required": policiesOr(s.RequestDefaultMessageRequired, "false"),
		"request_priority_required":        policiesOr(s.RequestPriorityRequired, "false"),
		"external_ticket_number_required":  policiesOr(s.ExternalTicketNumberRequired, "false"),
		"approval_message_required":        policiesOr(s.ApprovalMessageRequired, "false"),
		"ticket_number_regex":              policiesOr(s.TicketNumberRegex, `TK-\d{6}`),
		"ticket_number_regex_display_hint": s.TicketNumberRegexDisplayHint,
		"ticket_number_validation":         s.TicketNumberValidation,
		"endorse_alert":                    s.EndorseAlert,
		"endorse_default_message":          s.EndorseDefaultMessage,
		"endorse_agent_count":              s.EndorseAgentCount,
		"deny_alert":                       s.DenyAlert,
		"execute_on_endorse":               policiesOr(s.ExecuteOnEndorse, "false"),
		"execute_alert":                    s.ExecuteAlert,
		"allow_self_endorse":               policiesOr(s.AllowSelfEndorse, "false"),
		"execute_as":                       s.ExecuteAs,
		"sql":                              s.SQL,
	}
	if s.ApprovalExpiry != "" {
		p["approval_expiry"] = s.ApprovalExpiry
	}
	if s.RequestExpiry != "" {
		p["request_expiry"] = s.RequestExpiry
	}
	return p
}

// PoliciesCreateProcedure creates (or replaces) an on-demand policy
// procedure.
func (c *Client) PoliciesCreateProcedure(ctx context.Context, spec ProcedureSpec) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/policies/create_procedure", spec.params())
}

//
// Database masking policies
//

// DBMaskingPolicies searches database masking policies.
func (c *Client) DBMaskingPolicies(ctx context.Context, query any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/policies/dbpolicy/search", query)
}

// PoliciesGetPolicyColumnRules searches masking policy column rules.
func (c *Client) PoliciesGetPolicyColumnRules(ctx context.Context, query any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/policies/get_policy_column_rules", query)
}

// PoliciesSetPolicyProjection sets the projection (masking) expression of a
// column in a masking policy. Empty projectionExpression, policyName and
// tableType default to "masked", "default" and "table".
func (c *Client) PoliciesSetPolicyProjection(ctx context.Context, tableName, columnName, projectionExpression, policyName, tableType string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/policies/set_policy_projection", Params{
		"table_name":            tableName,
		"column_name":           columnName,
		"projection_expression": policiesOr(projectionExpression, "masked"),
		"policy_name":           policiesOr(policyName, "default"),
		"table_type":            policiesOr(tableType, "table"),
	})
}

// SearchUsersWithPolicy searches the users granted a policy.
func (c *Client) SearchUsersWithPolicy(ctx context.Context, policy string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/policies/"+policy+"/users", options)
}

// SearchRolesWithPolicy searches the roles granted a policy.
func (c *Client) SearchRolesWithPolicy(ctx context.Context, policy string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/policies/"+policy+"/roles", options)
}

//
// HTTP proxy API filters
//

// GetHTTPAPIFilters lists HTTP proxy API filters.
func (c *Client) GetHTTPAPIFilters(ctx context.Context, query any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/policies/http_apifilters", query)
}

// GetHTTPAPIReveals lists HTTP proxy API reveals.
func (c *Client) GetHTTPAPIReveals(ctx context.Context, query any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/policies/http_apireveals", query)
}

// AddHTTPAPIFilter creates an HTTP proxy API filter.
func (c *Client) AddHTTPAPIFilter(ctx context.Context, filter any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/policies/create_http_apifilter", Params{"filter": filter})
}

// SetHTTPAPIFilter updates an HTTP proxy API filter. filter must have an "id"
// field when JSON encoded.
func (c *Client) SetHTTPAPIFilter(ctx context.Context, filter any) (json.RawMessage, error) {
	id, err := policiesObjectID(filter)
	if err != nil {
		return nil, err
	}
	return c.Call(ctx, http.MethodPut, "/v1/policies/set_http_apifilter/"+id, Params{"filter": filter})
}

// DeleteHTTPAPIFilter deletes an HTTP proxy API filter.
func (c *Client) DeleteHTTPAPIFilter(ctx context.Context, filterID int64) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/policies/delete_http_apifilter/"+strconv.FormatInt(filterID, 10), nil)
}

// ActivateHTTPAPIFilter activates an HTTP proxy API filter.
func (c *Client) ActivateHTTPAPIFilter(ctx context.Context, filterID int64) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/policies/activate_http_apifilter/"+strconv.FormatInt(filterID, 10), nil)
}

// DisableHTTPAPIFilter disables an HTTP proxy API filter.
func (c *Client) DisableHTTPAPIFilter(ctx context.Context, filterID int64) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/policies/disable_http_apifilter/"+strconv.FormatInt(filterID, 10), nil)
}

// policiesObjectID returns the "id" field of v (a map or struct) as it would
// appear when JSON encoded, the way TS code reads obj.id.
func policiesObjectID(v any) (string, error) {
	buf, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("mamori: encoding request: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return "", fmt.Errorf("mamori: expected an object with an id: %w", err)
	}
	switch id := m["id"].(type) {
	case string:
		if id != "" {
			return id, nil
		}
	case json.Number:
		return id.String(), nil
	}
	return "", errors.New("mamori: id not specified")
}
