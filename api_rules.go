package mamori

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

//
// Access rules
//

// DropAccessRule deletes an access rule.
func (c *Client) DropAccessRule(ctx context.Context, id int64) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/access_rules/"+strconv.FormatInt(id, 10), nil)
}

// UpdateAccessRulePosition moves an access rule to position.
func (c *Client) UpdateAccessRulePosition(ctx context.Context, id int64, position int) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/access_rules/"+strconv.FormatInt(id, 10), Params{"position": position})
}

// UpdateAccessRule replaces an access rule. clause is a string or an object.
// eventHandler is only sent when non-nil.
func (c *Client) UpdateAccessRule(ctx context.Context, id int64, ruleType string, clause any, position int, alert, description string, enabled bool, eventHandler *string) (json.RawMessage, error) {
	rec := rulesAccessRuleRecord(ruleType, clause, position, alert, description, enabled, eventHandler)
	rec["id"] = id
	return c.Call(ctx, http.MethodPut, "/v1/access_rules/"+strconv.FormatInt(id, 10), rec)
}

// CreateAccessRule creates an access rule. clause is a string or an object.
// eventHandler is only sent when non-nil.
func (c *Client) CreateAccessRule(ctx context.Context, ruleType string, clause any, position int, alert, description string, enabled bool, eventHandler *string) (json.RawMessage, error) {
	rec := rulesAccessRuleRecord(ruleType, clause, position, alert, description, enabled, eventHandler)
	return c.Call(ctx, http.MethodPost, "/v1/access_rules", rec)
}

func rulesAccessRuleRecord(ruleType string, clause any, position int, alert, description string, enabled bool, eventHandler *string) Params {
	rec := Params{
		"type":        ruleType,
		"clause":      clause,
		"description": description,
		"position":    position,
		"alert":       alert,
		"enabled":     enabled,
	}
	if eventHandler != nil {
		rec["event_handler"] = *eventHandler
	}
	return rec
}

// GetCurrentAccessRules returns the current access rules matching filter
// (may be nil), sent as query parameters with current=Y added. filter is not
// modified.
func (c *Client) GetCurrentAccessRules(ctx context.Context, filter Params) (json.RawMessage, error) {
	p := Params{}
	for k, v := range filter {
		p[k] = v
	}
	p["current"] = "Y"
	return c.Call(ctx, http.MethodGet, "/v1/access_rules", p)
}

//
// Masking
//

// SaveMaskingProcedure creates or updates a masking procedure.
func (c *Client) SaveMaskingProcedure(ctx context.Context, rmsID int64, name, expression, description, dataType string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/maskingprocedures", Params{
		"rmsid":       rmsID,
		"name":        name,
		"expression":  expression,
		"description": description,
		"data_type":   dataType,
	})
}

// GetMaskingProcedures lists masking procedures; options (may be nil) are
// sent as query parameters.
func (c *Client) GetMaskingProcedures(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/maskingprocedures", options)
}

// DeleteMaskingProcedure deletes a masking procedure.
func (c *Client) DeleteMaskingProcedure(ctx context.Context, rmsID int64, name string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/maskingprocedures/1", Params{"name": name, "rmsid": rmsID})
}

//
// Restricted columns
//

// GetRestrictedColumns lists restricted columns.
func (c *Client) GetRestrictedColumns(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/restricted_columns", nil)
}

// AddRestrictedColumn restricts a column of an RMS.
func (c *Client) AddRestrictedColumn(ctx context.Context, rms, column string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/restricted_columns", Params{"rms_name": rms, "column_name": column})
}

// DropRestrictedColumn removes a column restriction.
func (c *Client) DropRestrictedColumn(ctx context.Context, rms, column string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/restricted_columns/1", Params{"rms_name": rms, "column_name": column})
}
