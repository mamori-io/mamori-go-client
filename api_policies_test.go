package mamori

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestPoliciesCreateProcedureDefaults(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	if _, err := c.PoliciesCreateProcedure(ctx, ProcedureSpec{ProcedureName: "p1", SQL: "select 1"}); err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.Method != http.MethodPost || r.Path != "/api/v1/policies/create_procedure" {
		t.Fatalf("unexpected request %+v", r)
	}
	want := map[string]any{
		"procedure_name":                   "p1",
		"parameters":                       nil,
		"requires":                         "",
		"type":                             "policy",
		"description":                      "p1",
		"request_role":                     "",
		"request_alert":                    "",
		"request_default_message":          "",
		"request_default_message_required": "false",
		"request_priority_required":        "false",
		"external_ticket_number_required":  "false",
		"approval_message_required":        "false",
		"ticket_number_regex":              `TK-\d{6}`,
		"ticket_number_regex_display_hint": "",
		"ticket_number_validation":         "",
		"endorse_alert":                    "",
		"endorse_default_message":          "",
		"endorse_agent_count":              nil,
		"deny_alert":                       "",
		"execute_on_endorse":               "false",
		"execute_alert":                    "",
		"allow_self_endorse":               "false",
		"execute_as":                       "",
		"sql":                              "select 1",
	}
	for k, v := range want {
		got, ok := r.Body[k]
		if !ok || got != v {
			t.Errorf("%s = %#v (present %v), want %#v", k, got, ok, v)
		}
	}
	for _, k := range []string{"approval_expiry", "request_expiry"} {
		if _, ok := r.Body[k]; ok {
			t.Errorf("%s should be omitted when empty", k)
		}
	}
	if len(r.Body) != len(want) {
		t.Errorf("unexpected body keys: %v", r.Body)
	}
}

func TestPoliciesCreateProcedureValues(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	spec := ProcedureSpec{
		ProcedureName:     "p1",
		Parameters:        []any{Params{"name": "a"}},
		Type:              "resource",
		Description:       "desc",
		TicketNumberRegex: "X-\\d+",
		ExecuteOnEndorse:  "true",
		AllowSelfEndorse:  "true",
		EndorseAgentCount: "2",
		ApprovalExpiry:    "24",
		RequestExpiry:     "15",
	}
	c.PoliciesCreateProcedure(context.Background(), spec)
	b := (*reqs)[0].Body
	if b["type"] != "resource" || b["description"] != "desc" || b["ticket_number_regex"] != "X-\\d+" ||
		b["execute_on_endorse"] != "true" || b["allow_self_endorse"] != "true" || b["endorse_agent_count"] != "2" ||
		b["approval_expiry"] != "24" || b["request_expiry"] != "15" {
		t.Fatalf("unexpected body %v", b)
	}
	if ps, _ := b["parameters"].([]any); len(ps) != 1 {
		t.Fatalf("parameters: %v", b["parameters"])
	}
}

func TestPoliciesSetPolicyProjectionDefaults(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	c.PoliciesSetPolicyProjection(context.Background(), "t", "c", "", "", "")
	b := (*reqs)[0].Body
	if b["projection_expression"] != "masked" || b["policy_name"] != "default" || b["table_type"] != "table" {
		t.Fatalf("unexpected body %v", b)
	}
}

func TestSetHTTPAPIFilter(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	if _, err := c.SetHTTPAPIFilter(ctx, Params{"id": 42, "name": "f"}); err != nil {
		t.Fatal(err)
	}
	type filter struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if _, err := c.SetHTTPAPIFilter(ctx, filter{ID: "abc", Name: "f"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetHTTPAPIFilter(ctx, Params{"name": "f"}); err == nil {
		t.Fatal("expected error for missing id")
	}
	r := *reqs
	if len(r) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(r))
	}
	if r[0].Method != http.MethodPut || r[0].Path != "/api/v1/policies/set_http_apifilter/42" || r[0].Body["filter"] == nil {
		t.Fatalf("unexpected request %+v", r[0])
	}
	if r[1].Path != "/api/v1/policies/set_http_apifilter/abc" {
		t.Fatalf("unexpected request %+v", r[1])
	}
	_, err := policiesObjectID([]int{1})
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestDeletePolicy(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	c.DeletePolicy(context.Background(), "My Policy")
	if r := (*reqs)[0]; r.Method != http.MethodDelete || r.Path != "/api/v1/policies/my%20policy" {
		t.Fatalf("unexpected request %+v", r)
	}
}
