package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// PolicyType is the point at which an access policy is evaluated.
type PolicyType string

// Access policy types.
const (
	PolicyTypeBeforeConnection PolicyType = "BEFORE CONNECTION"
	PolicyTypeAfterConnection  PolicyType = "AFTER CONNECTION"
	PolicyTypeBeforeExecute    PolicyType = "BEFORE EXECUTE"
)

// PolicyAction is what happens when an access policy matches.
type PolicyAction string

// Access policy actions.
const (
	PolicyActionAllow          PolicyAction = "Allow"
	PolicyActionAllowAndLog    PolicyAction = "Allow And Log"
	PolicyActionDeny           PolicyAction = "Deny"
	PolicyActionDenyWithoutLog PolicyAction = "Deny Without Log"
)

// PolicyRuleType says whether a policy always applies or only when its rule
// matches.
type PolicyRuleType string

// Access policy rule types.
const (
	PolicyRuleTypeAlways PolicyRuleType = "Always"
	PolicyRuleTypeWhen   PolicyRuleType = "When"
)

// Policy is an access rule: a connection policy (evaluated before or after
// a connection is made) or a statement policy (evaluated before a statement
// executes). It corresponds to the TypeScript PolicyBase, ConnectionPolicy
// and StatementPolicy classes.
type Policy struct {
	// ID is the server id, set for existing policies (0 for new ones).
	ID int64 `json:"id"`
	// Position orders the policy among others of the same type.
	Position int `json:"position"`
	// Enabled enables the policy.
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	// Alert is the name of an alert channel to notify.
	Alert string `json:"alert"`
	// EventHandler is the name of an event handler to invoke.
	EventHandler string     `json:"event_handler"`
	Type         PolicyType `json:"type"`
	// RuleType, Action and RuleSEXP build the policy clause unless RuleJSON
	// is set.
	RuleType PolicyRuleType `json:"rule_type"`
	// RuleSEXP is the rule as an s-expression, e.g. "(SOURCE-IP 127.0.0.1)".
	RuleSEXP string `json:"rule_sexp"`
	// RuleJSON, when non-nil, is sent as the complete clause.
	RuleJSON any          `json:"rule_json"`
	Action   PolicyAction `json:"action"`
}

// NewConnectionPolicy returns an enabled policy of type t (normally
// PolicyTypeBeforeConnection or PolicyTypeAfterConnection) that denies
// when its rule matches.
func NewConnectionPolicy(t PolicyType, description string) *Policy {
	return &Policy{
		Type:        t,
		Description: description,
		Enabled:     true,
		Action:      PolicyActionDeny,
		RuleType:    PolicyRuleTypeWhen,
	}
}

// NewStatementPolicy returns a PolicyTypeBeforeExecute policy.
func NewStatementPolicy(description string) *Policy {
	return NewConnectionPolicy(PolicyTypeBeforeExecute, description)
}

// UnmarshalJSON decodes an access rule record as returned by the server.
// Numbers may be strings and enabled may be a string. Server records carry
// the policy type in "rule_type"; when "type" is absent it is taken from
// there (as the TypeScript build() does) and RuleType keeps its default.
func (p *Policy) UnmarshalJSON(b []byte) error {
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(b, &rec); err != nil {
		return err
	}
	*p = *NewConnectionPolicy("", "")
	str := func(k string, dst *string) {
		if v, ok := rec[k]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil {
				*dst = s
			}
		}
	}
	num := func(k string) (int64, error) {
		v, ok := rec[k]
		if !ok || string(v) == "null" || string(v) == `""` {
			return 0, nil
		}
		var s string
		if json.Unmarshal(v, &s) != nil {
			s = string(v)
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil {
			return 0, fmt.Errorf("mamori: policy %s: %w", k, err)
		}
		return int64(f), nil
	}
	var err error
	if p.ID, err = num("id"); err != nil {
		return err
	}
	pos, err := num("position")
	if err != nil {
		return err
	}
	p.Position = int(pos)
	if v, ok := rec["enabled"]; ok {
		var bv bool
		var s string
		switch {
		case json.Unmarshal(v, &bv) == nil:
			p.Enabled = bv
		case json.Unmarshal(v, &s) == nil:
			p.Enabled = s == "true"
		}
	}
	str("description", &p.Description)
	str("alert", &p.Alert)
	str("event_handler", &p.EventHandler)
	str("rule_sexp", &p.RuleSEXP)
	var action, ruleType, typ string
	str("action", &action)
	str("rule_type", &ruleType)
	str("type", &typ)
	if action != "" {
		p.Action = PolicyAction(action)
	}
	switch PolicyRuleType(ruleType) {
	case PolicyRuleTypeAlways, PolicyRuleTypeWhen:
		p.RuleType = PolicyRuleType(ruleType)
	}
	if typ != "" {
		p.Type = PolicyType(typ)
	} else {
		p.Type = PolicyType(ruleType)
	}
	if v, ok := rec["rule_json"]; ok && string(v) != "null" {
		if err := json.Unmarshal(v, &p.RuleJSON); err != nil {
			return err
		}
	}
	return nil
}

// payload builds the create/update request body.
func (p *Policy) payload(withID bool) Params {
	var clause any = p.RuleJSON
	if !policyTruthy(p.RuleJSON) {
		clause = Params{
			"action": p.Action,
			"format": "sql",
			"condition": Params{
				"clause_type": p.RuleType,
				"clauses":     p.RuleSEXP,
			},
		}
	}
	rec := Params{
		"type":        p.Type,
		"clause":      clause,
		"description": p.Description,
		"position":    p.Position,
		"alert":       p.Alert,
		"enabled":     p.Enabled,
	}
	if p.EventHandler != "" {
		rec["event_handler"] = p.EventHandler
	}
	if withID && p.ID != 0 {
		rec["id"] = p.ID
	}
	return rec
}

// policyTruthy reports whether v is set the way JavaScript truthiness would
// see it (nil, "", false and 0 are not).
func policyTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case bool:
		return x
	case float64:
		return x != 0
	case int:
		return x != 0
	}
	return true
}

// list queries current access rules (GET /v1/access_rules).
func (s *PolicyService) list(ctx context.Context, filter Params) ([]*Policy, error) {
	q := Params{}
	for k, v := range filter {
		q[k] = v
	}
	q["current"] = "Y"
	var out []*Policy
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/access_rules", q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Get returns the access rules with the given id (normally one).
func (s *PolicyService) Get(ctx context.Context, id int64) ([]*Policy, error) {
	return s.list(ctx, Params{"id": id})
}

// ListBeforeConnection returns the current before-connection policies
// matching filter (field/value pairs such as {"description": name}; may be
// nil).
func (s *PolicyService) ListBeforeConnection(ctx context.Context, filter Params) ([]*Policy, error) {
	return s.listType(ctx, filter, PolicyTypeBeforeConnection)
}

// ListAfterConnection returns the current after-connection policies
// matching filter.
func (s *PolicyService) ListAfterConnection(ctx context.Context, filter Params) ([]*Policy, error) {
	return s.listType(ctx, filter, PolicyTypeAfterConnection)
}

// ListStatement returns the current statement (before-execute) policies
// matching filter.
func (s *PolicyService) ListStatement(ctx context.Context, filter Params) ([]*Policy, error) {
	return s.listType(ctx, filter, PolicyTypeBeforeExecute)
}

func (s *PolicyService) listType(ctx context.Context, filter Params, t PolicyType) ([]*Policy, error) {
	q := Params{}
	for k, v := range filter {
		q[k] = v
	}
	q["rule_type"] = string(t)
	return s.list(ctx, q)
}

// Create creates the policy.
func (s *PolicyService) Create(ctx context.Context, p *Policy) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, "/v1/access_rules", p.payload(false))
}

// Update updates the existing policy p (p.ID must be set).
func (s *PolicyService) Update(ctx context.Context, p *Policy) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, "/v1/access_rules/"+strconv.FormatInt(p.ID, 10), p.payload(true))
}

// Delete deletes the policy with the given id.
func (s *PolicyService) Delete(ctx context.Context, id int64) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/access_rules/"+strconv.FormatInt(id, 10), nil)
}
