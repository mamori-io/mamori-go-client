package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// OnDemandPolicyType is the type of an on-demand policy.
type OnDemandPolicyType string

// On-demand policy types.
const (
	OnDemandPolicyTypePolicy   OnDemandPolicyType = "policy"
	OnDemandPolicyTypeOther    OnDemandPolicyType = "other"
	OnDemandPolicyTypeResource OnDemandPolicyType = "resource"
)

// OnDemandPolicyParameter is a parameter the applicant supplies when
// requesting an on-demand policy.
type OnDemandPolicyParameter struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	DefaultValue any    `json:"default_value"`
	DataType     string `json:"data_type,omitempty"`
	Options      any    `json:"options,omitempty"`
}

// OnDemandPolicy is a requestable (on-demand) policy: a SQL script executed
// after an applicant's request is endorsed. Most settings are strings holding
// "true"/"false" or numbers, as the server stores them.
type OnDemandPolicy struct {
	SQLText                       string                    `json:"sqlText"`
	Name                          string                    `json:"name"`
	Description                   string                    `json:"description"`
	Requires                      string                    `json:"requires"`
	Type                          OnDemandPolicyType        `json:"type"`
	RequestRole                   string                    `json:"request_role"`
	RequestAlert                  string                    `json:"request_alert"`
	RequestDefaultMessage         string                    `json:"request_default_message"`
	RequestDefaultMessageRequired string                    `json:"request_default_message_required"`
	RequestPriorityRequired       string                    `json:"request_priority_required"`
	ExternalTicketNumberRequired  string                    `json:"external_ticket_number_required"`
	ApprovalMessageRequired       string                    `json:"approval_message_required"`
	TicketNumberRegex             string                    `json:"ticket_number_regex"`
	TicketNumberRegexDisplayHint  string                    `json:"ticket_number_regex_display_hint"`
	TicketNumberValidation        string                    `json:"ticket_number_validation"`
	EndorseAlert                  string                    `json:"endorse_alert"`
	EndorseDefaultMessage         string                    `json:"endorse_default_message"`
	EndorseAgentCount             string                    `json:"endorse_agent_count"`
	ExecuteOnEndorse              string                    `json:"execute_on_endorse"`
	ExecuteAlert                  string                    `json:"execute_alert"`
	DenyAlert                     string                    `json:"deny_alert"`
	Parameters                    []OnDemandPolicyParameter `json:"parameters"`
	ApprovalExpiry                string                    `json:"approval_expiry"`
	AllowSelfEndorse              string                    `json:"allow_self_endorse"`
	RequestExpiry                 string                    `json:"request_expiry"`
	ExecuteAs                     string                    `json:"execute_as"`
}

// NewOnDemandPolicy returns a policy with the SDK defaults. typ defaults to
// [OnDemandPolicyTypePolicy] when empty.
func NewOnDemandPolicy(name string, typ OnDemandPolicyType) *OnDemandPolicy {
	if typ == "" {
		typ = OnDemandPolicyTypePolicy
	}
	return &OnDemandPolicy{
		Name:                          name,
		Type:                          typ,
		RequestDefaultMessageRequired: "false",
		RequestPriorityRequired:       "false",
		ExternalTicketNumberRequired:  "false",
		ApprovalMessageRequired:       "false",
		TicketNumberRegex:             `TK-\d{6}`,
		EndorseAgentCount:             "1",
		ExecuteOnEndorse:              "false",
		Parameters:                    []OnDemandPolicyParameter{},
		ApprovalExpiry:                "24",
		RequestExpiry:                 "15",
		AllowSelfEndorse:              "false",
	}
}

// MarshalJSON encodes the policy record; parameters are encoded as a JSON
// string, as the server stores them.
func (p OnDemandPolicy) MarshalJSON() ([]byte, error) {
	type plain OnDemandPolicy
	params := p.Parameters
	if params == nil {
		params = []OnDemandPolicyParameter{}
	}
	enc, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		plain
		Parameters string `json:"parameters"`
	}{plain(p), string(enc)})
}

// UnmarshalJSON decodes a policy record. Parameters may be an array or a
// JSON-encoded string, and the numeric/boolean settings may be numbers or
// booleans as well as strings.
func (p *OnDemandPolicy) UnmarshalJSON(data []byte) error {
	var rec map[string]json.RawMessage
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	norm := make(map[string]json.RawMessage, len(rec))
	for k, v := range rec {
		if k == "parameters" {
			continue
		}
		var s string
		if json.Unmarshal(v, &s) == nil || string(v) == "null" {
			norm[k] = v
			continue
		}
		var x any
		if json.Unmarshal(v, &x) == nil {
			switch x.(type) {
			case bool, float64:
				b, _ := json.Marshal(string(v))
				norm[k] = b
				continue
			}
		}
		norm[k] = v
	}
	buf, err := json.Marshal(norm)
	if err != nil {
		return err
	}
	type plain OnDemandPolicy
	var out plain
	if err := json.Unmarshal(buf, &out); err != nil {
		return err
	}
	*p = OnDemandPolicy(out)
	if raw, ok := rec["parameters"]; ok {
		params, err := onDemandPolicyDecodeParameters(raw)
		if err != nil {
			return err
		}
		p.Parameters = params
	}
	return nil
}

func onDemandPolicyDecodeParameters(raw json.RawMessage) ([]OnDemandPolicyParameter, error) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if strings.TrimSpace(s) == "" {
			return []OnDemandPolicyParameter{}, nil
		}
		raw = json.RawMessage(s)
	}
	var params []OnDemandPolicyParameter
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, fmt.Errorf("mamori: decoding policy parameters: %w", err)
	}
	return params, nil
}

// AddParameter appends a request parameter. dataType and options are
// optional (pass "" and nil to omit).
func (p *OnDemandPolicy) AddParameter(name, description string, defaultValue any, dataType string, options any) []OnDemandPolicyParameter {
	p.Parameters = append(p.Parameters, OnDemandPolicyParameter{
		Name:         name,
		Description:  description,
		DefaultValue: defaultValue,
		DataType:     dataType,
		Options:      options,
	})
	return p.Parameters
}

// DeleteParameter removes the first parameter with the given name.
func (p *OnDemandPolicy) DeleteParameter(name string) []OnDemandPolicyParameter {
	for i := range p.Parameters {
		if p.Parameters[i].Name == name {
			p.Parameters = append(p.Parameters[:i], p.Parameters[i+1:]...)
			break
		}
	}
	return p.Parameters
}

// SetScript sets SQLText to a BEGIN/END block of the given statements. Blank
// lines are dropped and each statement is terminated with ";".
func (p *OnDemandPolicy) SetScript(lines []string) {
	var body []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if !strings.HasSuffix(l, ";") {
			l += ";"
		}
		body = append(body, l)
	}
	p.SQLText = "BEGIN;\n" + strings.Join(body, "\n") + "\nEND"
}

func onDemandPolicyOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func onDemandPolicyBool(v string) string {
	if v == "true" {
		return "true"
	}
	return "false"
}

func (p *OnDemandPolicy) createPayload() Params {
	var params any
	if len(p.Parameters) > 0 {
		m := make(map[string]any, len(p.Parameters))
		for i, x := range p.Parameters {
			m[strconv.Itoa(i)] = x
		}
		params = m
	}
	return Params{
		"procedure_name":                   p.Name,
		"parameters":                       params,
		"requires":                         p.Requires,
		"type":                             onDemandPolicyOr(string(p.Type), "policy"),
		"description":                      onDemandPolicyOr(p.Description, p.Name),
		"request_role":                     p.RequestRole,
		"request_alert":                    p.RequestAlert,
		"request_default_message":          p.RequestDefaultMessage,
		"request_default_message_required": onDemandPolicyOr(p.RequestDefaultMessageRequired, "false"),
		"request_priority_required":        onDemandPolicyOr(p.RequestPriorityRequired, "false"),
		"external_ticket_number_required":  onDemandPolicyOr(p.ExternalTicketNumberRequired, "false"),
		"approval_message_required":        onDemandPolicyOr(p.ApprovalMessageRequired, "false"),
		"ticket_number_regex":              onDemandPolicyOr(p.TicketNumberRegex, `TK-\d{6}`),
		"ticket_number_regex_display_hint": p.TicketNumberRegexDisplayHint,
		"ticket_number_validation":         p.TicketNumberValidation,
		"endorse_alert":                    p.EndorseAlert,
		"endorse_default_message":          p.EndorseDefaultMessage,
		"endorse_agent_count":              p.EndorseAgentCount,
		"deny_alert":                       p.DenyAlert,
		"execute_on_endorse":               onDemandPolicyBool(p.ExecuteOnEndorse),
		"execute_alert":                    p.ExecuteAlert,
		"approval_expiry":                  p.ApprovalExpiry,
		"allow_self_endorse":               onDemandPolicyBool(p.AllowSelfEndorse),
		"request_expiry":                   p.RequestExpiry,
		"execute_as":                       p.ExecuteAs,
		"sql":                              p.SQLText,
	}
}

// List searches on-demand policies. Non-admins only see policies granted to
// them.
func (s *OnDemandPolicyService) List(ctx context.Context, opts SearchOptions) (*SearchResult[OnDemandPolicy], error) {
	var res SearchResult[OnDemandPolicy]
	if err := s.client.CallInto(ctx, http.MethodPut, "/v1/policies/get_procedures", opts.params(), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Get returns the named policy with its SQL text and parameters loaded, or
// [ErrNotFound].
func (s *OnDemandPolicyService) Get(ctx context.Context, name string) (*OnDemandPolicy, error) {
	res, err := s.List(ctx, SearchOptions{Skip: 0, Take: 1, Filter: Filters{F("name", FilterEquals, name)}})
	if err != nil {
		return nil, err
	}
	if len(res.Data) == 0 {
		return nil, fmt.Errorf("mamori: on-demand policy %q: %w", name, ErrNotFound)
	}
	p := res.Data[0]
	if err := s.LoadDetails(ctx, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

var (
	onDemandPolicyOpenRe  = regexp.MustCompile(`\s+\{\s`)
	onDemandPolicyCloseRe = regexp.MustCompile(`\s\}\s`)
)

// LoadDetails fetches the SQL text and parameters of p from the server.
func (s *OnDemandPolicyService) LoadDetails(ctx context.Context, p *OnDemandPolicy) error {
	raw, err := s.client.Call(ctx, http.MethodGet, "/v1/policies/get_procedure_sql/"+pathEscape(p.Name), nil)
	if err != nil {
		return err
	}
	sqlText := string(raw)
	var str string
	if json.Unmarshal(raw, &str) == nil {
		sqlText = str
	}
	sqlText = strings.TrimSpace(sqlText)
	sqlText = onDemandPolicyOpenRe.ReplaceAllString(sqlText, "\n  {{ ")
	sqlText = onDemandPolicyCloseRe.ReplaceAllString(sqlText, " }} ")

	raw, err = s.client.Call(ctx, http.MethodGet, "/v1/policies/get_procedure_parameters/"+pathEscape(p.Name), nil)
	if err != nil {
		return err
	}
	params, err := onDemandPolicyDecodeParameters(raw)
	if err != nil {
		return err
	}
	p.SQLText = sqlText
	p.Parameters = params
	return nil
}

// Create creates the policy.
func (s *OnDemandPolicyService) Create(ctx context.Context, p *OnDemandPolicy) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, "/v1/policies/create_procedure", p.createPayload())
}

// Delete drops the named policy.
func (s *OnDemandPolicyService) Delete(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, "/v1/policies/drop_procedure/"+pathEscape(name), nil)
}

// Update replaces the policy by dropping and re-creating it.
func (s *OnDemandPolicyService) Update(ctx context.Context, p *OnDemandPolicy) (json.RawMessage, error) {
	if _, err := s.Delete(ctx, p.Name); err != nil {
		return nil, err
	}
	return s.Create(ctx, p)
}
