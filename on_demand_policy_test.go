package mamori

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestOnDemandPolicyCreate(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	p := NewOnDemandPolicy("pol", "")
	p.RequestRole = "rr"
	p.AddParameter("time", "number of minutes", "15", "", nil)
	p.AddParameter("x", "y", "z", "string", nil)
	p.DeleteParameter("x")
	p.SetScript([]string{"GRANT SELECT ON * TO :APPLICANT VALID FOR :time minutes", "  ", "select 1;"})
	if _, err := c.OnDemandPolicies.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.Method != "POST" || r.Path != "/api/v1/policies/create_procedure" {
		t.Fatalf("bad request %+v", r)
	}
	b := r.Body
	if b["procedure_name"] != "pol" || b["description"] != "pol" || b["type"] != "policy" ||
		b["ticket_number_regex"] != `TK-\d{6}` || b["execute_on_endorse"] != "false" ||
		b["endorse_agent_count"] != "1" || b["request_role"] != "rr" ||
		b["sql"] != "BEGIN;\nGRANT SELECT ON * TO :APPLICANT VALID FOR :time minutes;\nselect 1;\nEND" {
		t.Fatalf("bad body %v", b)
	}
	params := b["parameters"].(map[string]any)
	if len(params) != 1 || params["0"].(map[string]any)["name"] != "time" {
		t.Fatalf("bad parameters %v", params)
	}
	if _, ok := params["0"].(map[string]any)["data_type"]; ok {
		t.Fatal("data_type should be omitted")
	}

	p.Parameters = nil
	if _, err := c.OnDemandPolicies.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if v, ok := (*reqs)[1].Body["parameters"]; !ok || v != nil {
		t.Fatalf("parameters should be null, got %v", v)
	}
}

func TestOnDemandPolicyGet(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		switch r.Path {
		case "/api/v1/policies/get_procedures":
			if r.Body["filter"].(map[string]any)["0"].([]any)[2] == "missing" {
				return Params{"data": []any{}, "totalCount": 0}
			}
			return Params{"totalCount": 1, "data": []Params{{
				"name": "pol", "type": "resource", "endorse_agent_count": 2,
				"parameters": `[{"name":"time","description":"d","default_value":"15"}]`,
			}}}
		case "/api/v1/policies/get_procedure_sql/pol":
			return "  BEGIN; GRANT { x } TO y; END  "
		default:
			return []Params{{"name": "time", "description": "d", "default_value": "30"}}
		}
	})
	ctx := context.Background()
	p, err := c.OnDemandPolicies.Get(ctx, "pol")
	if err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.Method != "PUT" || r.Body["take"] != float64(1) || r.Body["filter"].(map[string]any)["0"].([]any)[1] != "=" {
		t.Fatalf("bad list request %+v", r)
	}
	if p.Type != OnDemandPolicyTypeResource || p.EndorseAgentCount != "2" {
		t.Fatalf("bad policy %+v", p)
	}
	if p.SQLText != "BEGIN; GRANT\n  {{ x }} TO y; END" {
		t.Fatalf("sql = %q", p.SQLText)
	}
	if len(p.Parameters) != 1 || p.Parameters[0].DefaultValue != "30" {
		t.Fatalf("parameters = %+v", p.Parameters)
	}
	if (*reqs)[1].Method != "GET" || (*reqs)[2].Path != "/api/v1/policies/get_procedure_parameters/pol" {
		t.Fatalf("bad detail requests %+v", (*reqs)[1:])
	}
	if _, err := c.OnDemandPolicies.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	// Round trip: parameters are serialized as a JSON string.
	buf, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["parameters"].(string); !ok {
		t.Fatalf("parameters should be a string: %s", buf)
	}
	var back OnDemandPolicy
	if err := json.Unmarshal(buf, &back); err != nil || back.Parameters[0].Name != "time" || back.SQLText != p.SQLText {
		t.Fatalf("round trip failed: %v %+v", err, back)
	}
}

func TestOnDemandPolicyUpdate(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	if _, err := c.OnDemandPolicies.Update(context.Background(), NewOnDemandPolicy("a b", OnDemandPolicyTypeOther)); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[0]; r.Method != "GET" || r.Path != "/api/v1/policies/drop_procedure/a%20b" {
		t.Fatalf("bad drop %+v", r)
	}
	if r := (*reqs)[1]; r.Method != "POST" || r.Body["type"] != "other" {
		t.Fatalf("bad create %+v", r)
	}
}
