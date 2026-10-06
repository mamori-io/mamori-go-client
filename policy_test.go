package mamori

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"testing"
)

func TestPolicyCreateUpdate(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	p := NewConnectionPolicy(PolicyTypeBeforeConnection, "desc")
	p.Enabled = false
	p.Position = 20
	p.Action = PolicyActionAllow
	p.RuleSEXP = "(SOURCE-IP 127.0.0.1)"
	p.Alert = "alert1"
	p.EventHandler = "eh"
	if _, err := c.Policies.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	var want Params
	json.Unmarshal([]byte(`{"type":"BEFORE CONNECTION","clause":{"action":"Allow","format":"sql","condition":{"clause_type":"When","clauses":"(SOURCE-IP 127.0.0.1)"}},"description":"desc","position":20,"alert":"alert1","enabled":false,"event_handler":"eh"}`), &want)
	if r := (*reqs)[0]; r.Method != "POST" || r.Path != "/api/v1/access_rules" || !reflect.DeepEqual(r.Body, want) {
		t.Fatalf("got %s", r.Raw)
	}

	s := NewStatementPolicy("stmt")
	s.ID = 42
	s.RuleJSON = map[string]any{"action": "Deny"}
	if _, err := c.Policies.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[1]
	if r.Method != "PUT" || r.Path != "/api/v1/access_rules/42" || r.Body["id"] != float64(42) || r.Body["type"] != "BEFORE EXECUTE" ||
		!reflect.DeepEqual(r.Body["clause"], map[string]any{"action": "Deny"}) || r.Body["enabled"] != true {
		t.Fatalf("got %s", r.Raw)
	}
	if _, ok := r.Body["event_handler"]; ok {
		t.Fatal("event_handler should be omitted")
	}
	if _, err := c.Policies.Delete(ctx, 42); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[2]; r.Method != "DELETE" || r.Path != "/api/v1/access_rules/42" {
		t.Fatalf("%+v", r)
	}
}

func TestPolicyList(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		return json.RawMessage(`[{"id":"7","position":20,"enabled":"false","description":"d","rule_type":"BEFORE CONNECTION","action":"Allow","rule_json":{"action":"Allow"}}]`)
	})
	ctx := context.Background()
	list, err := c.Policies.ListBeforeConnection(ctx, Params{"description": "d"})
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.ParseQuery((*reqs)[0].Query)
	if (*reqs)[0].Method != "GET" || q.Get("description") != "d" || q.Get("rule_type") != "BEFORE CONNECTION" || q.Get("current") != "Y" {
		t.Fatalf("query %q", (*reqs)[0].Query)
	}
	p := list[0]
	if p.ID != 7 || p.Position != 20 || p.Enabled || p.Type != PolicyTypeBeforeConnection || p.RuleType != PolicyRuleTypeWhen || p.Action != PolicyActionAllow {
		t.Fatalf("%+v", p)
	}
	if _, err := c.Policies.ListStatement(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if q, _ := url.ParseQuery((*reqs)[1].Query); q.Get("rule_type") != "BEFORE EXECUTE" {
		t.Fatalf("query %q", (*reqs)[1].Query)
	}
	if _, err := c.Policies.Get(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if q, _ := url.ParseQuery((*reqs)[2].Query); q.Get("id") != "7" || q.Get("current") != "Y" {
		t.Fatalf("query %q", (*reqs)[2].Query)
	}
}
