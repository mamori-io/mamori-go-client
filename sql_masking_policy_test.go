package mamori

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSQLMaskingPolicy(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		switch {
		case r.Path == "/api/v1/policies/dbpolicy/search":
			return Params{"totalCount": 1, "data": []any{Params{"name": "p"}}}
		case r.Path == "/api/v1/policies/dbpolicy/p" && r.Method == "GET":
			return []any{Params{"id": 5, "name": "p", "priority": 100}}
		case r.Path == "/api/v1/policies/dbpolicy/missing":
			return []any{}
		case r.Path == "/api/v1/grantee/bob":
			return []string{"Granted"}
		case r.Path == "/api/v1/policies/set_policy_projection":
			return []any{Params{"status": "OK"}}
		}
		return "ok"
	})
	ctx := context.Background()
	prio := 100
	p := NewSQLMaskingPolicy("p")
	p.Priority = &prio
	if _, err := c.SQLMaskingPolicies.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[0]; r.Method != "POST" || r.Path != "/api/v1/policies/dbpolicy" || !reflect.DeepEqual(r.Body, Params{"name": "p", "description": "", "priority": float64(100)}) {
		t.Fatalf("%+v", r)
	}
	res, err := c.SQLMaskingPolicies.List(ctx, SearchOptions{Take: 10, Filter: Filters{F("name", FilterEqualsString, "p")}})
	if err != nil || res.TotalCount != 1 {
		t.Fatalf("%v %v", res, err)
	}
	got, err := c.SQLMaskingPolicies.Get(ctx, "p")
	if err != nil || *got.ID != 5 || *got.Priority != 100 {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := c.SQLMaskingPolicies.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	n := len(*reqs)
	if _, err := c.SQLMaskingPolicies.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[n]; r.Method != "PUT" || r.Path != "/api/v1/policies/dbpolicy/5" || r.Body["id"] != float64(5) || r.Body["priority"] != float64(100) {
		t.Fatalf("%+v", r)
	}
	if err := c.SQLMaskingPolicies.GrantTo(ctx, "p", "Bob"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[n+1]; r.Method != "POST" || r.Path != "/api/v1/grantee/bob" || !strings.Contains(string(r.Raw), "POLICY") {
		t.Fatalf("%+v", r)
	}
	if _, err := c.SQLMaskingPolicies.ListColumnRules(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[n+2]; !reflect.DeepEqual(r.Body, Params{"filter": []any{"name", "equals", "p"}}) {
		t.Fatalf("%+v", r)
	}
	el, err := c.SQLMaskingPolicies.AddColumnRule(ctx, "p", "ds.db.s.t", "col1", "masked by full()", "")
	if err != nil || string(el) != `{"status":"OK"}` {
		t.Fatalf("%s %v", el, err)
	}
	want := Params{"table_name": "ds.db.s.t", "column_name": "col1", "projection_expression": "masked by full()", "policy_name": "p", "table_type": "table"}
	if r := (*reqs)[n+3]; r.Method != "PUT" || !reflect.DeepEqual(r.Body, want) {
		t.Fatalf("%+v", r)
	}
	if _, err := c.SQLMaskingPolicies.DeleteColumnRule(ctx, "p", "t", "c", SQLMaskingTableTypeResultset); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[n+4]; r.Body["projection_expression"] != "REVEAL" || r.Body["table_type"] != "resultset" {
		t.Fatalf("%+v", r)
	}
}
