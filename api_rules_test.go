package mamori

import (
	"context"
	"testing"
)

func TestAccessRuleRequests(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	h := "handler1"
	c.CreateAccessRule(ctx, "block", "x = 1", 2, "none", "desc", true, nil)
	c.UpdateAccessRule(ctx, 9, "block", Params{"a": 1}, 3, "none", "desc", false, &h)
	filter := Params{"type": "block"}
	c.GetCurrentAccessRules(ctx, filter)
	c.GetCurrentAccessRules(ctx, nil)
	r := *reqs
	if r[0].Method != "POST" || r[0].Path != "/api/v1/access_rules" || r[0].Body["clause"] != "x = 1" || r[0].Body["position"] != float64(2) {
		t.Errorf("create: %+v", r[0])
	}
	if _, ok := r[0].Body["event_handler"]; ok {
		t.Errorf("create should omit event_handler: %+v", r[0].Body)
	}
	if _, ok := r[0].Body["id"]; ok {
		t.Errorf("create should omit id")
	}
	if r[1].Method != "PUT" || r[1].Path != "/api/v1/access_rules/9" || r[1].Body["id"] != float64(9) || r[1].Body["event_handler"] != "handler1" || r[1].Body["enabled"] != false {
		t.Errorf("update: %+v", r[1])
	}
	if r[2].Method != "GET" || r[2].Query != "current=Y&type=block" {
		t.Errorf("current rules: %+v", r[2])
	}
	if _, ok := filter["current"]; ok {
		t.Errorf("filter mutated")
	}
	if r[3].Query != "current=Y" {
		t.Errorf("current rules nil filter: %+v", r[3])
	}
}

func TestMaskingAndRestrictedColumns(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.DeleteMaskingProcedure(ctx, 3, "mask")
	c.DropRestrictedColumn(ctx, "rms", "col")
	r := *reqs
	if r[0].Method != "DELETE" || r[0].Path != "/api/v1/maskingprocedures/1" || r[0].Query != "name=mask&rmsid=3" {
		t.Errorf("delete masking: %+v", r[0])
	}
	if r[1].Method != "DELETE" || r[1].Path != "/api/v1/restricted_columns/1" || r[1].Query != "column_name=col&rms_name=rms" {
		t.Errorf("drop restricted: %+v", r[1])
	}
}
