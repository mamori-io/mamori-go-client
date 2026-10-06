package mamori

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestScriptFlowCreate(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any { return []any{21} })
	ctx := context.Background()
	f := NewScriptFlow("flow",
		ScriptFlowStepDef{ID: "b1", Script: "s1", Mappings: map[string]any{}},
		ScriptFlowStepDef{
			ID: "loop", Type: ScriptFlowStepLoop, Name: "each", Mode: ScriptFlowModeSerial,
			Mappings: map[string]any{"input": ScriptFlowMappingSpec{From: "b1", Name: "users"}},
			Steps:    []ScriptFlowStepDef{{ID: "c", Script: "s3"}},
		},
	)
	if _, err := c.ScriptFlows.Create(ctx, f); err != nil {
		t.Fatal(err)
	}
	if f.ID != 21 {
		t.Fatalf("id not set: %d", f.ID)
	}
	r := (*reqs)[0]
	args := r.Body["args"].([]any)
	if r.Path != "/v2/call/CREATE_SCRIPT_FLOW" || len(args) != 4 || args[0] != "flow" || args[2] != nil || args[3] != "[]" {
		t.Fatalf("bad create args %v", args)
	}
	want := `[{"id":"b1","script":"s1","mappings":{}},` +
		`{"id":"loop","type":"loop","name":"each","mode":"serial","steps":[{"id":"c","script":"s3"}],"mappings":{"input":{"from":"b1","name":"users"}}}]`
	var got, exp any
	json.Unmarshal([]byte(args[1].(string)), &got)
	json.Unmarshal([]byte(want), &exp)
	gb, _ := json.Marshal(got)
	eb, _ := json.Marshal(exp)
	if string(gb) != string(eb) {
		t.Fatalf("steps =\n%s\nwant\n%s", args[1], want)
	}

	if _, err := c.ScriptFlows.Update(ctx, f); err != nil {
		t.Fatal(err)
	}
	args = (*reqs)[1].Body["args"].([]any)
	if (*reqs)[1].Path != "/v2/call/UPDATE_SCRIPT_FLOW" || args[0] != float64(21) || args[1] != "flow" || len(args) != 5 {
		t.Fatalf("bad update args %v", args)
	}
	if _, err := c.ScriptFlows.Delete(ctx, 0); err == nil {
		t.Fatal("delete without id should fail")
	}
}

func TestScriptFlowGetByName(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		switch r.Body["sql"] {
		case "SELECT * FROM SYS.SCRIPT_FLOWS WHERE lower(name) = lower('flow')":
			return []Params{{"id": "4", "name": "flow"}}
		case "SELECT * FROM SYS.SCRIPT_FLOW_STEPS WHERE flow_id = 4 ORDER BY position":
			return []Params{
				{"SCRIPT_NAME": "s1", "INPUT_MAPPINGS": ""},
				{"SCRIPT_NAME": "s2", "INPUT_MAPPINGS": `{"ticket":{"from":"b1","name":"ticket"}}`},
			}
		}
		return []Params{}
	})
	ctx := context.Background()
	f, err := c.ScriptFlows.GetByName(ctx, "flow")
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != 4 || len(f.Steps) != 2 || f.Steps[0].Script != "s1" || len(f.Steps[0].Mappings) != 0 {
		t.Fatalf("bad flow %+v", f)
	}
	m := f.Steps[1].Mappings["ticket"].(map[string]any)
	if m["from"] != "b1" {
		t.Fatalf("bad mappings %+v", f.Steps[1].Mappings)
	}
	if len(*reqs) != 2 {
		t.Fatalf("expected 2 queries, got %d", len(*reqs))
	}
	if _, err := c.ScriptFlows.GetByName(ctx, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestScriptFlowRun(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		return []Params{{"success": false, "error": "boom"}}
	})
	res, err := c.ScriptFlows.Run(context.Background(), "flow", map[string]any{"ticket_id": "TK-1"})
	if err != nil {
		t.Fatal(err)
	}
	if (*reqs)[0].Path != "/v2/call/RUN_SCRIPT_FLOW" || res.Success || res.Error != "boom" {
		t.Fatalf("bad run %+v", res)
	}
}
