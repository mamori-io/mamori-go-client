package mamori

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestScriptCreateUpdateDelete(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Path == "/v2/call/CREATE_SCRIPT" {
			return []Params{{"RESULT": "17"}}
		}
		return Params{"success": true}
	})
	ctx := context.Background()
	sc := NewScript("s1", "", "parameters.out.set('x', 1);")
	sc.Parameters = []ScriptParameter{
		{Name: "who", Direction: ScriptParamIn, Type: ScriptParamTypeString, Default: "world"},
		{Name: "x", Direction: ScriptParamOut, Type: ScriptParamTypeNumber},
	}
	if _, err := c.Scripts.Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	if sc.ID != 17 || sc.Language != "text/javascript" {
		t.Fatalf("bad script %+v", sc)
	}
	r := (*reqs)[0]
	args := r.Body["args"].([]any)
	if r.Method != "POST" || len(args) != 6 || args[0] != "s1" || args[1] != "MAMORI" || args[2] != nil || args[5] != nil {
		t.Fatalf("bad create args %v", args)
	}
	var params []map[string]any
	if err := json.Unmarshal([]byte(args[4].(string)), &params); err != nil || len(params) != 2 || params[0]["default"] != "world" {
		t.Fatalf("bad parameters %v %v", args[4], err)
	}
	if _, ok := params[1]["default"]; ok {
		t.Fatal("unset default should be omitted")
	}

	sc.SetTarget(ScriptTargetSQL, "ds1")
	sc.Capabilities = []string{}
	if _, err := c.Scripts.Update(ctx, sc); err != nil {
		t.Fatal(err)
	}
	r = (*reqs)[1]
	args = r.Body["args"].([]any)
	if r.Path != "/v2/call/UPDATE_SCRIPT" || args[0] != float64(17) || args[2] != "SQL" || args[3] != "ds1" || args[6] != "[]" || sc.Language != "text/sql" {
		t.Fatalf("bad update args %v", args)
	}

	if _, err := c.Scripts.Delete(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[2]; r.Path != "/v2/call/DELETE_SCRIPT" || r.Body["args"].([]any)[0] != float64(17) {
		t.Fatalf("bad delete %+v", r)
	}
	if _, err := c.Scripts.Update(ctx, NewScript("x", "", "")); err == nil {
		t.Fatal("update without id should fail")
	}
}

func TestScriptGetByName(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Body["sql"] == "SELECT * FROM SYS.SCRIPTS WHERE lower(name) = lower('o''brien')" {
			return []Params{{
				"ID": 3, "NAME": "o'brien", "TARGET_TYPE": "sql", "TARGET_NAME": "",
				"LANGUAGE": "text/sql", "BODY": "select 1",
				"PARAMETERS":   `[{"name":"n","direction":"out","type":"number"}]`,
				"CAPABILITIES": `["REVEAL SECRET"]`,
			}}
		}
		return []Params{}
	})
	ctx := context.Background()
	sc, err := c.Scripts.GetByName(ctx, "o'brien")
	if err != nil {
		t.Fatal(err)
	}
	if (*reqs)[0].Path != "/api/v1/query" {
		t.Fatalf("bad path %s", (*reqs)[0].Path)
	}
	if sc.ID != 3 || sc.Name != "o'brien" || sc.TargetType != ScriptTargetSQL || sc.TargetName != "" ||
		len(sc.Parameters) != 1 || sc.Parameters[0].Type != ScriptParamTypeNumber || sc.Capabilities[0] != "REVEAL SECRET" {
		t.Fatalf("bad script %+v", sc)
	}
	if _, err := c.Scripts.GetByName(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestScriptRun(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		return Params{"rows": []Params{{"SUCCESS": "true", "RESULT": `{"outs":{"greeting":"hello-sdk"}}`}}}
	})
	res, err := c.Scripts.Run(context.Background(), "s1", map[string]any{"who": "sdk"})
	if err != nil {
		t.Fatal(err)
	}
	args := (*reqs)[0].Body["args"].([]any)
	if (*reqs)[0].Path != "/v2/call/RUN_SCRIPT" || args[0] != "s1" || args[1] != `{"who":"sdk"}` {
		t.Fatalf("bad run args %v", args)
	}
	if !res.Success || res.Outs()["greeting"] != "hello-sdk" || res.Error != nil {
		t.Fatalf("bad result %+v", res)
	}
	if _, err := c.Scripts.Run(context.Background(), "s1", nil); err != nil {
		t.Fatal(err)
	}
	if (*reqs)[1].Body["args"].([]any)[1] != "{}" {
		t.Fatalf("nil inputs should be {}")
	}
}

func TestScriptExtractID(t *testing.T) {
	cases := map[string]int64{
		`5`:                    5,
		`[7]`:                  7,
		`{"data":[{"id":8}]}`:  8,
		`{"rows":[{"x":"9"}]}`: 9,
		`{"result":10}`:        10,
	}
	for in, want := range cases {
		if got, ok := scriptExtractID(json.RawMessage(in)); !ok || got != want {
			t.Errorf("%s: got %d %v", in, got, ok)
		}
	}
	if _, ok := scriptExtractID(json.RawMessage(`{"result":"abc"}`)); ok {
		t.Error("non-numeric id should not be extracted")
	}
}

func TestScriptGrant(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any { return []string{"ok"} })
	if err := c.Scripts.GrantTo(context.Background(), "s1", "Bob"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[0]; r.Method != "POST" || r.Path != "/api/v1/grantee/bob" {
		t.Fatalf("bad grant %+v", r)
	}
}
