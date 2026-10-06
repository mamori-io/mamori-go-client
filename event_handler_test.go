package mamori

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
)

func TestEventHandlerCRUD(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Method == "GET" {
			return Params{"totalCount": 2, "data": []Params{
				{"id": 1, "name": "h", "type": "rule", "body": "x", "capabilities": nil},
				{"id": 2, "name": "h", "type": "trigger", "body": "y", "capabilities": `["REVEAL SECRET"]`},
			}}
		}
		return Params{"success": true}
	})
	ctx := context.Background()
	h := NewEventHandler("h", EventHandlerTypeTrigger, "body")
	h.Capabilities = []string{}
	if _, err := c.EventHandlers.Create(ctx, h); err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.Method != "POST" || r.Path != "/api/v1/event_handlers" || r.Body["id"] != "" ||
		r.Body["language"] != "text/javascript" || len(r.Body["capabilities"].([]any)) != 0 {
		t.Fatalf("bad create %+v", r)
	}

	got, err := c.EventHandlers.GetByName(ctx, "h", EventHandlerTypeTrigger)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 2 || len(got.Capabilities) != 1 || got.Capabilities[0] != "REVEAL SECRET" {
		t.Fatalf("bad handler %+v", got)
	}
	q, _ := url.ParseQuery((*reqs)[1].Query)
	if q.Get("skip") != "0" || q.Get("take") != "500" {
		t.Fatalf("bad list query %q", (*reqs)[1].Query)
	}
	untyped, err := c.EventHandlers.GetByName(ctx, "h", "")
	if err != nil || untyped.ID != 1 || untyped.Capabilities != nil {
		t.Fatalf("bad untyped lookup %+v %v", untyped, err)
	}
	if _, err := c.EventHandlers.GetByName(ctx, "zz", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	// Delete without an id looks the handler up first.
	n := len(*reqs)
	if _, err := c.EventHandlers.Delete(ctx, NewEventHandler("h", EventHandlerTypeTrigger, "")); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[n+1]; r.Method != "DELETE" || r.Path != "/api/v1/event_handlers/2" {
		t.Fatalf("bad delete %+v", r)
	}

	got.Body = "new"
	got.Capabilities = nil
	if _, err := c.EventHandlers.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	r = (*reqs)[len(*reqs)-1]
	if r.Method != "PUT" || r.Path != "/api/v1/event_handlers/2" || r.Body["id"] != float64(2) || r.Body["body"] != "new" {
		t.Fatalf("bad update %+v", r)
	}
	if _, ok := r.Body["capabilities"]; ok {
		t.Fatal("nil capabilities should be omitted")
	}

	if _, err := c.EventHandlers.Test(ctx, got, Params{"a": 1}); err != nil {
		t.Fatal(err)
	}
	r = (*reqs)[len(*reqs)-1]
	if r.Path != "/api/v1/event_handlers/test" || r.Body["body"] != "new" || r.Body["type"] != "trigger" ||
		r.Body["payload"].(map[string]any)["a"] != float64(1) {
		t.Fatalf("bad test request %+v", r)
	}
}

func TestEventHandlerListArray(t *testing.T) {
	c, _ := newTestClient(t, func(r recordedRequest) any {
		return json.RawMessage(`[{"id":5,"name":"a","type":"rule","capabilities":["x",1]}]`)
	})
	res, err := c.EventHandlers.List(context.Background(), SearchOptions{Take: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalCount != 1 || res.Data[0].ID != 5 || res.Data[0].Capabilities[1] != "1" || res.Data[0].Language != "text/javascript" {
		t.Fatalf("bad list %+v", res)
	}
}
