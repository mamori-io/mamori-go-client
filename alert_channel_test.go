package mamori

import (
	"context"
	"errors"
	"testing"
)

func TestAlertChannelCreateEncodesActions(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any { return Params{"id": 42} })
	a := NewAlertChannel("alerts")
	a.AddEmailAlert("a@b.com", "subj", "line1\nsaid \"hi\" <b>")
	a.AddHTTPAlert(HTTPOperationPost, "", "https://hooks.example.com/x", "{}", "application/json")
	a.AddPushNotificationAlert("{{applicant}}", "Test")
	if _, err := c.AlertChannels.Create(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.Method != "POST" || r.Path != "/api/v1/alerts" {
		t.Fatalf("bad request %s %s", r.Method, r.Path)
	}
	alert := r.Body["alert"].(map[string]any)
	want := `(email "a@b.com" "subj" "line1\nsaid \"hi\" <b>")` +
		`(http "POST" "https://hooks.example.com/x" "e30=" "application/json" "")` +
		`(notification "{{applicant}}" "PushMessage" "Test")`
	if alert["action"] != want || alert["name"] != "alerts" {
		t.Fatalf("action = %v", alert["action"])
	}
	if a.ID != 42 {
		t.Fatalf("id not set: %d", a.ID)
	}
}

func TestAlertChannelListAndGet(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		return []Params{{
			"id":     7,
			"name":   "x",
			"action": `(email "a@b.com" "subj" "l1\nl2")(http "GET" "https://h.example.com:8443/p/q" "" "text/plain" "")(notification "bob" "Message" "m")`,
		}}
	})
	ctx := context.Background()
	ch, err := c.AlertChannels.Get(ctx, "x")
	if err != nil {
		t.Fatal(err)
	}
	if (*reqs)[0].Method != "GET" || (*reqs)[0].Path != "/api/v1/alerts" {
		t.Fatalf("bad request %+v", (*reqs)[0])
	}
	if ch.ID != 7 || len(ch.Actions) != 3 {
		t.Fatalf("bad channel %+v", ch)
	}
	e := ch.Actions[0]
	if e.Name != "EMAIL" || e.Key != 0 || e.EmailParams[2] != "l1\nl2" || len(e.HTTPParams) != 0 || e.HTTPParams == nil {
		t.Fatalf("bad email action %+v", e)
	}
	if ch.Actions[2].Key != 2 || ch.Actions[2].NotificationParams[0] != "bob" {
		t.Fatalf("bad notification action %+v", ch.Actions[2])
	}
	want := "Send email to a@b.com with subject 'subj' then Perform https GET request to h.example.com:8443 at /p/q then Send a notification to bob"
	if ch.Description != want {
		t.Fatalf("description = %q", ch.Description)
	}
	// Actions read back re-encode with the upper-case name.
	enc, err := ch.EncodeActions()
	if err != nil || enc[:len(`(EMAIL "a@b.com"`)] != `(EMAIL "a@b.com"` {
		t.Fatalf("re-encode = %q, %v", enc, err)
	}
	if _, err := c.AlertChannels.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestAlertChannelUpdateDelete(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	a := NewAlertChannel("n")
	a.ID = 3
	a.AddMessageAlert("bob", "hi")
	if _, err := c.AlertChannels.Update(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AlertChannels.Delete(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[0]; r.Method != "PUT" || r.Path != "/api/v1/alerts/3" ||
		r.Body["alert"].(map[string]any)["action"] != `(notification "bob" "Message" "hi")` {
		t.Fatalf("bad update %+v", r)
	}
	if r := (*reqs)[1]; r.Method != "DELETE" || r.Path != "/api/v1/alerts/3" {
		t.Fatalf("bad delete %+v", r)
	}
}
