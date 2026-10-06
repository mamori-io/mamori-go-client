package mamori

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestHTTPResourceSetURL(t *testing.T) {
	var r HTTPResource
	r.SetURL("https://localhost/login")
	if r.Host != "localhost" || r.Port != 443 {
		t.Fatalf("%+v", r)
	}
	r.SetURL("http://example.com:8080/x")
	if r.Host != "example.com" || r.Port != 8080 {
		t.Fatalf("%+v", r)
	}
	r.SetURL("http://example.com")
	if r.Port != 80 {
		t.Fatalf("%+v", r)
	}
}

func TestHTTPResourceSQL(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Path == "/api/v1/search/web_resources" {
			return Params{"data": []Params{}, "totalCount": 0}
		}
		return []Params{{"status": "ok"}}
	})
	ctx := context.Background()
	r := &HTTPResource{Name: "web", Description: "it's", RecordSession: true}
	r.SetURL("https://localhost/login")
	if _, err := c.HTTPResources.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	want := "call add_http_resource('web', 'localhost', 443, 'https://localhost/login', 'it''s',false, true)"
	if got := (*reqs)[0].Body["sql"]; got != want {
		t.Fatalf("sql = %v\nwant  %v", got, want)
	}
	r.ID = "17"
	if _, err := c.HTTPResources.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	want = "call update_http_resource(17, 'web', 'localhost', 443, 'https://localhost/login', 'it''s',false, true)"
	if got := (*reqs)[1].Body["sql"]; got != want {
		t.Fatalf("sql = %v", got)
	}
	if _, err := c.HTTPResources.Delete(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if got := (*reqs)[2].Body["sql"]; got != "call delete_http_resource('web')" {
		t.Fatalf("sql = %v", got)
	}
	if _, err := c.HTTPResources.GetByName(ctx, "web"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if q := (*reqs)[3]; q.Method != "PUT" || q.Body["take"] != float64(5) {
		t.Fatalf("search = %+v", q)
	}
}

func TestHTTPResourceDecode(t *testing.T) {
	var r HTTPResource
	if err := json.Unmarshal([]byte(`{"id":5,"name":"n","port":"*","exclude_from_pac":"true"}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.ID != "5" || r.Port != 0 || !r.ExcludeFromPAC {
		t.Fatalf("%+v", r)
	}
}
