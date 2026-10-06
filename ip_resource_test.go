package mamori

import (
	"context"
	"net/url"
	"testing"
)

func TestIPResource(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Method == "GET" {
			return Params{"data": []Params{{"name": "r", "cidr": "10.0.0.0/24", "ports": "80"}}, "totalCount": 1}
		}
		return Params{"status": "ok"}
	})
	ctx := context.Background()
	r := &IPResource{Name: "r", CIDR: "10.0.0.0/24", Ports: "443,80"}
	if _, err := c.IPResources.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got := (*reqs)[0].Body["resource"].(map[string]any); got["cidr"] != "10.0.0.0/24" || got["ports"] != "443,80" || got["name"] != "r" {
		t.Fatalf("body = %v", got)
	}
	if _, err := c.IPResources.Update(ctx, "r", &IPResource{Name: "r2", CIDR: "c", Ports: "p"}); err != nil {
		t.Fatal(err)
	}
	if u := (*reqs)[1]; u.Method != "PUT" || u.Path != "/api/v1/ip_resources/r" || u.Body["resource"].(map[string]any)["name"] != "r2" {
		t.Fatalf("update = %+v", u)
	}
	if _, err := c.IPResources.Update(ctx, "r", &IPResource{Name: "r"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := (*reqs)[2].Body["resource"].(map[string]any)["name"]; ok {
		t.Fatal("unchanged name must not be sent")
	}
	if _, err := c.IPResources.Delete(ctx, "a.b c"); err != nil {
		t.Fatal(err)
	}
	if d := (*reqs)[3]; d.Method != "DELETE" || d.Path != "/api/v1/ip_resources/a.b%20c" {
		t.Fatalf("delete = %+v", d)
	}

	res, err := c.IPResources.List(ctx, SearchOptions{Take: 100, Filter: Filters{F("name", FilterEquals, "r")}})
	if err != nil || len(res.Data) != 1 || res.Data[0].CIDR != "10.0.0.0/24" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	q, _ := url.QueryUnescape((*reqs)[4].Query)
	if q != "filter[0][]=name&filter[0][]==&filter[0][]=r&skip=0&take=100" {
		t.Fatalf("query = %s", q)
	}
	if _, err := c.IPResources.List(ctx, SearchOptions{Take: 1, Filter: Filters{F("a", FilterEquals, "1"), F("b", FilterEquals, "2")}}); err != nil {
		t.Fatal(err)
	}
	q, _ = url.QueryUnescape((*reqs)[5].Query)
	if q != "filter[0][]=a&filter[0][]==&filter[0][]=1&filter[1][]=b&filter[1][]==&filter[1][]=2&skip=0&take=1" {
		t.Fatalf("query = %s", q)
	}
}
