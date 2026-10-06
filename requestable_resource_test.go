package mamori

import (
	"context"
	"errors"
	"net/url"
	"testing"
)

func TestRequestableResourceListFor(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		return Params{"totalCount": 1, "data": []Params{{"id": 12, "resource_type": "SCRIPT", "resource_name": "s"}}}
	})
	ctx := context.Background()
	q := RequestableResourceQuery{Type: RequestableResourceTypeScript, Grantee: "bob", Resource: "s", Policy: "p"}
	r, err := c.RequestableResources.DeleteByName(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "12" || r.ResourceType != RequestableResourceTypeScript {
		t.Fatalf("bad resource %+v", r)
	}
	list := (*reqs)[0]
	vals, err := url.ParseQuery(list.Query)
	if err != nil {
		t.Fatal(err)
	}
	if list.Method != "GET" || list.Path != "/api/v1/requestable_resources" || vals.Get("take") != "5" {
		t.Fatalf("bad list %+v", list)
	}
	// [[resource_type,equals,SCRIPT],"and",[grantee,...],"and",...,[policy_name,equals,p]]
	if len(vals["filter[]"]) != 3 || vals.Get("filter[]") != "and" || vals["filter[0][]"][2] != "SCRIPT" || vals["filter[6][]"][0] != "policy_name" {
		t.Fatalf("bad filter query %q", list.Query)
	}
	if del := (*reqs)[1]; del.Method != "DELETE" || del.Path != "/api/v1/requestable_resources/12" {
		t.Fatalf("bad delete %+v", del)
	}

	// A single condition is not nested.
	if _, err := c.RequestableResources.ListFor(ctx, 0, 10, RequestableResourceQuery{Grantee: "bob"}); err != nil {
		t.Fatal(err)
	}
	vals, _ = url.ParseQuery((*reqs)[2].Query)
	if got := vals["filter[]"]; len(got) != 3 || got[0] != "grantee" || got[1] != "equals" {
		t.Fatalf("bad single filter %q", (*reqs)[2].Query)
	}
}

func TestRequestableResourceNotFound(t *testing.T) {
	c, _ := newTestClient(t, func(r recordedRequest) any { return Params{"data": []any{}, "totalCount": 0} })
	if _, err := c.RequestableResources.DeleteByName(context.Background(), RequestableResourceQuery{Resource: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestRequestableResourceCreateUpdate(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	r := NewRequestableResource(RequestableResourceTypeSSHLogin)
	r.ResourceName = "login"
	r.Grantee = "bob"
	r.PolicyName = "p"
	if _, err := c.RequestableResources.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
	b := (*reqs)[0].Body
	if (*reqs)[0].Method != "POST" || b["privileges"] != "SSH,SFTP" || b["resource_type"] != "SSH LOGIN" || b["resource_name"] != "login" {
		t.Fatalf("bad create %+v", (*reqs)[0])
	}
	if _, ok := b["id"]; ok {
		t.Fatal("id should not be sent")
	}
	r.ID = "9"
	if _, err := c.RequestableResources.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	if u := (*reqs)[1]; u.Method != "PUT" || u.Path != "/api/v1/requestable_resources/9" || u.Body["privileges"] != "SSH,SFTP" {
		t.Fatalf("bad update %+v", u)
	}
	if RequestableResourceTypeResourceGroup.DefaultPrivileges() != "" || RequestableResourceTypeScriptFlow.DefaultPrivileges() != "EXECUTE SCRIPT FLOW" {
		t.Fatal("bad default privileges")
	}
}
