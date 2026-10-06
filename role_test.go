package mamori

import (
	"context"
	"net/url"
	"reflect"
	"testing"
)

func TestRoleCRUD(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Path == "/api/v1/roles/r1/dependencies" {
			return Params{"grantees": []string{"bob"}, "jobs": []string{}}
		}
		return Params{"error": false}
	})
	ctx := context.Background()
	role := NewRole("r1")
	role.Position = "5"
	if _, err := c.Roles.Create(ctx, role); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Roles.Update(ctx, role); err != nil {
		t.Fatal(err)
	}
	deps, err := c.Roles.Dependencies(ctx, "r1")
	if err != nil || !reflect.DeepEqual(deps.Grantees, []string{"bob"}) {
		t.Fatalf("deps %+v %v", deps, err)
	}
	if _, err := c.Roles.Delete(ctx, "r 1", true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Roles.GetAll(ctx); err != nil {
		t.Fatal(err)
	}
	r := *reqs
	want := Params{"roleid": "r1", "externalname": "", "position": "5"}
	if r[0].Method != "POST" || r[0].Path != "/api/v1/roles" || !reflect.DeepEqual(r[0].Body, want) {
		t.Errorf("create: %+v", r[0])
	}
	if r[1].Method != "PUT" || r[1].Path != "/api/v1/roles/r1" {
		t.Errorf("update: %+v", r[1])
	}
	if r[3].Method != "DELETE" || r[3].Path != "/api/v1/roles/r%201" || r[3].Query != "cascade=true" {
		t.Errorf("delete: %+v", r[3])
	}
	if r[4].Path != "/api/v1/query" || r[4].Body["sql"] == nil {
		t.Errorf("getall: %+v", r[4])
	}
}

func TestRoleGrantRevoke(t *testing.T) {
	ok := true
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if ok {
			return []string{"ok"}
		}
		return []string{"error: nope"}
	})
	ctx := context.Background()
	if _, err := c.Roles.GrantTo(ctx, "r1", "Bob", false, RoleOptionValidFor(Minutes, 30)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Roles.RevokeFrom(ctx, "r1", "Bob", nil); err != nil {
		t.Fatal(err)
	}
	ok = false
	if _, err := c.Roles.Grant(ctx, "r1", []string{"SELECT"}, "ds.db.s.t", true, nil); err == nil {
		t.Fatal("expected error")
	}
	r := *reqs
	want := Params{"grantables": []any{"r1"}, "object_name": nil, "with_grant_option": false, "valid_unit": "minutes", "valid_duration": float64(30)}
	if r[0].Method != "POST" || r[0].Path != "/api/v1/grantee/bob" || !reflect.DeepEqual(r[0].Body, want) {
		t.Errorf("grantTo: %+v", r[0])
	}
	q, _ := url.ParseQuery(r[1].Query)
	if r[1].Method != "DELETE" || r[1].Path != "/api/v1/grantee/bob" || q.Get("grantables[]") != "r1" || q.Has("object_name") {
		t.Errorf("revokeFrom: %+v", r[1])
	}
	if r[2].Path != "/api/v1/grantee/r1" || r[2].Body["object_name"] != "ds.db.s.t" || r[2].Body["with_grant_option"] != true {
		t.Errorf("grant: %+v", r[2])
	}
}

func TestRoleGrantees(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		return []Params{{"roleid": "r1", "grantee": "bob", "type": "user"}}
	})
	ctx := context.Background()
	rows, err := c.Roles.GetGrantees(ctx, "R1")
	if err != nil || len(rows) != 1 || rows[0]["type"] != "user" {
		t.Fatalf("%v %v", rows, err)
	}
	if _, err := c.Roles.GetAllGrantedRoles(ctx, "R1"); err != nil {
		t.Fatal(err)
	}
	r := *reqs
	if r[0].Path != "/api/v1/roles/r1/granted" || r[1].Path != "/api/v1/roles/r1/grantee" || r[1].Query != "recursive=Y" {
		t.Errorf("paths: %+v", r)
	}
}
