package mamori

import (
	"context"
	"net/url"
	"testing"
)

func TestUpdateUserRolesBranches(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.UpdateUserRoles(ctx, "Bob Smith", []string{"r1"}, []string{"r2"})
	c.UpdateUserRoles(ctx, "bob", []string{"r1"}, nil)
	c.UpdateUserRoles(ctx, "bob", nil, []string{"r2"})
	raw, err := c.UpdateUserRoles(ctx, "bob", nil, nil)
	if raw != nil || err != nil {
		t.Fatalf("no-op update returned %s, %v", raw, err)
	}
	r := *reqs
	if len(r) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(r))
	}
	if r[0].Method != "PUT" || r[0].Path != "/api/v1/users/bob%20smith/roles" {
		t.Errorf("both: %+v", r[0])
	}
	if a, _ := r[0].Body["selected_roles"].([]any); len(a) != 1 || a[0] != "r2" {
		t.Errorf("both selected: %+v", r[0].Body)
	}
	if d, _ := r[0].Body["deleted_roles"].([]any); len(d) != 1 || d[0] != "r1" {
		t.Errorf("both deleted: %+v", r[0].Body)
	}
	if q, _ := url.QueryUnescape(r[1].Query); r[1].Method != "DELETE" || q != "selected_roles[]=r1" {
		t.Errorf("revoke: %+v", r[1])
	}
	if r[2].Method != "POST" || r[2].Path != "/api/v1/users/bob/roles" {
		t.Errorf("grant: %+v", r[2])
	}
}

func TestUpdateRoleCredentialsBranches(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.UpdateRoleCredentials(ctx, "r", []string{"a"}, []string{"b"})
	c.UpdateRoleCredentials(ctx, "r", []string{"a"}, []string{})
	c.UpdateRoleCredentials(ctx, "r", nil, []string{"b"})
	c.UpdateRoleCredentials(ctx, "r", nil, nil)
	r := *reqs
	if len(r) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(r))
	}
	if r[0].Method != "PUT" || r[0].Path != "/api/v1/roles/r/credentials" || r[0].Body["db_credentials"] == nil || r[0].Body["deleted_credentials"] == nil {
		t.Errorf("both: %+v", r[0])
	}
	if q, _ := url.QueryUnescape(r[1].Query); r[1].Method != "DELETE" || q != "db_credentials[]=a" {
		t.Errorf("drop: %+v", r[1])
	}
	if r[2].Method != "POST" || r[2].Body["db_credentials"] == nil {
		t.Errorf("add: %+v", r[2])
	}
}

func TestUpdateGlobalAndObjectPermission(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.UpdateGlobalPermission(ctx, "r", []string{"a"}, []string{"b"})
	c.UpdateGlobalPermission(ctx, "r", []string{"a"}, nil)
	c.UpdateGlobalPermission(ctx, "r", nil, []string{"b"})
	c.UpdateGlobalPermission(ctx, "r", nil, nil)
	c.UpdateObjectPermission(ctx, "r", []string{"a"}, []string{"b"})
	c.UpdateObjectPermission(ctx, "r", []string{"a"}, nil)
	c.UpdateObjectPermission(ctx, "r", nil, []string{"b"})
	r := *reqs
	if len(r) != 6 {
		t.Fatalf("expected 6 requests, got %d", len(r))
	}
	check := func(i int, method, path, key, query string) {
		t.Helper()
		if r[i].Method != method || r[i].Path != path {
			t.Errorf("%d: %+v", i, r[i])
		}
		if query != "" {
			if q, _ := url.QueryUnescape(r[i].Query); q != query {
				t.Errorf("%d: query %q want %q", i, q, query)
			}
		} else if r[i].Body[key] == nil {
			t.Errorf("%d: missing %s in %+v", i, key, r[i].Body)
		}
	}
	check(0, "PUT", "/api/v1/roles/r/global/permissions", "selected_permission", "")
	if r[0].Body["deleted_permission"] == nil {
		t.Errorf("missing deleted_permission")
	}
	check(1, "DELETE", "/api/v1/roles/r/grant/global/permissions", "", "deleted_permission[]=a")
	check(2, "POST", "/api/v1/roles/r/grant/global/permissions", "selected_permissions_cirro", "")
	check(3, "PUT", "/api/v1/roles/r/object/permissions", "selected_permissions_object", "")
	check(4, "DELETE", "/api/v1/roles/r/grant/object/permissions", "", "deleted_permission_object[]=a")
	check(5, "POST", "/api/v1/roles/r/grant/object/permissions", "selected_permissions_object", "")
}

func TestGrantToRevokeFrom(t *testing.T) {
	ok := true
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if ok {
			return []string{"ok"}
		}
		return []string{"error", "no such role"}
	})
	ctx := context.Background()
	res, err := c.GrantTo(ctx, "Some User", []string{"r1"}, "", true, Params{"valid_until": "2030"})
	if err != nil || len(res.Result) != 1 {
		t.Fatalf("grant: %v %v", res, err)
	}
	r := (*reqs)[0]
	if r.Method != "POST" || r.Path != "/api/v1/grantee/some%20user" || r.Body["with_grant_option"] != true || r.Body["valid_until"] != "2030" {
		t.Errorf("grant request: %+v", r)
	}
	if _, has := r.Body["object_name"]; has {
		t.Errorf("object_name should be omitted")
	}

	ok = false
	res, err = c.RevokeFrom(ctx, "U", []string{"SELECT"}, "ds.db.t", nil)
	if err == nil || res == nil || res.Result[1] != "no such role" {
		t.Fatalf("revoke should fail: %v %v", res, err)
	}
	r = (*reqs)[1]
	if q, _ := url.QueryUnescape(r.Query); r.Method != "DELETE" || r.Path != "/api/v1/grantee/u" || q != "grantables[]=SELECT&object_name=ds.db.t" {
		t.Errorf("revoke request: %+v", r)
	}
}

func TestPermissionsQueries(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.ListPermissions(ctx, nil)
	c.ListPermissions(ctx, []string{"a", "b"})
	c.ListPermissionsFiltered(ctx, nil, "GLOBAL")
	c.PermissionsByRole(ctx, "r", []string{"x"})
	c.UserRoles(ctx, "Bob@X")
	c.UsersRolesRecursive(ctx, []string{"a", "b"})
	c.GranteeObjectGrants(ctx, "g", "SELECT", "o")
	want := []string{
		"",
		"scope[]=a&scope[]=b",
		"permissiontype=GLOBAL",
		"scope[]=x",
		"isdef=N&grantee=bob@x",
		"recursive=Y&grantee[]=a&grantee[]=b",
		"object_name=o&permission=SELECT",
	}
	for i, w := range want {
		if q, _ := url.QueryUnescape((*reqs)[i].Query); q != w {
			t.Errorf("%d: query %q want %q", i, q, w)
		}
	}
	if (*reqs)[4].Query != "isdef=N&grantee=bob%40x" {
		t.Errorf("grantee not escaped: %s", (*reqs)[4].Query)
	}
}
