package mamori

import (
	"context"
	"net/http"
	"net/url"
	"testing"
)

func TestUpdateRoleUsers(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.UpdateRoleUsers(ctx, "r1", []string{"a"}, []string{"b"})
	c.UpdateRoleUsers(ctx, "r1", []string{"a"}, nil)
	c.UpdateRoleUsers(ctx, "r1", nil, []string{"b"})
	r := *reqs
	if r[0].Method != http.MethodPut || r[0].Path != "/api/v1/roles/r1/users" ||
		r[0].Body["selected_users"].([]any)[0] != "b" || r[0].Body["deleted_users"].([]any)[0] != "a" {
		t.Fatalf("both: %+v", r[0])
	}
	q, _ := url.ParseQuery(r[1].Query)
	if r[1].Method != http.MethodDelete || r[1].Path != "/api/v1/roles/r1/users" || q.Get("selected_users[]") != "a" {
		t.Fatalf("deleted only: %+v", r[1])
	}
	if r[2].Method != http.MethodPost || r[2].Path != "/api/v1/roles/r1/users" || r[2].Body["selected_users"].([]any)[0] != "b" {
		t.Fatalf("added only: %+v", r[2])
	}
}

func TestUpdateUserDBCreds(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	del := []any{Params{"system_name": "s1"}}
	add := []any{Params{"system_name": "s2"}}
	c.UpdateUserDBCreds(ctx, "Bob Smith", del, add)
	c.UpdateUserDBCreds(ctx, "bob", del, nil)
	c.UpdateUserDBCreds(ctx, "bob", nil, add)
	r := *reqs
	if r[0].Method != http.MethodPut || r[0].Path != "/api/v1/users/bob%20smith/credentials" ||
		r[0].Body["db_credentials"] == nil || r[0].Body["deleted_credentials"] == nil {
		t.Fatalf("both: %+v", r[0])
	}
	if r[1].Method != http.MethodDelete || r[1].Path != "/api/v1/users/bob/credentials" || r[1].Query == "" {
		t.Fatalf("deleted only: %+v", r[1])
	}
	if r[2].Method != http.MethodPost || r[2].Path != "/api/v1/users/bob/credentials" {
		t.Fatalf("added only: %+v", r[2])
	}
	creds, _ := r[2].Body["db_credentials"].([]any)
	if len(creds) != 1 || creds[0].(map[string]any)["system_name"] != "s2" {
		t.Fatalf("added only body: %+v", r[2].Body)
	}
}

func TestUserPaths(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.User(ctx, "Alice")
	c.UsersExternal(ctx)
	c.SetUserScopedMFA(ctx, "Alice", "totp", []string{"ssh"})
	c.GetGranteePolicies(ctx, "Role A")
	c.EnrollScopedMFA(ctx, "")
	r := *reqs
	if r[0].Path != "/api/v1/users/alice" {
		t.Fatalf("user: %+v", r[0])
	}
	if r[1].Path != "/api/v1/users" || r[1].Query != "external=y" {
		t.Fatalf("external: %+v", r[1])
	}
	// The TS SDK does not lower-case the user name for mfa_apply endpoints.
	if r[2].Method != http.MethodPut || r[2].Path != "/api/v1/users/Alice/mfa_apply" || r[2].Body["provider"] != "totp" {
		t.Fatalf("scoped mfa: %+v", r[2])
	}
	if r[3].Path != "/api/v1/grantee/role%20a/policies" {
		t.Fatalf("grantee policies: %+v", r[3])
	}
	if v, ok := r[4].Body["provider_name"]; !ok || v != "" {
		t.Fatalf("enroll: %+v", r[4])
	}
}
