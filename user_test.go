package mamori

import (
	"context"
	"reflect"
	"testing"
)

func TestUserCRUD(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Method == "GET" {
			return Params{"email": "a@b.c", "fullname": "Al Ice"}
		}
		return Params{"error": false}
	})
	ctx := context.Background()
	u := &User{Username: "Al.ice x", Email: "a@b.c", FullName: "Al Ice"}
	if _, err := c.Users.Create(ctx, u, "pw"); err != nil {
		t.Fatal(err)
	}
	got, err := c.Users.Get(ctx, "Al.ice x")
	if err != nil {
		t.Fatal(err)
	}
	if *got != *u {
		t.Fatalf("got %+v", got)
	}
	if _, err := c.Users.Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Users.Disable(ctx, u.Username); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Users.Delete(ctx, u.Username); err != nil {
		t.Fatal(err)
	}
	r := *reqs
	if r[0].Method != "POST" || r[0].Path != "/api/v1/users" || r[0].Body["identified_by"] != "password" ||
		r[0].Body["password"] != "pw" || r[0].Body["fullname"] != "Al Ice" {
		t.Errorf("create: %+v", r[0])
	}
	if r[1].Path != "/api/v1/users/al.ice%20x" {
		t.Errorf("get path: %s", r[1].Path)
	}
	if r[2].Method != "PUT" || r[2].Body["email"] != "a@b.c" || len(r[2].Body) != 2 {
		t.Errorf("update: %+v", r[2])
	}
	if r[3].Method != "PUT" || r[3].Path != "/api/v1/users/al.ice%20x/disable" {
		t.Errorf("disable: %+v", r[3])
	}
	if r[4].Method != "DELETE" || r[4].Path != "/api/v1/users/al.ice%20x" {
		t.Errorf("delete: %+v", r[4])
	}
}

func TestUserScopedMFASQL(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	if _, err := c.Users.SetScopedMFA(ctx, "o'neil", MFAProviderPushTOTP); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Users.DeleteScopedMFA(ctx, "bob", MFAApplyPortalOAuth); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Users.ListAuthenticationProviders(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"CALL SYSCS_UTIL.SET_USER_SCOPED_MFA('o''neil', 'pushtotp', 'portal_local_auth,resource_access')",
		"CALL SYSCS_UTIL.DELETE_USER_SCOPED_MFA('bob', 'portal_oauth')",
		"SELECT * FROM SYS.USER_AUTHENTICATION_PROVIDERS WHERE lower(user_name) = lower('bob')",
	}
	for i, w := range want {
		if got := (*reqs)[i].Body["sql"]; got != w {
			t.Errorf("sql %d: got %v want %v", i, got, w)
		}
	}
}

func TestUserMFAHTTP(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	if _, err := c.Users.SetScopedMFAHTTP(ctx, "Bob", MFAProviderTOTP); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Users.DeleteScopedMFAHTTP(ctx, "Bob", MFAApplyPortalOAuth); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Users.SetMFAProvider(ctx, "bob", MFAProviderNone, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Users.SetAsServiceAccount(ctx, "bob", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Users.EnrollScopedMFA(ctx, ""); err != nil {
		t.Fatal(err)
	}
	r := *reqs
	if r[0].Method != "PUT" || r[0].Path != "/api/v1/users/Bob/mfa_apply" || r[0].Body["provider"] != "totp" ||
		!reflect.DeepEqual(r[0].Body["mfa_applies"], []any{"portal_local_auth", "resource_access"}) {
		t.Errorf("set http: %+v", r[0])
	}
	if r[1].Method != "DELETE" || r[1].Path != "/api/v1/users/Bob/mfa_apply" || r[1].Query == "" {
		t.Errorf("delete http: %+v", r[1])
	}
	want := map[string]any{"provider": "none", "options": map[string]any{}}
	if !reflect.DeepEqual(r[2].Body["authenticated_by_primary"], want) {
		t.Errorf("set mfa: %+v", r[2].Body)
	}
	want = map[string]any{"provider": "service", "options": map[string]any{"ALLOWED_IP": "10.0.0.1"}}
	if !reflect.DeepEqual(r[3].Body["authenticated_by_primary"], want) {
		t.Errorf("service account: %+v", r[3].Body)
	}
	if r[4].Method != "POST" || r[4].Path != "/api/v1/my/mfa_apply/enroll" || !reflect.DeepEqual(r[4].Body, Params{"provider_name": ""}) {
		t.Errorf("enroll: %+v", r[4])
	}
}

func TestUserClearMFARequests(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	if err := c.Users.ClearMFARequests(ctx, "bob", ""); err != nil {
		t.Fatal(err)
	}
	if err := c.Users.ClearMFARequests(ctx, "bob", "k/ey="); err != nil {
		t.Fatal(err)
	}
	r := *reqs
	if r[0].Body["sql"] != "CALL CLEAR_AUTHENTICATION_REQUESTS('bob')" {
		t.Errorf("sql: %v", r[0].Body)
	}
	if r[1].Method != "DELETE" || r[1].Path != "/api/v1/wireguard/disconnect_user/bob" {
		t.Errorf("disconnect user: %+v", r[1])
	}
	if r[3].Path != "/api/v1/wireguard/k%2Fey%3D/disconnect" {
		t.Errorf("disconnect peer: %+v", r[3])
	}
}

func TestUserGrantedRolesAndDirectory(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Path == "/api/v1/roles" {
			return Params{"rows": []any{[]any{"u", "r"}}}
		}
		return Params{"data": []any{Params{"username": "x"}}, "totalCount": 1}
	})
	ctx := context.Background()
	rows, err := c.Users.GetAllGrantedRoles(ctx, "Bob")
	if err != nil || string(rows) != `[["u","r"]]` {
		t.Fatalf("rows %s err %v", rows, err)
	}
	res, err := c.Users.ListDirectoryUsers(ctx, SearchOptions{Skip: 0, Take: 10, Filter: Filters{F("username", FilterEquals, "x")}})
	if err != nil || res.TotalCount != 1 {
		t.Fatalf("list: %+v %v", res, err)
	}
	if _, err := c.Users.CreateDirectoryUser(ctx, &DirectoryUser{Provider: "ldap", Username: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Users.DeleteDirectoryUser(ctx, "X"); err != nil {
		t.Fatal(err)
	}
	r := *reqs
	if r[0].Query != "recursive=Y&grantee=bob" {
		t.Errorf("roles query: %s", r[0].Query)
	}
	if r[1].Method != "PUT" || r[1].Path != "/api/v1/search/directory_users" || r[1].Body["take"] != float64(10) || r[1].Body["filter"] == nil {
		t.Errorf("dir search: %+v", r[1])
	}
	if r[2].Body["provider"] != "ldap" || r[2].Path != "/api/v1/directory_users" {
		t.Errorf("dir create: %+v", r[2])
	}
	if r[3].Method != "DELETE" || r[3].Path != "/api/v1/users/x/external" {
		t.Errorf("dir delete: %+v", r[3])
	}
}

func TestUserPasswordProcedures(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	if _, err := c.Users.ExportPassword(ctx, "bob", "key"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Users.RestorePassword(ctx, "bob", "blob", "key"); err != nil {
		t.Fatal(err)
	}
	r := *reqs
	if r[0].Path != "/v2/call/EXPORT_USER_PASSWORD_EX" || !reflect.DeepEqual(r[0].Body["args"], []any{"bob", "key"}) {
		t.Errorf("export: %+v", r[0])
	}
	if r[1].Path != "/v2/call/RESTORE_USER_PASSWORD_EX" || !reflect.DeepEqual(r[1].Body["args"], []any{"bob", "blob", "key"}) {
		t.Errorf("restore: %+v", r[1])
	}
}
