package mamori

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

// permissionJSON normalizes v through JSON so typed values compare equal to
// their decoded form.
func permissionJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPermissionGrantOptions(t *testing.T) {
	cascade := true
	noCascade := false

	withValidity := NewSecretPermission("s1", "bob")
	withValidity.Validity = ValidFor(60, Minutes)
	withValidity.WithGrantOption = true

	between := NewRolePermission("r1", "bob")
	between.Validity = ValidBetweenTimes("2022-01-01 00:00", "2022-01-15 00:00")
	between.Cascade = &cascade

	from := NewKeyPermission("k1", "bob")
	from.Validity = ValidFromTime("2022-01-01 00:00")
	from.Cascade = &noCascade

	until := NewMamoriPermission("bob", MamoriPrivilegeViewAllUserLogs)
	until.Validity = ValidUntilTime("2030-01-01 00:00")

	dsAll := NewDatasourcePermission("bob", DBPermissionSelect).On("*", "*", "*", "*")
	dsPart := NewDatasourcePermission("bob", DBPermissionSelect, DBPermissionMasked).On("ss", "*", "dev", "")
	dsPart.Where = "id > 1"
	dsPart.WithRowLimit(10)
	dsUnl := NewDatasourcePermission("bob", DBPermissionCreateSchema).On("*", "", "", "").WithUnlimitedRows()

	ip := NewIPResourcePermission("net1", "bob")
	ipU := NewIPResourcePermission("net1", "bob")
	ipU.Unauthenticated = true

	cred := NewCredentialPermission("bob")
	cred.Datasource = "pg"
	cred.LoginName = "dbuser"
	credDS := NewCredentialPermission("bob")
	credDS.Datasource = "pg"

	tests := []struct {
		name string
		p    Permission
		want Params
	}{
		{"datasource all", dsAll, Params{"grantables": []any{"SELECT"}, "object_name": "*.*.*.*"}},
		{"datasource partial", dsPart, Params{"grantables": []any{"SELECT", "MASKED PASSTHROUGH"}, "object_name": `"ss".*."dev"`, "where_clause": "id > 1", "limit": "10"}},
		{"datasource unlimited", dsUnl, Params{"grantables": []any{"CREATE SCHEMA"}, "object_name": "*", "limit": "none"}},
		{"datasource empty", &DatasourcePermission{}, Params{"grantables": []any{}, "object_name": ""}},
		{"policy", NewPolicyPermission("p1", "bob"), Params{"grantables": []any{` POLICY "p1"`}}},
		{"policy empty", &PolicyPermission{}, Params{"grantables": []any{}}},
		{"key from", from, Params{"grantables": []any{"KEY USAGE"}, "object_name": "k1", "valid_from": "2022-01-01 00:00", "cascade": "false"}},
		{"key empty", &KeyPermission{}, Params{"grantables": []any{}, "object_name": ""}},
		{"role between", between, Params{"grantables": []any{"r1"}, "valid_from": "2022-01-01 00:00", "valid_until": "2022-01-15 00:00", "cascade": "true"}},
		{"ssh", NewSSHLoginPermission("l1", "bob"), Params{"grantables": []any{"SSH"}, "object_name": "l1"}},
		{"sftp", NewSFTPLoginPermission("l1", "bob"), Params{"grantables": []any{"SFTP"}, "object_name": "l1"}},
		{"rdp", NewRemoteDesktopLoginPermission("rd", "bob"), Params{"grantables": []any{"RDP"}, "object_name": "rd"}},
		{"ip", ip, Params{"grantables": []any{"IP USAGE"}, "object_name": `"net1"`}},
		{"ip unauthenticated", ipU, Params{"grantables": []any{"UNAUTHENTICATED IP USAGE"}, "object_name": `"net1"`}},
		{"mamori until", until, Params{"grantables": []any{"VIEW ALL USER LOGS"}, "valid_until": "2030-01-01 00:00"}},
		{"mamori empty", &MamoriPermission{}, Params{"grantables": []any{}}},
		{"secret valid for", withValidity, Params{"grantables": []any{"REVEAL SECRET"}, "object_name": `"s1"`, "valid_duration": float64(60), "valid_unit": "minutes", "with_grant_option": "true"}},
		{"http", NewHTTPResourcePermission("h1", "bob"), Params{"grantables": []any{"HTTP ACCESS"}, "object_name": `"h1"`}},
		{"credential login", cred, Params{"grantables": []any{"CREDENTIAL USAGE"}, "object_name": `"dbuser@pg"`}},
		{"credential datasource", credDS, Params{"grantables": []any{"CREDENTIAL USAGE"}, "object_name": "pg"}},
		{"script", NewScriptPermission("sc", "bob"), Params{"grantables": []any{"EXECUTE SCRIPT"}, "object_name": `"sc"`}},
		{"script flow", NewScriptFlowPermission("fl", "bob"), Params{"grantables": []any{"EXECUTE SCRIPT FLOW"}, "object_name": `"fl"`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := permissionJSON(t, tt.p.GrantOptions())
			want := permissionJSON(t, tt.want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("GrantOptions() = %#v\nwant %#v", got, want)
			}
		})
	}
}

func TestPermissionFromRecord(t *testing.T) {
	tests := []struct {
		name string
		rec  Params
		want Permission
	}{
		{"ssh", Params{"permissiontype": "SSH", "grantee": "bob", "key_name": "l1"}, NewSSHLoginPermission("l1", "bob")},
		{"sftp", Params{"permissiontype": "SFTP", "grantee": "bob", "key_name": "l1"}, NewSFTPLoginPermission("l1", "bob")},
		{"ip", Params{"permissiontype": "IP USAGE", "grantee": "bob", "key_name": "n"}, NewIPResourcePermission("n", "bob")},
		{"ip unauth", Params{"permissiontype": "UNAUTHENTICATED IP USAGE", "grantee": "bob", "key_name": "n"},
			&IPResourcePermission{PermissionBase: PermissionBase{Grantee: "bob"}, Name: "n", Unauthenticated: true}},
		{"rdp", Params{"permissiontype": "RDP", "grantee": "bob", "key_name": "rd"}, NewRemoteDesktopLoginPermission("rd", "bob")},
		{"key", Params{"permissiontype": "KEY USAGE", "grantee": "bob", "key_name": "k"}, NewKeyPermission("k", "bob")},
		{"credential", Params{"permissiontype": "CREDENTIAL USAGE", "grantee": "bob", "key_name": "u", "onsystem": "pg"},
			&CredentialPermission{PermissionBase: PermissionBase{Grantee: "bob"}, Datasource: "pg", LoginName: "u"}},
		{"secret", Params{"permissiontype": "REVEAL SECRET", "grantee": "bob", "key_name": "s"}, NewSecretPermission("s", "bob")},
		{"http", Params{"permissiontype": "HTTP ACCESS", "grantee": "bob", "key_name": "h"}, NewHTTPResourcePermission("h", "bob")},
		{"script", Params{"permissiontype": "EXECUTE SCRIPT", "grantee": "bob", "key_name": "sc"}, NewScriptPermission("sc", "bob")},
		{"script flow", Params{"permissiontype": "EXECUTE SCRIPT FLOW", "grantee": "bob", "key_name": "f"}, NewScriptFlowPermission("f", "bob")},
		{"datasource", Params{"permissiontype": "SELECT", "grantee": "bob", "id": 3.0}, NewDatasourcePermission("bob", DBPermissionSelect)},
		{"datasource fields", Params{"permissiontype": "SELECT", "grantee": "bob", "permissions": "SELECT,INSERT", "datasource": "*", "database": "*", "schema": "s", "object": "o"},
			NewDatasourcePermission("bob", DBPermissionSelect, DBPermissionInsert).On("*", "*", "s", "o")},
		{"mamori", Params{"permissiontype": "VIEW ALL USER LOGS", "grantee": "bob"}, NewMamoriPermission("bob", MamoriPrivilegeViewAllUserLogs)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PermissionFromRecord(tt.rec)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PermissionFromRecord() = %#v\nwant %#v", got, tt.want)
			}
			// Round trip: the rebuilt permission produces the same request.
			if g, w := permissionJSON(t, got.GrantOptions()), permissionJSON(t, tt.want.GrantOptions()); !reflect.DeepEqual(g, w) {
				t.Errorf("GrantOptions() = %v, want %v", g, w)
			}
		})
	}

	if _, err := PermissionFromRecord(Params{"permissiontype": "UNKNOWN THING"}); err == nil {
		t.Error("expected error for unsupported type")
	}
	if _, err := PermissionFromRecord(Params{}); err == nil {
		t.Error("expected error for missing type")
	}
}

func TestNewPermission(t *testing.T) {
	types := map[PermissionType]Permission{
		PermissionTypeDatasource:    &DatasourcePermission{},
		PermissionTypeIPResource:    &IPResourcePermission{},
		PermissionTypeKey:           &KeyPermission{},
		PermissionTypeMamori:        &MamoriPermission{},
		PermissionTypePolicy:        &PolicyPermission{},
		PermissionTypeRemoteDesktop: &RemoteDesktopLoginPermission{},
		PermissionTypeRole:          &RolePermission{},
		PermissionTypeSSH:           &SSHLoginPermission{},
		PermissionTypeHTTPResource:  &HTTPResourcePermission{},
		PermissionTypeSecret:        &SecretPermission{},
		PermissionTypeCredential:    &CredentialPermission{},
		PermissionTypeScript:        &ScriptPermission{},
		PermissionTypeScriptFlow:    &ScriptFlowPermission{},
	}
	for typ, want := range types {
		got, err := NewPermission(typ)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if reflect.TypeOf(got) != reflect.TypeOf(want) {
			t.Errorf("%s: got %T want %T", typ, got, want)
		}
	}
	if _, err := NewPermission("bogus"); err == nil {
		t.Error("expected error for unknown type")
	}
}

func TestPermissionGrantRequest(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any { return []string{"ok"} })
	p := NewDatasourcePermission("Some User", DBPermissionSelect).On("*", "*", "*", "*")
	p.Validity = ValidFor(60, Minutes)
	res, err := c.Permissions.Grant(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Result, []string{"ok"}) {
		t.Errorf("result = %v", res.Result)
	}
	r := (*reqs)[len(*reqs)-1]
	if r.Method != "POST" || r.Path != "/api/v1/grantee/some%20user" {
		t.Errorf("request = %s %s", r.Method, r.Path)
	}
	want := permissionJSON(t, Params{"grantables": []string{"SELECT"}, "object_name": "*.*.*.*", "valid_duration": 60, "valid_unit": "minutes"})
	if got := permissionJSON(t, r.Body); !reflect.DeepEqual(got, want) {
		t.Errorf("body = %v, want %v", got, want)
	}

	// Revoke with an error result.
	c2, reqs2 := newTestClient(t, func(r recordedRequest) any { return []string{"Error: no such grant"} })
	if _, err := c2.Permissions.Revoke(context.Background(), NewSecretPermission("s", "bob")); err == nil {
		t.Error("expected error")
	}
	if r := (*reqs2)[len(*reqs2)-1]; r.Method != "DELETE" || r.Path != "/api/v1/grantee/bob" {
		t.Errorf("request = %s %s", r.Method, r.Path)
	}
}
