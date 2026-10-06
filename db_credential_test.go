package mamori

import (
	"context"
	"errors"
	"testing"
)

func TestDBCredentialListAndDelete(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		switch r.Path {
		case "/api/v1/search/datasource-credentials":
			return Params{"totalCount": 1, "data": []any{Params{"datasource": "ds", "remoteusername": "pg", "grantee": "@", "auth_id": 7}}}
		case "/api/v1/query":
			return []any{Params{"value": "BLOB"}}
		}
		return "ok"
	})
	ctx := context.Background()
	cred, err := c.DBCredentials.DeleteByName(ctx, "ds", "pg", "@")
	if err != nil {
		t.Fatal(err)
	}
	if cred.Datasource != "ds" || cred.Username != "pg" || cred.AuthID != float64(7) {
		t.Fatalf("bad credential %+v", cred)
	}
	r := (*reqs)[0]
	if r.Method != "PUT" || r.Body["skip"] != float64(0) || r.Body["take"] != float64(5) {
		t.Fatalf("bad search %+v", r)
	}
	f := r.Body["filter"].(map[string]any)
	if len(f) != 3 || f["0"].([]any)[0] != "datasource" || f["1"].([]any)[0] != "grantee" || f["2"].([]any)[2] != "pg" {
		t.Fatalf("bad filter %v", f)
	}
	d := (*reqs)[1]
	if d.Method != "DELETE" || d.Path != "/api/v1/grantee/%22%40%22/datasource_authorization" || d.Query != "datasource=ds&username=pg" {
		t.Fatalf("bad delete %+v", d)
	}

	pw, err := c.DBCredentials.ExportPassword(ctx, cred, "k1")
	if err != nil || pw != "BLOB" {
		t.Fatalf("export %q %v", pw, err)
	}
	if got := (*reqs)[2].Body["sql"]; got != "call export_credential('ds', 'pg', '@', 'k1')" {
		t.Fatalf("sql %v", got)
	}
}

func TestDBCredentialNotFound(t *testing.T) {
	c, _ := newTestClient(t, func(r recordedRequest) any { return Params{"totalCount": 0, "data": []any{}} })
	if _, err := c.DBCredentials.GetByName(context.Background(), "ds", "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestDBCredentialCreateRestore(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	cred := NewDBCredential("ds", "pg")
	if _, err := c.DBCredentials.Create(ctx, cred, "secret"); err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.Path != "/api/v1/grantee/%40/datasource_authorization" || r.Body["password"] != "secret" || r.Body["reset_days"] != "" || r.Body["username"] != "pg" {
		t.Fatalf("bad create %+v", r)
	}
	cred.Password = "BLOB"
	if _, err := c.DBCredentials.Restore(ctx, cred, "k1"); err != nil {
		t.Fatal(err)
	}
	r = (*reqs)[1]
	args := r.Body["args"].([]any)
	if r.Path != "/v2/call/RESTORE_DATASOURCE_CREDENTIAL_EX" || len(args) != 5 || args[3] != "BLOB" || args[4] != "k1" {
		t.Fatalf("bad restore %+v", r)
	}
}
