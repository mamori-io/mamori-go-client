package mamori

import (
	"context"
	"reflect"
	"testing"
)

func datasourceAnyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestDatasourceCreate(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	tr := true
	ds := NewDatasource("test")
	ds.Type, ds.Driver = "POSTGRESQL", "postgres"
	ds.At("10.0.2.2", "5432").WithDatabase("mamori")
	ds.User, ds.Password = "postgres", "pw"
	ds.URLProperties = "a=b"
	ds.WebSQLAutoCommitDefault = &tr
	ds.ExtraOptions = "POOL_MAXIMUM '3', ENABLED FALSE"
	if _, err := c.Datasources.Create(context.Background(), ds); err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.Method != "POST" || r.Path != "/api/v1/systems" || r.Body["preview"] != "N" {
		t.Fatalf("bad request %+v", r)
	}
	if sys := r.Body["system"].(map[string]any); sys["name"] != "test" || sys["type"] != "POSTGRESQL" || sys["host"] != "10.0.2.2" {
		t.Fatalf("bad system %v", sys)
	}
	want := []string{"DRIVER 'postgres'", "USER 'postgres'", "PASSWORD 'pw'", "PORT '5432'",
		"TEMPDATABASE 'mamori'", "DEFAULTDATABASE 'mamori'", "WEBSQLAUTOCOMMITDEFAULT 'TRUE'",
		"CONNECTION_PROPERTIES 'a=b'", "POOL_MAXIMUM '3'", " ENABLED FALSE"}
	if got := datasourceAnyStrings(r.Body["options"]); !reflect.DeepEqual(got, want) {
		t.Fatalf("options\n got %q\nwant %q", got, want)
	}
	if a := r.Body["authorizations"].([]any); len(a) != 0 {
		t.Fatal("authorizations not empty")
	}
}

func TestDatasourceUpdate(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ds := NewDatasource("ora")
	ds.Type = "ORACLE"
	ds.At("h", "1521")
	cs, empty, tr := "jdbc:x", "", true
	_, err := c.Datasources.Update(context.Background(), ds, DatasourceUpdate{ConnectionString: &cs, Host: &empty, Port: &empty, WebSQLAutoCommitDefault: &tr}, false)
	if err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	if r.Method != "PUT" || r.Path != "/api/v1/systems/ora" {
		t.Fatalf("bad request %+v", r)
	}
	if sys := r.Body["system"].(map[string]any); sys["host"] != "h" || sys["type"] != "ORACLE" {
		t.Fatalf("bad system %v", sys)
	}
	want := []string{"WEBSQLAUTOCOMMITDEFAULT 'TRUE'", "CONNECTION_STRING 'jdbc:x'"}
	if got := datasourceAnyStrings(r.Body["options"]); !reflect.DeepEqual(got, want) {
		t.Fatalf("options %q", got)
	}

	// Host change: HOST option, no system host; diffsOnly drops unchanged port.
	host, port := "new", "1521"
	if _, err := c.Datasources.Update(context.Background(), ds, DatasourceUpdate{Host: &host, Port: &port}, true); err != nil {
		t.Fatal(err)
	}
	r = (*reqs)[1]
	if _, ok := r.Body["system"].(map[string]any)["host"]; ok {
		t.Fatal("host should be omitted")
	}
	if got := datasourceAnyStrings(r.Body["options"]); !reflect.DeepEqual(got, []string{"HOST 'new'"}) {
		t.Fatalf("options %q", got)
	}
}

func TestDatasourceCredentialsAndRead(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Path == "/api/v1/objects/databases" {
			return []any{}
		}
		return "ok"
	})
	ctx := context.Background()
	if _, err := c.Datasources.Read(ctx, "a b"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if got := (*reqs)[0].Query; got != "usersystems=true&name=a%20b" {
		t.Fatalf("query %q", got)
	}
	if _, err := c.Datasources.AddCredentialWithManagedPassword(ctx, "ds", "Bob.X", "u", "p", "15"); err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[1]
	if r.Path != "/api/v1/grantee/bob.x/datasource_authorization" || r.Body["reset_days"] != "15" || r.Body["datasource"] != "ds" {
		t.Fatalf("bad request %+v", r)
	}
	if _, err := c.Datasources.RemoveCredential(ctx, "ds", "bob"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[2]; r.Method != "DELETE" || r.Query != "datasource=ds" {
		t.Fatalf("bad request %+v", r)
	}
	if _, err := c.Datasources.ValidateCredential(ctx, "ds", "bob", "u", "p"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[3]; r.Path != "/api/v1/grantee/bob/datasource_authorization/validate" {
		t.Fatalf("bad request %+v", r)
	}
}

func TestDatasourceWithConnectionString(t *testing.T) {
	ds := NewDatasource("x").At("h", "1").WithDatabase("db").WithConnectionString("cs")
	if ds.Host != "" || ds.Port != "" || ds.Database != "" || ds.TempDatabase != "db" || ds.ConnectionString != "cs" {
		t.Fatalf("%+v", ds)
	}
}
