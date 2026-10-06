package mamori

import (
	"context"
	"reflect"
	"testing"
)

func TestServerSettingsBootstrap(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	if _, err := c.ServerSettings.SetBootstrapAccount(ctx, true, "pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ServerSettings.SetBootstrapAccount(ctx, false, "  "); err != nil {
		t.Fatal(err)
	}
	r := *reqs
	want := Params{"name": "admin", "type": "admin", "enabled": "true", "password": "pw"}
	if r[0].Method != "PUT" || r[0].Path != "/api/v1/providers/admin" || !reflect.DeepEqual(r[0].Body, want) {
		t.Errorf("enable: %+v", r[0])
	}
	want = Params{"name": "admin", "type": "admin", "enabled": "false"}
	if !reflect.DeepEqual(r[1].Body, want) {
		t.Errorf("disable: %+v", r[1])
	}
}

func TestServerSettingsPassthrough(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	if _, err := c.ServerSettings.SetPassthrough(context.Background(), "ds1"); err != nil {
		t.Fatal(err)
	}
	if got := (*reqs)[0].Body["sql"]; got != "set PASSTHROUGH 'ds1' true" {
		t.Errorf("sql: %v", got)
	}
}
