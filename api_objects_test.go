package mamori

import (
	"context"
	"testing"
)

func TestObjectRequests(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.DatabasesFiltered(ctx, "system=pg&x=1")
	c.DatabaseSchemas(ctx, "my ds", "db&1")
	c.GetTablesBySystemSchema(ctx, "ds/1", "pub lic")
	c.DatabaseValidateLogin(ctx, "ds", Params{"username": "u"})
	r := *reqs
	if r[0].Path != "/api/v1/objects/databases" || r[0].Query != "system=pg&x=1" {
		t.Errorf("filtered: %+v", r[0])
	}
	if r[1].Path != "/api/v1/objects/databases/my%20ds" || r[1].Query != "database=db%261" {
		t.Errorf("database schemas: %+v", r[1])
	}
	if r[2].Path != "/api/v1/objects/system/ds%2F1/schemas/pub%20lic/tables" {
		t.Errorf("tables: %+v", r[2])
	}
	if r[3].Method != "PUT" || r[3].Path != "/api/v1/objects/databases/ds/validate" || r[3].Body["username"] != "u" {
		t.Errorf("validate: %+v", r[3])
	}
}
