package mamori

import (
	"context"
	"testing"
)

func TestProviderListGet(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		return Params{"provider_name": "duo", "is_mfa": "Y", "properties": Params{"host": "h"}}
	})
	ctx := context.Background()
	if _, err := c.Providers.List(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := c.Providers.Get(ctx, "My DUO")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Decode[DUOProvider](raw)
	if err != nil || p.ProviderName != "duo" || p.IsMFA != "Y" || p.Properties["host"] != "h" {
		t.Fatalf("%+v %v", p, err)
	}
	r := *reqs
	if r[0].Path != "/api/v1/providers" || r[1].Path != "/api/v1/providers/my%20duo" {
		t.Errorf("paths: %+v", r)
	}
}
