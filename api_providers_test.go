package mamori

import (
	"context"
	"testing"
)

func TestProviderRequests(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.GetProvider(ctx, "My LDAP")
	c.EnableProvider(ctx, "ldap1", "ldap")
	c.DisableProvider(ctx, "ldap1", "ldap")
	c.SetTOTPCacheTime(ctx, 30)
	c.AgentDrop(ctx, "agent/1")
	c.GetProviderOptions(ctx)
	r := *reqs
	if r[0].Path != "/api/v1/providers/my%20ldap" {
		t.Errorf("get provider: %+v", r[0])
	}
	if r[1].Method != "PUT" || r[1].Path != "/api/v1/providers/ldap1" || r[1].Body["enabled"] != "true" || r[1].Body["type"] != "ldap" || r[1].Body["name"] != "ldap1" {
		t.Errorf("enable: %+v", r[1])
	}
	if r[2].Body["enabled"] != "false" {
		t.Errorf("disable: %+v", r[2])
	}
	if r[3].Method != "PUT" || r[3].Path != "/api/v1/defaults/totpcachetime/30" {
		t.Errorf("totp cache: %+v", r[3])
	}
	if r[4].Method != "DELETE" || r[4].Path != "/api/v1/agents/agent%2F1" {
		t.Errorf("agent drop: %+v", r[4])
	}
	if r[5].Path != "/api/v1/providers" || r[5].Query != "options=y" {
		t.Errorf("provider options: %+v", r[5])
	}
}
