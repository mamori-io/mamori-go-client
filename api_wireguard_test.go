package mamori

import (
	"context"
	"net/http"
	"testing"
)

func TestWireguardRequests(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	if _, err := c.UpdateWireguardPeer(ctx, Params{"id": "p1", "device_name": "laptop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateWireguardPeer(ctx, Params{"device_name": "laptop"}); err == nil {
		t.Fatal("expected error for peer without id")
	}
	c.CreateWireguardPeer(ctx, Params{"device_name": "laptop"})
	c.WireguardDisconnectPeer(ctx, "abc+/=")
	r := *reqs
	if len(r) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(r))
	}
	if r[0].Method != http.MethodPut || r[0].Path != "/api/v1/wireguard/p1" || r[0].Body["peer"].(map[string]any)["device_name"] != "laptop" {
		t.Fatalf("update: %+v", r[0])
	}
	if r[1].Method != http.MethodPost || r[1].Path != "/api/v1/wireguard" || r[1].Body["peer"] == nil {
		t.Fatalf("create: %+v", r[1])
	}
	if r[2].Method != http.MethodDelete || r[2].Path != "/api/v1/wireguard/abc%2B%2F%3D/disconnect" {
		t.Fatalf("disconnect: %+v", r[2])
	}
}
