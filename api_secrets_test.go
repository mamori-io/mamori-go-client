package mamori

import (
	"context"
	"net/http"
	"testing"
)

func TestExportSecret(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.ExportSecret(ctx, "my secret", "")
	c.ExportSecret(ctx, "my secret", "k&y 1")
	r := *reqs
	if r[0].Method != http.MethodGet || r[0].Path != "/api/v1/secrets/my%20secret/export" || r[0].Query != "" {
		t.Fatalf("no key: %+v", r[0])
	}
	if r[1].Path != "/api/v1/secrets/my%20secret/export" || r[1].Query != "key=k%26y%201" {
		t.Fatalf("with key: %+v", r[1])
	}
}

func TestRestoreSecret(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.RestoreSecret(ctx, "blob", "")
	c.RestoreSecret(ctx, "blob", "k1")
	r := *reqs
	if r[0].Method != http.MethodPost || r[0].Path != "/api/v1/secrets/" || r[0].Body["restore"] != true || r[0].Body["secret"] != "blob" {
		t.Fatalf("no key: %+v", r[0])
	}
	if _, ok := r[0].Body["key"]; ok {
		t.Fatalf("key should be omitted: %+v", r[0].Body)
	}
	if r[1].Body["key"] != "k1" || r[1].Body["restore"] != true || r[1].Body["secret"] != "blob" {
		t.Fatalf("with key: %+v", r[1].Body)
	}
}

func TestSecretMisc(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.CreateSecret(ctx, Params{"name": "s"})
	c.ResetSecretAlert(ctx, "12", "2026-01-01")
	r := *reqs
	if r[0].Body["secret"].(map[string]any)["name"] != "s" {
		t.Fatalf("create: %+v", r[0])
	}
	if r[1].Method != http.MethodPut || r[1].Path != "/api/v1/secrets/12/reset_alert" || r[1].Body["alert_at"] != "2026-01-01" {
		t.Fatalf("reset alert: %+v", r[1])
	}
}
