package mamori

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestObjects(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	if _, err := c.Objects(ctx, "pg", "db", "public", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Objects(ctx, "pg", "db", "public", "t1"); err != nil {
		t.Fatal(err)
	}
	r := *reqs
	if r[0].Method != http.MethodGet || r[0].Path != "/api/v1/objects" {
		t.Fatalf("unexpected request %+v", r[0])
	}
	if strings.Contains(r[0].Query, "object_name") || !strings.Contains(r[0].Query, "system_name=pg") {
		t.Fatalf("unexpected query %q", r[0].Query)
	}
	if !strings.Contains(r[1].Query, "object_name=t1") {
		t.Fatalf("missing object_name: %q", r[1].Query)
	}
}

func TestSystemMisc(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.InstallCerts(ctx, "web", "CA", "KEY", "CRT")
	c.UpdateAlert(ctx, 7, Params{"name": "a"})
	c.UpdateListenerLogging(ctx, "pg", true)
	c.GetQRCode(ctx, "a b")
	r := *reqs
	certs, _ := r[0].Body["certs"].(map[string]any)
	if r[0].Path != "/api/v1/certs" || r[0].Body["name"] != "web" || certs["ca_crt"] != "CA" || certs["key"] != "KEY" || certs["crt"] != "CRT" {
		t.Fatalf("install certs: %+v", r[0])
	}
	if r[1].Method != http.MethodPut || r[1].Path != "/api/v1/alerts/7" || r[1].Body["alert"] == nil {
		t.Fatalf("update alert: %+v", r[1])
	}
	if r[2].Path != "/api/v1/listeners/pg/logging" || r[2].Body["detailed_logging"] != true {
		t.Fatalf("listener logging: %+v", r[2])
	}
	if r[3].Path != "/api/ua/qrcheck/a%20b" {
		t.Fatalf("qr code: %+v", r[3])
	}
}

func TestSetServerDomain(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Method == http.MethodGet {
			return Params{}
		}
		return []any{"ok"}
	})
	if err := c.SetServerDomain(context.Background(), "mamori.example.com"); err != nil {
		t.Fatal(err)
	}
	const url = "https://mamori.example.com/"
	type want struct {
		method, path string
		check        func(Params) bool
	}
	wants := []want{
		{http.MethodGet, "/api/v1/smtp", func(Params) bool { return true }},
		{http.MethodPut, "/api/v1/smtp", func(b Params) bool { return b["web_url"] == url && b["ssl"] == false }},
		{http.MethodPut, "/api/v1/server_properties", func(b Params) bool {
			p, _ := b["properties"].(map[string]any)
			return p["wireguard_public_address"] == "mamori.example.com"
		}},
		{http.MethodPut, "/api/v1/server_properties", func(b Params) bool {
			p, _ := b["properties"].(map[string]any)
			return p["rdp_uri"] == url+"rdp"
		}},
		{http.MethodPut, "/api/v1/providers/pushtotp", func(b Params) bool {
			return b["type"] == "pushtotp" && b["name"] == "pushtotp" && b["mamori_service_url"] == url &&
				b["authentication_timeout"] == "180" && b["cache_authentication_timeout"] == "900"
		}},
		{http.MethodPut, "/api/v1/providers/pushmobile", func(b Params) bool {
			return b["type"] == "pushmobile" && b["mamori_service_url"] == url
		}},
	}
	// The expected requests must appear in order; helper methods may issue
	// additional requests in between.
	i := 0
	for _, r := range *reqs {
		if i < len(wants) && r.Method == wants[i].method && r.Path == wants[i].path && wants[i].check(r.Body) {
			i++
		}
	}
	if i != len(wants) {
		t.Fatalf("request %d (%s %s) not seen in order; got %+v", i, wants[i].method, wants[i].path, *reqs)
	}
}

func TestSetServerDomainJoinsErrors(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/api/v1/providers/pushtotp" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	err = c.SetServerDomain(context.Background(), "x")
	if StatusCode(err) != http.StatusInternalServerError {
		t.Fatalf("expected joined 500 error, got %v", err)
	}
	if !slices.Contains(paths, "/api/v1/providers/pushmobile") {
		t.Fatalf("later calls not attempted after a failure: %v", paths)
	}
}
