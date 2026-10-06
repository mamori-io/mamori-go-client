package mamori

import (
	"context"
	"testing"
)

func TestCreateDBPolicyPriority(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	cases := []struct {
		priority any
		want     bool
	}{
		{nil, false}, {0, false}, {"", false}, {"abc", false}, {5, true}, {"7", true}, {2.5, true},
	}
	for _, tc := range cases {
		if _, err := c.CreateDBPolicy(ctx, "p1", tc.priority, "d"); err != nil {
			t.Fatal(err)
		}
		r := (*reqs)[len(*reqs)-1]
		if r.Method != "POST" || r.Path != "/api/v1/policies/dbpolicy" || r.Body["name"] != "p1" || r.Body["description"] != "d" {
			t.Fatalf("bad request %+v", r)
		}
		if _, ok := r.Body["priority"]; ok != tc.want {
			t.Errorf("priority %v: sent=%v want %v", tc.priority, ok, tc.want)
		}
	}
}

func TestGetSMTPConfigMergesLogo(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		switch r.Path {
		case "/api/v1/smtp":
			return Params{"host": "mail"}
		case "/api/v1/server_properties":
			return Params{"email_logo": "L", "email_logo_height": "40"}
		}
		return nil
	})
	cfg, err := c.GetSMTPConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cfg["host"] != "mail" || cfg["logo"] != "L" || cfg["logo_height"] != "40" {
		t.Fatalf("bad config %v", cfg)
	}
	if len(*reqs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(*reqs))
	}
}

func TestSetSMTPConfig(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	_, err := c.SetSMTPConfig(context.Background(), Params{"host": "mail", "logo": "L", "logo_height": 40})
	if err != nil {
		t.Fatal(err)
	}
	r := *reqs
	if len(r) != 2 || r[0].Method != "PUT" || r[0].Path != "/api/v1/smtp" || r[0].Body["host"] != "mail" {
		t.Fatalf("bad first request %+v", r)
	}
	props, _ := r[1].Body["properties"].(map[string]any)
	if r[1].Method != "PUT" || r[1].Path != "/api/v1/server_properties" || props["email_logo"] != "L" || props["email_logo_height"] != float64(40) {
		t.Fatalf("bad second request %+v", r[1])
	}
}

func TestConnectionInfoAndDrivers(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	c.ConnectionInfo(ctx, "a b/c", false)
	c.ConnectionInfo(ctx, "x", true)
	c.SSHSessionLog(ctx, "s/1", Params{"skip": 0})
	c.DriversForType(ctx, "postgres sql")
	c.CreateDriverForSpec(ctx, DriverSpec{Name: "pg", Type: "postgresql", Classname: "org.Driver", IncludeParentClasspath: true, ResourceFiles: []any{"a.jar"}})
	r := *reqs
	if r[0].Path != "/api/v1/connection_log/a%20b%2Fc" || r[0].Query != "" {
		t.Errorf("connection info: %+v", r[0])
	}
	if r[1].Query != "ssh_streams=y" {
		t.Errorf("ssh streams: %+v", r[1])
	}
	if r[2].Path != "/api/v1/ssh/s%2F1" || r[2].Query != "skip=0" {
		t.Errorf("ssh session log: %+v", r[2])
	}
	if r[3].Path != "/api/v1/drivers" || r[3].Query != "type=postgres%20sql" {
		t.Errorf("drivers for type: %+v", r[3])
	}
	b := r[4].Body
	if r[4].Method != "POST" || b["name"] != "pg" || b["type"] != "postgresql" || b["classname"] != "org.Driver" || b["include_parent_classpath"] != true {
		t.Errorf("create driver: %+v", r[4])
	}
}
