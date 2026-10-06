package mamori

import (
	"context"
	"encoding/json"
	"testing"
)

func TestRemoteDesktopLoginMode(t *testing.T) {
	l := NewRemoteDesktopLogin("x", RemoteDesktopProtocolRDP)
	if l.RDP == nil || l.VNC != nil || l.LoginMode() != RemoteDesktopLoginModeOSPrompt {
		t.Fatalf("%+v", l)
	}
	l.SetLoginMode(RemoteDesktopLoginModeMamoriPrompt)
	if l.LoginMode() != RemoteDesktopLoginModeMamoriPrompt {
		t.Fatal(l.LoginMode())
	}
	l.SetCredentials("u", "p", "")
	if l.LoginMode() != RemoteDesktopLoginModeManual {
		t.Fatal(l.LoginMode())
	}
	l.SetProtocol(RemoteDesktopProtocolVNC)
	if l.RDP != nil || l.VNC == nil || l.VNC.Port != 3389 {
		t.Fatalf("%+v", l)
	}
}

func TestRemoteDesktopLoginJSON(t *testing.T) {
	l := NewRemoteDesktopLogin("x", RemoteDesktopProtocolRDP)
	l.At("host", 3390)
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	if err := json.Unmarshal(b, &flat); err != nil {
		t.Fatal(err)
	}
	if flat["hostname"] != "host" || flat["protocol"] != "rdp" || flat["record"] != true || flat["id"] != float64(-1) || flat["color_depth"] != float64(24) {
		t.Fatalf("flat = %v", flat)
	}
	var back RemoteDesktopLogin
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Name != "x" || back.ID != -1 || back.RDP == nil || *back.RDP != *l.RDP || !back.Record {
		t.Fatalf("back = %+v %+v", back, back.RDP)
	}
}

func TestRemoteDesktopService(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Method == "GET" && r.Path == "/api/v1/rdp/x" {
			return Params{"_id": 12, "_protocol": "rdp", "_record_session": false, "hostname": "h", "port": "port", "username": "", "_credentials_required": true}
		}
		if r.Method == "GET" {
			return Params{"data": []Params{{"name": "x"}}, "totalCount": 1}
		}
		return Params{"status": "ok"}
	})
	ctx := context.Background()
	l := NewRemoteDesktopLogin("x", RemoteDesktopProtocolVNC)
	l.At("vh", 5900)
	if _, err := c.RemoteDesktops.Create(ctx, l); err != nil {
		t.Fatal(err)
	}
	r := (*reqs)[0]
	d := r.Body["details"].(map[string]any)
	if r.Method != "POST" || r.Path != "/api/v1/rdp/" || r.Body["name"] != "x" || d["_protocol"] != "vnc" || d["_record_session"] != true || d["hostname"] != "vh" || d["port"] != float64(5900) {
		t.Fatalf("create = %+v", r)
	}

	got, err := c.RemoteDesktops.GetByName(ctx, "x")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 12 || got.Name != "x" || got.Record || got.RDP == nil || got.RDP.Hostname != "h" || got.RDP.Port != 3389 || got.LoginMode() != RemoteDesktopLoginModeMamoriPrompt {
		t.Fatalf("got = %+v %+v", got, got.RDP)
	}

	if _, err := c.RemoteDesktops.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if u := (*reqs)[2]; u.Method != "PUT" || u.Path != "/api/v1/rdp/12" || u.Body["details"].(map[string]any)["_record_session"] != false {
		t.Fatalf("update = %+v", u)
	}

	if _, err := c.RemoteDesktops.List(ctx, SearchOptions{Take: 10, Filter: Filters{F("name", FilterEquals, "x")}}); err != nil {
		t.Fatal(err)
	}
	if q := (*reqs)[3]; q.Method != "GET" || q.Path != "/api/v1/rdp" || q.Query == "" {
		t.Fatalf("list = %+v", q)
	}
	if _, err := c.RemoteDesktops.Delete(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if d := (*reqs)[4]; d.Method != "DELETE" || d.Path != "/api/v1/rdp/x" {
		t.Fatalf("delete = %+v", d)
	}
}
