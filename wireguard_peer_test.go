package mamori

import (
	"context"
	"testing"
)

func TestWireguardPeer(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		switch {
		case r.Method == "POST" && r.Path == "/api/v1/wireguard":
			return Params{"peer": Params{"id": 4, "userid": "u", "device_name": "d"}, "config": "[Interface]"}
		case r.Method == "GET":
			return Params{"data": []Params{{"id": 4, "userid": "u", "device_name": "d", "public_key": "0102ff"}}, "totalCount": 1}
		case r.Method == "PUT":
			return Params{"config": "CFG"}
		}
		return Params{"status": "ok"}
	})
	ctx := context.Background()
	res, err := c.WireguardPeers.Create(ctx, NewWireguardPeer("u", "d"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Config != "[Interface]" || res.Peer.ID != "4" {
		t.Fatalf("res = %+v", res)
	}
	peer := (*reqs)[0].Body["peer"].(map[string]any)
	if v, ok := peer["public_key"]; !ok || v != nil || peer["userid"] != "u" || peer["device_name"] != "d" {
		t.Fatalf("peer = %v", peer)
	}

	list, err := c.WireguardPeers.List(ctx, SearchOptions{Take: 10})
	if err != nil {
		t.Fatal(err)
	}
	if row := list.Data[0]; row["public_key"] != "AQL/" || row["name"] != "u-d" {
		t.Fatalf("row = %v", row)
	}

	p := &WireguardPeer{ID: "4", UserID: "u", DeviceName: "d"}
	if _, err := c.WireguardPeers.Reset(ctx, p, true); err != nil {
		t.Fatal(err)
	}
	n := len(*reqs)
	put, notify := (*reqs)[n-2], (*reqs)[n-1]
	if put.Method != "PUT" || put.Path != "/api/v1/wireguard/4" || len(put.Body["peer"].(map[string]any)) != 3 {
		t.Fatalf("put = %+v", put)
	}
	if notify.Path != "/api/v1/wireguard/notify" || notify.Body["config"] != "CFG" || notify.Body["username"] != "u" {
		t.Fatalf("notify = %+v", notify)
	}

	if _, err := c.WireguardPeers.Lock(ctx, "4"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[len(*reqs)-1]; r.Method != "PUT" || r.Path != "/api/v1/wireguard/4/lock" {
		t.Fatalf("lock = %+v", r)
	}
	if _, err := c.WireguardPeers.Disconnect(ctx, "ab+/="); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[len(*reqs)-1]; r.Method != "DELETE" || r.Path != "/api/v1/wireguard/ab%2B%2F%3D/disconnect" {
		t.Fatalf("disconnect = %+v", r)
	}
	if _, err := c.WireguardPeers.Delete(ctx, ""); err == nil {
		t.Fatal("expected error for missing id")
	}
}
