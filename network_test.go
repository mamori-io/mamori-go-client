package mamori

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

func TestNetworkCreate(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any { return "started" })
	ctx := context.Background()

	tun := NewSSHTunnel("Test_Tunnel")
	tun.Host, tun.Port = "example.com", 22
	tun.LocalPort, tun.RemoteHost, tun.RemotePort = 2224, "localhost", 22
	tun.User, tun.PrivateKeyID = "root", "sshkey"

	ovpn := NewOpenVPN("ovpn")
	ovpn.Host, ovpn.Port, ovpn.User = "vpn", 1194, "u"

	ipsec := NewIPSecVPN("ipsec")
	ipsec.Host, ipsec.PSK = "h", "psk"

	for _, n := range []NetworkConfig{tun, ovpn, ipsec} {
		if _, err := c.Networks.Create(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{
		`{"vpn":{"config":{"host":"example.com","localPort":2224,"port":22,"remoteHost":"localhost","remotePort":22,"username":"root"},"name":"test_tunnel","secrets":[{"name":"privateKeyId","value":"sshkey"}],"type":"ssh"}}`,
		`{"vpn":{"config":{"compression":"yes","host":"vpn","network":"tun","port":1194,"tls_client":false,"transport":"udp"},"name":"ovpn","secrets":[{"name":"vpn-user","value":"u"},{"name":"vpn-password"},{"name":"vpn-ca"},{"name":"vpn-ta"},{"name":"vpn-client-cert"},{"name":"vpn-client-key"}],"type":"openvpn"}}`,
		`{"vpn":{"config":{"host":"h"},"name":"ipsec","secrets":[{"name":"password"},{"name":"psk","value":"psk"}],"type":"ipsec"}}`,
	}
	for i, w := range want {
		r := (*reqs)[i]
		var wantBody Params
		json.Unmarshal([]byte(w), &wantBody)
		if r.Method != "POST" || r.Path != "/api/v1/vpns" || !reflect.DeepEqual(r.Body, wantBody) {
			t.Fatalf("case %d: got %s", i, r.Raw)
		}
	}
}

func TestNetworkLifecycle(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any { return "ok" })
	ctx := context.Background()
	c.Networks.Start(ctx, "Net")
	c.Networks.Stop(ctx, "net")
	c.Networks.Status(ctx, "net")
	c.Networks.ConnectionLog(ctx, "net")
	c.Networks.Delete(ctx, "net")
	want := []string{"PUT /api/v1/vpns/net/start", "PUT /api/v1/vpns/net/stop", "GET /api/v1/vpns/net/status", "GET /api/v1/vpns/net/logs", "DELETE /api/v1/vpns/net"}
	for i, w := range want {
		if got := (*reqs)[i].Method + " " + (*reqs)[i].Path; got != w {
			t.Fatalf("got %q want %q", got, w)
		}
	}
}

func TestNetworkDecode(t *testing.T) {
	v := NewOpenVPN("x")
	if err := json.Unmarshal([]byte(`{"name":"x","type":"openvpn","host":"h","tls_client":true,"ca_crt":"CA"}`), v); err != nil {
		t.Fatal(err)
	}
	if v.Host != "h" || !v.TLSClient || v.CACert != "CA" || v.Transport != "udp" || v.Name != "x" {
		t.Fatalf("%+v", v)
	}
}
