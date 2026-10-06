package mamori

import (
	"context"
	"testing"
)

func TestKeyCreate(t *testing.T) {
	c, reqs := newTestClient(t, nil)
	ctx := context.Background()
	cases := []struct {
		key  *Key
		path string
		body Params
	}{
		{NewKey("rsa", KeyTypeRSA), "/api/v1/encryption_keys/create/rsapair", Params{"name": "rsa", "size": float64(1024)}},
		{&Key{Name: "ed", Type: KeyTypeSSH, Algorithm: SSHAlgorithmED25519, Size: 1024}, "/api/v1/encryption_keys/create/sshkey", Params{"name": "ed", "algorithm": "ED25519", "size": float64(256)}},
		{&Key{Name: "ec", Type: KeyTypeSSH, Algorithm: SSHAlgorithmECDSA, Size: 384}, "/api/v1/encryption_keys/create/sshkey", Params{"name": "ec", "algorithm": "ECDSA", "size": float64(384)}},
		{NewKey("aes", KeyTypeAES), "/api/v1/encryption_keys", Params{"name": "aes", "type": "AES"}},
		{&Key{Name: "pem", Type: KeyTypeRSA, Key: "PEM", Password: "pw"}, "/api/v1/encryption_keys", Params{"name": "pem", "type": "RSA", "value": "PEM", "password": "pw"}},
	}
	for i, tc := range cases {
		if _, err := c.Keys.Create(ctx, tc.key); err != nil {
			t.Fatal(err)
		}
		r := (*reqs)[i]
		if r.Method != "POST" || r.Path != tc.path || len(r.Body) != len(tc.body) {
			t.Fatalf("case %d: %+v", i, r)
		}
		for k, v := range tc.body {
			if r.Body[k] != v {
				t.Fatalf("case %d: %s = %v, want %v", i, k, r.Body[k], v)
			}
		}
	}
}

func TestKeyGrantRevoke(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any { return "Granted" })
	ctx := context.Background()
	res, err := c.Keys.GrantTo(ctx, "k1", "Bob")
	if s, _ := Decode[string](res); err != nil || s != "Granted" {
		t.Fatalf("%s %v", res, err)
	}
	if r := (*reqs)[0]; r.Path != "/api/v1/grantee/bob/encryption_keys" || r.Body["encryption_keys"].([]any)[0] != "k1" {
		t.Fatalf("%+v", r)
	}
	if _, err := c.Keys.RevokeFrom(ctx, "k1", "Bob"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[1]; r.Method != "DELETE" || r.Query != "encryption_keys%5B%5D=k1" {
		t.Fatalf("%+v", r)
	}
	if _, err := c.Keys.Rename(ctx, "k1", "k2"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[2]; r.Method != "PUT" || r.Path != "/api/v1/encryption_keys/k1" || r.Body["name"] != "k2" {
		t.Fatalf("%+v", r)
	}
}
