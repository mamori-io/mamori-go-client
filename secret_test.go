package mamori

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestSecretCreateAndMultiPart(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		return []Params{{"status": "OK"}}
	})
	ctx := context.Background()
	s := NewSecret(SecretProtocolGeneric, "s1")
	s.Secret = "pw"
	s.ID = "9"
	res, err := c.Secrets.Create(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	if string(res) != `{"status":"OK"}` {
		t.Fatalf("res = %s", res)
	}
	r := (*reqs)[0]
	if r.Method != "POST" || r.Path != "/api/v1/secrets/" {
		t.Fatalf("got %s %s", r.Method, r.Path)
	}
	body := r.Body["secret"].(map[string]any)
	if body["secret"] != "pw" || body["type"] != "SECRET" || body["name"] != "s1" || body["encoding"] != "text" {
		t.Fatalf("body = %v", body)
	}
	if _, ok := body["id"]; ok {
		t.Fatal("id must not be sent")
	}
	if _, ok := body["expires_at"]; ok {
		t.Fatal("unset expires_at must not be sent")
	}

	m := NewSecret(SecretProtocolGeneric, "multi")
	m.Parts = []string{"a", "b"}
	if _, err := c.Secrets.RestoreWithKey(ctx, m, "k1"); err != nil {
		t.Fatal(err)
	}
	r = (*reqs)[1]
	body = r.Body["secret"].(map[string]any)
	if body["secret"] != `["a","b"]` || body["type"] != "MULTI-SECRET" || r.Body["key"] != "k1" || r.Body["restore"] != true {
		t.Fatalf("body = %v", r.Body)
	}

	s.Description = "new"
	if _, err := c.Secrets.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[2]; r.Method != "PUT" || r.Path != "/api/v1/secrets/9" || r.Body["secret"].(map[string]any)["description"] != "new" {
		t.Fatalf("update = %+v", r)
	}
}

func TestSecretGetByName(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		switch r.Path {
		case "/api/v1/search/secrets":
			return Params{"data": []Params{{"id": 42, "name": "m", "type": "MULTI-SECRET"}}, "totalCount": 1}
		case "/api/v1/secrets/42/parts":
			return Params{"parts": `["p1","p2"]`}
		}
		return nil
	})
	s, err := c.Secrets.GetByName(context.Background(), "m")
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "42" || !reflect.DeepEqual(s.Parts, []string{"p1", "p2"}) {
		t.Fatalf("secret = %+v", s)
	}
	r := (*reqs)[0]
	if r.Method != "PUT" || r.Body["take"] != float64(100) {
		t.Fatalf("search req = %+v", r)
	}
	f := r.Body["filter"].(map[string]any)["0"].([]any)
	if f[0] != "name" || f[1] != "=" || f[2] != "m" {
		t.Fatalf("filter = %v", f)
	}
}

func TestSecretNotFoundAndExport(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		switch r.Path {
		case "/api/v1/search/secrets":
			if r.Body["filter"].(map[string]any)["0"].([]any)[2] == "missing" {
				return Params{"data": []Params{}, "totalCount": 0}
			}
			return Params{"data": []Params{{"id": "7", "name": "a b", "type": "SECRET"}}, "totalCount": 1}
		case "/api/v1/secrets/a%20b/export":
			return []Params{{"value": "ENC"}}
		}
		return nil
	})
	ctx := context.Background()
	if _, err := c.Secrets.DeleteByName(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	s, err := c.Secrets.ExportByName(ctx, "a b", "key1")
	if err != nil {
		t.Fatal(err)
	}
	if s.Secret != "ENC" || s.ID != "7" {
		t.Fatalf("secret = %+v", s)
	}
	last := (*reqs)[len(*reqs)-1]
	if last.Method != "GET" || last.Query != "key=key1" {
		t.Fatalf("export req = %+v", last)
	}
}

func TestSecretRevealWithIDAndDelete(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		return []Params{{"secret": "x"}}
	})
	ctx := context.Background()
	row, err := c.Secrets.RevealWithID(ctx, "12")
	if err != nil || row["secret"] != "x" {
		t.Fatalf("row=%v err=%v", row, err)
	}
	if got := (*reqs)[0].Body["sql"]; got != "call REVEAL_SECRET(12)" {
		t.Fatalf("sql = %v", got)
	}
	if _, err := c.Secrets.Delete(ctx, "12"); err != nil {
		t.Fatal(err)
	}
	if r := (*reqs)[1]; r.Method != "DELETE" || r.Path != "/api/v1/secrets/12" {
		t.Fatalf("delete req = %+v", r)
	}
}

func TestSecretJSONRoundTrip(t *testing.T) {
	s := NewSecret(SecretProtocolSSH, "x")
	s.Secret = "v"
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back Secret
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*s, back) {
		t.Fatalf("%+v != %+v", *s, back)
	}
}
