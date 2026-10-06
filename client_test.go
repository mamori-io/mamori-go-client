package mamori

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// recordedRequest captures what the client sent to the test server.
type recordedRequest struct {
	Method string
	Path   string // escaped path
	Query  string // raw query
	Body   Params // decoded JSON body, nil if none
	Raw    []byte
}

// newTestClient returns a client wired to an httptest server. respond is
// called for every request and its return value is JSON encoded as the
// response (a json.RawMessage or []byte is written verbatim). The returned slice
// pointer accumulates the requests seen.
func newTestClient(t *testing.T, respond func(r recordedRequest) any) (*Client, *[]recordedRequest) {
	t.Helper()
	var reqs []recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		rec := recordedRequest{Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery, Raw: raw}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.Body)
		}
		reqs = append(reqs, rec)
		var out any
		if respond != nil {
			out = respond(rec)
		}
		w.Header().Set("Content-Type", "application/json")
		switch v := out.(type) {
		case json.RawMessage:
			w.Write(v)
		case []byte:
			w.Write(v)
		case nil:
			w.Write([]byte("[]"))
		default:
			json.NewEncoder(w).Encode(v)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return c, &reqs
}

func TestLoginAndCall(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		switch r.Path {
		case "/":
			return []byte(`<html><head><meta name="csrf-token" content="tok123"></head></html>`)
		case "/sessions/login":
			return Params{"username": "alice", "session_id": "s1", "privs": []string{"CREATE USER"}}
		case "/api/v1/ping":
			return Params{"pong": true}
		}
		return nil
	})
	ctx := context.Background()
	login, err := c.Login(ctx, "Alice", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if login.SessionID != "s1" || c.SessionID() != "s1" || !c.HasPriv("CREATE USER") || c.HasPriv("DROP USER") {
		t.Fatalf("unexpected session state: %+v", login)
	}
	if got := (*reqs)[1].Body["username"]; got != "alice" {
		t.Fatalf("username not lower-cased: %v", got)
	}
	if c.csrf != "tok123" {
		t.Fatalf("csrf not captured: %q", c.csrf)
	}
	pong, err := c.Ping(ctx)
	if err != nil || !pong {
		t.Fatalf("ping: %v %v", pong, err)
	}
}

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"nope"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	c, _ := New(srv.URL)
	_, err := c.Call(context.Background(), http.MethodGet, "/v1/users", nil)
	if StatusCode(err) != http.StatusForbidden {
		t.Fatalf("expected 403 APIError, got %v", err)
	}
}

func TestEncodeParams(t *testing.T) {
	tests := []struct {
		in   any
		want string
	}{
		{Params{"a": 1, "b": "x y"}, "a=1&b=x%20y"},
		{Params{"scope": []string{"x", "y"}}, "scope%5B%5D=x&scope%5B%5D=y"},
		{Params{"f": Params{"0": []any{"name", "=", "bob"}}}, "f%5B0%5D%5B%5D=name&f%5B0%5D%5B%5D=%3D&f%5B0%5D%5B%5D=bob"},
		{Params{"o": []any{Params{"k": true}}}, "o%5B0%5D%5Bk%5D=true"},
		{nil, ""},
	}
	for _, tt := range tests {
		got, err := EncodeParams(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("EncodeParams(%v) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func TestDecodeMessage(t *testing.T) {
	m, err := DecodeMessage("7._status,5.hello,2.50;")
	if err != nil || m.Command != "_status" || len(m.Params) != 2 || m.Params[0] != "hello" || m.Params[1] != "50" {
		t.Fatalf("got %+v, %v", m, err)
	}
	if _, err := DecodeMessage("3.abc;x"); err == nil {
		t.Fatal("expected trailing data error")
	}
	if _, err := DecodeMessage("9.abc;"); err == nil {
		t.Fatal("expected short data error")
	}
}

func TestParseSexp(t *testing.T) {
	v, err := ParseSexp(`(a "b c" (1 -2.5) 'q')`)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 4 || v[0] != Symbol("a") || v[1] != "b c" || v[3] != "q" {
		t.Fatalf("got %#v", v)
	}
	if sub := v[2].([]any); sub[0] != 1.0 || sub[1] != -2.5 {
		t.Fatalf("got %#v", sub)
	}
	if _, err := ParseSexp(`(a "b`); err == nil {
		t.Fatal("expected error")
	}
}
