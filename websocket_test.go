package mamori

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// fakeWSServer emulates the /websockets/query protocol: authenticate, a
// two-batch query and a tail stream.
func fakeWSServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx := r.Context()
		send := func(v any) {
			b, _ := json.Marshal(v)
			conn.Write(ctx, websocket.MessageText, b)
		}
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var req Params
			json.Unmarshal(data, &req)
			id := req["id"]
			switch req["command"] {
			case "authenticate":
				opts := req["options"].(map[string]any)
				if opts["password_encrypted"] != Base64Encode("pw") {
					send(Params{"task": Params{"id": id}, "error": "bad password"})
					continue
				}
				send(Params{"task": Params{"id": id, "authtoken": "T"}})
			case "query":
				if req["authtoken"] != "T" {
					send(Params{"task": Params{"id": id}, "error": "no token"})
					continue
				}
				// Task ids may arrive as strings.
				send(Params{"task": Params{"id": fmt.Sprint(id)}, "meta": []Params{{"name": "A"}}, "rows": [][]any{{1}, {2}}})
			case "next":
				send(Params{"task": Params{"id": id}, "meta": []Params{{"name": "A"}}, "rows": [][]any{{3}}, "complete": true})
			case "tail":
				for i := range 3 {
					send(Params{"task": Params{"id": id}, "line": i, "complete": i == 2})
				}
			}
		}
	}))
	t.Cleanup(srv.Close)
	return WebsocketURL(srv.URL)
}

func TestWebsocketAuthAndErrors(t *testing.T) {
	url := fakeWSServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := DialWebsocket(ctx, url, "u", "wrong", nil)
	var wsErr *WSError
	if !errors.As(err, &wsErr) {
		t.Fatalf("expected WSError, got %v", err)
	}

	ws, err := DialWebsocket(ctx, url, "u", "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	ch, err := ws.Tail(ctx, "x")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 3 {
		t.Fatalf("tail delivered %d messages, want 3", n)
	}

	ws.Close()
	if _, err := ws.Next(ctx, 1); err == nil {
		t.Fatal("expected error after close")
	}
}

func TestWebsocketSelect(t *testing.T) {
	url := fakeWSServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, err := DialWebsocket(ctx, url, "u", "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	var got []any
	for row, err := range ws.Select(ctx, "select a", nil) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, row["A"])
	}
	if len(got) != 3 || got[2] != 3.0 {
		t.Fatalf("select rows = %v", got)
	}

	rows, err := ws.QueryRows(ctx, "select a", nil)
	if err != nil || len(rows) != 2 || rows[0]["a"] != 1.0 {
		t.Fatalf("QueryRows = %v, %v", rows, err)
	}
}
