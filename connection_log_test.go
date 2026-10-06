package mamori

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestConnectionLogList(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if r.Path == "/api/v1/search/connection_events" {
			return []Params{{"id": 1}, {"id": 2}}
		}
		return Params{"data": []Params{{"ssid": "s1"}}, "totalCount": 7}
	})
	ctx := context.Background()
	res, err := c.ConnectionLogs.List(ctx, SearchOptions{Take: 25, Filter: Filters{F("login_username", FilterEqualsString, "bob")}},
		ConnectionLogSort{Selector: "starttime", Desc: true})
	if err != nil || res.TotalCount != 7 || res.Data[0]["ssid"] != "s1" {
		t.Fatalf("%+v %v", res, err)
	}
	ev, err := c.ConnectionLogs.ListEvents(ctx, SearchOptions{Take: 50})
	if err != nil || ev.TotalCount != 2 {
		t.Fatalf("%+v %v", ev, err)
	}
	r := *reqs
	if r[0].Method != "PUT" || r[0].Path != "/api/v1/search/connection_log" ||
		!reflect.DeepEqual(r[0].Body["sort"], []any{map[string]any{"selector": "starttime", "desc": true}}) ||
		!reflect.DeepEqual(r[0].Body["filter"], map[string]any{"0": []any{"login_username", "equals", "bob"}}) {
		t.Errorf("list: %+v", r[0].Body)
	}
	if _, ok := r[1].Body["filter"]; ok || r[1].Body["sort"] != nil {
		t.Errorf("events: %+v", r[1].Body)
	}
}

func TestConnectionLogGet(t *testing.T) {
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if strings.HasPrefix(r.Path, "/api/v1/ssh/") {
			return []byte("{\"version\": 2}\n[0.1, \"o\", \"hi\"]\n")
		}
		return Params{"ssid": "a/b", "ssh_streams": []any{}}
	})
	ctx := context.Background()
	row, err := c.ConnectionLogs.Get(ctx, "a/b", true)
	if err != nil || row["ssid"] != "a/b" {
		t.Fatalf("%v %v", row, err)
	}
	cast, err := c.ConnectionLogs.SSHSessionLog(ctx, "a/b", nil)
	if err != nil || !strings.Contains(cast, `"o"`) {
		t.Fatalf("%q %v", cast, err)
	}
	r := *reqs
	if r[0].Path != "/api/v1/connection_log/a%2Fb" || r[0].Query != "ssh_streams=y" {
		t.Errorf("get: %+v", r[0])
	}
	if r[1].Path != "/api/v1/ssh/a%2Fb" {
		t.Errorf("log: %+v", r[1])
	}
}

func TestConnectionLogDownloadSSHVideo(t *testing.T) {
	sse := "event: progress\r\ndata: {\"percent\": 50, \"message\": \"half\"}\r\n\r\ndata: not json\n\n" +
		"data: {\"percent\":100,\"message\":\"done\",\"done\":true,\"url\":\"/api/v1/ssh/video/download/x.mp4?t=1\"}\n"
	c, reqs := newTestClient(t, func(r recordedRequest) any {
		if strings.HasSuffix(r.Path, "/video/encode") {
			return []byte(sse)
		}
		return []byte("....ftypisom")
	})
	var progress []string
	buf, err := c.ConnectionLogs.DownloadSSHVideo(context.Background(), "s1", "3",
		SSHVideoEncodeOptions{Theme: "dracula", Quality: "low", Speed: 8},
		func(p float64, m string) { progress = append(progress, m) })
	if err != nil || string(buf) != "....ftypisom" {
		t.Fatalf("%q %v", buf, err)
	}
	if !reflect.DeepEqual(progress, []string{"half", "done"}) {
		t.Errorf("progress: %v", progress)
	}
	r := *reqs
	q, _ := url.ParseQuery(r[0].Query)
	if r[0].Method != "GET" || r[0].Path != "/api/v1/ssh/s1/video/encode" || q.Get("stream_id") != "3" ||
		q.Get("theme") != "dracula" || q.Get("speed") != "8" || q.Has("fps") {
		t.Errorf("encode: %+v", r[0])
	}
	if r[1].Path != "/api/v1/ssh/video/download/x.mp4" || r[1].Query != "t=1" {
		t.Errorf("download: %+v", r[1])
	}
}

func TestConnectionLogSSEErrors(t *testing.T) {
	if _, err := connectionLogReadSSE(strings.NewReader("data: {\"error\":\"boom\"}\n"), nil); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("error event: %v", err)
	}
	if _, err := connectionLogReadSSE(strings.NewReader("data: {\"percent\":1}"), nil); err == nil {
		t.Error("expected end-of-stream error")
	}
	if u, err := connectionLogReadSSE(strings.NewReader("data: {\"done\":true,\"url\":\"/x\"}"), nil); err != nil || u != "/x" {
		t.Errorf("unterminated last line: %q %v", u, err)
	}
}

func TestConnectionLogToken(t *testing.T) {
	cases := map[string]string{
		`"abc"`:                  "abc",
		`{"token":"t1"}`:         "t1",
		`{"download_token":"d"}`: "d",
		`null`:                   "",
		`plain`:                  "plain",
	}
	for in, want := range cases {
		if got := connectionLogToken(json.RawMessage(in)); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}
