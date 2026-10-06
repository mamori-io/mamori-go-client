package mamori

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ConnectionLogSort orders connection log search results.
type ConnectionLogSort struct {
	Selector string `json:"selector"`
	Desc     bool   `json:"desc,omitempty"`
}

// SSHVideoEncodeOptions controls SSH session video encoding. Zero values
// leave the server defaults (see [ConnectionLogService.SSHVideoOptions]).
type SSHVideoEncodeOptions struct {
	Theme     string
	FontSize  int
	Speed     float64
	Idle      float64
	FPS       int
	Quality   string
	VideoName string
}

func (o SSHVideoEncodeOptions) params() Params {
	p := Params{}
	set := func(k, v string) {
		if v != "" {
			p[k] = v
		}
	}
	num := func(k string, v float64) {
		if v != 0 {
			p[k] = strconv.FormatFloat(v, 'f', -1, 64)
		}
	}
	set("theme", o.Theme)
	num("font_size", float64(o.FontSize))
	num("speed", o.Speed)
	num("idle", o.Idle)
	num("fps", float64(o.FPS))
	set("quality", o.Quality)
	set("video_name", o.VideoName)
	return p
}

// SSHVideoProgress receives encoding progress updates.
type SSHVideoProgress func(percent float64, message string)

// List searches past connections (sessions). sort is optional.
func (s *ConnectionLogService) List(ctx context.Context, opts SearchOptions, sort ...ConnectionLogSort) (*SearchResult[Row], error) {
	p := opts.params()
	if len(sort) > 0 {
		p["sort"] = sort
	}
	return connectionLogSearch(s.client.Call(ctx, http.MethodPut, "/v1/search/connection_log", p))
}

// ListEvents searches connection and authentication events.
func (s *ConnectionLogService) ListEvents(ctx context.Context, opts SearchOptions) (*SearchResult[Row], error) {
	return connectionLogSearch(s.client.Call(ctx, http.MethodPut, "/v1/search/connection_events", opts.params()))
}

// connectionLogSearch decodes a {data,totalCount} search response, also
// accepting a bare array of rows.
func connectionLogSearch(raw json.RawMessage, err error) (*SearchResult[Row], error) {
	if err != nil {
		return nil, err
	}
	var res SearchResult[Row]
	if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] == '[' {
		if err := decode(raw, &res.Data); err != nil {
			return nil, err
		}
		res.TotalCount = Count(len(res.Data))
		return &res, nil
	}
	if err := decode(raw, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Get returns a single connection by session id. With sshStreams the SSH
// stream metadata (including kind) is included under "ssh_streams".
func (s *ConnectionLogService) Get(ctx context.Context, ssid string, sshStreams bool) (Row, error) {
	path := "/v1/connection_log/" + pathEscape(ssid)
	if sshStreams {
		path += "?ssh_streams=y"
	}
	var row Row
	if err := s.client.CallInto(ctx, http.MethodGet, path, nil, &row); err != nil {
		return nil, err
	}
	return row, nil
}

// SSHSessionLog returns the asciinema cast text (or filtered events) of an SSH
// session. options may be nil.
func (s *ConnectionLogService) SSHSessionLog(ctx context.Context, ssid string, options Params) (string, error) {
	var params any
	if options != nil {
		params = options
	}
	raw, err := s.client.Call(ctx, http.MethodGet, "/v1/ssh/"+pathEscape(ssid), params)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// SSHVideoOptions returns the SSH video encoding option catalog (themes,
// defaults, ...).
func (s *ConnectionLogService) SSHVideoOptions(ctx context.Context) (Params, error) {
	var p Params
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/ssh/video/options", nil, &p); err != nil {
		return nil, err
	}
	return p, nil
}

// DownloadSSHVideo encodes an SSH shell stream to MP4, reporting progress
// from the server-sent event stream to progress (which may be nil), then
// downloads and returns the video bytes.
func (s *ConnectionLogService) DownloadSSHVideo(ctx context.Context, ssid, streamID string, opts SSHVideoEncodeOptions, progress SSHVideoProgress) ([]byte, error) {
	params := opts.params()
	params["stream_id"] = streamID
	stream, err := s.client.CallStream(ctx, http.MethodGet, "/v1/ssh/"+pathEscape(ssid)+"/video/encode", params)
	if err != nil {
		return nil, err
	}
	url, err := connectionLogReadSSE(stream, progress)
	stream.Close()
	if err != nil {
		return nil, err
	}
	return s.client.CallBinary(ctx, http.MethodGet, url, nil)
}

// connectionLogReadSSE consumes encode events until one reports the download
// URL.
func connectionLogReadSSE(r io.Reader, progress SSHVideoProgress) (string, error) {
	br := bufio.NewReader(r)
	for {
		line, readErr := br.ReadString('\n')
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if strings.HasPrefix(line, "data:") {
			var ev struct {
				Error   any             `json:"error"`
				Percent json.RawMessage `json:"percent"`
				Message string          `json:"message"`
				Done    bool            `json:"done"`
				URL     string          `json:"url"`
			}
			if json.Unmarshal([]byte(strings.TrimSpace(line[len("data:"):])), &ev) == nil {
				if ev.Error != nil && ev.Error != false && ev.Error != "" {
					return "", fmt.Errorf("mamori: SSH video encode: %v", ev.Error)
				}
				if pct, err := strconv.ParseFloat(string(ev.Percent), 64); err == nil && ev.Message != "" && progress != nil {
					progress(pct, ev.Message)
				}
				if ev.Done && ev.URL != "" {
					return ev.URL, nil
				}
			}
		}
		if readErr == io.EOF {
			return "", errors.New("mamori: SSH video encode ended without a download URL")
		}
		if readErr != nil {
			return "", readErr
		}
	}
}

// DownloadRDPVideo prepares a remote desktop recording for download and
// returns its URL (under /rdp/stream/). tokenType defaults to "mp4".
// progress may be nil.
func (s *ConnectionLogService) DownloadRDPVideo(ctx context.Context, recordingID int64, tokenType string, progress RemoteDesktopDownloadProgress) (string, error) {
	if tokenType == "" {
		tokenType = "mp4"
	}
	raw, err := s.client.Call(ctx, http.MethodGet, "/v1/rdp/"+strconv.FormatInt(recordingID, 10)+"/download/"+tokenType, nil)
	if err != nil {
		return "", err
	}
	token := connectionLogToken(raw)
	if token == "" {
		return "", errors.New("mamori: session recording is not available")
	}
	return s.client.RemoteDesktopDownloadLink(ctx, token, progress)
}

// connectionLogToken extracts a download token from a bare string or an
// object with "token" or "download_token".
func connectionLogToken(raw json.RawMessage) string {
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || string(t) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(t, &s) == nil {
		return s
	}
	var obj struct {
		Token         string `json:"token"`
		DownloadToken string `json:"download_token"`
	}
	if t[0] == '{' && json.Unmarshal(t, &obj) == nil {
		if obj.Token != "" {
			return obj.Token
		}
		return obj.DownloadToken
	}
	return string(t)
}
