package mamori

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/coder/websocket"
)

// ServiceStatus reports which server daemons are running.
type ServiceStatus struct {
	Webd   bool `json:"webd"`
	Fqod   bool `json:"fqod"`
	Derbyd bool `json:"derbyd"`
	Rdbmsd bool `json:"rdbmsd"`
}

// Ping checks connectivity and that the session is valid.
func (c *Client) Ping(ctx context.Context) (bool, error) {
	var resp struct {
		Pong bool `json:"pong"`
	}
	err := c.CallInto(ctx, http.MethodGet, "/v1/ping", nil, &resp)
	return resp.Pong, err
}

// ServiceStatus returns the status of the server daemons. It does not require
// a session.
func (c *Client) ServiceStatus(ctx context.Context) (*ServiceStatus, error) {
	raw, err := c.doRequest(ctx, http.MethodGet, "/status", nil, nil, "")
	if err != nil {
		return nil, err
	}
	var s ServiceStatus
	return &s, decode(raw, &s)
}

// ChangePassword changes the current user's password.
func (c *Client) ChangePassword(ctx context.Context, oldPassword, newPassword string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/change_password", Params{
		"old_password": oldPassword,
		"new_password": newPassword,
	})
}

// Select executes a SQL statement through the REST query endpoint and returns
// the resulting rows. searchQuery may be nil.
func (c *Client) Select(ctx context.Context, sql string, searchQuery ...any) ([]Row, error) {
	p := Params{"sql": sql}
	if len(searchQuery) > 0 {
		p["search_query"] = searchQuery[0]
	}
	raw, err := c.Call(ctx, http.MethodPost, "/v1/query", p)
	if err != nil {
		return nil, err
	}
	return decodeRows(raw)
}

// SelectRaw is like [Client.Select] but returns the undecoded response.
func (c *Client) SelectRaw(ctx context.Context, sql string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/query", Params{"sql": sql})
}

// CallOperation invokes a named server query operation.
func (c *Client) CallOperation(ctx context.Context, operation string, filter any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/query", Params{"operation": operation, "filter": filter})
}

// decodeRows decodes a query response. Statements that return no result set
// may yield a non-array body, which decodes as no rows.
func decodeRows(raw json.RawMessage) ([]Row, error) {
	var rows []Row
	if err := json.Unmarshal(raw, &rows); err != nil {
		var ute *json.UnmarshalTypeError
		if errors.As(err, &ute) {
			return nil, nil
		}
		return nil, err
	}
	return rows, nil
}

// firstRow returns rows[0] or nil.
func firstRow(rows []Row, err error) (Row, error) {
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

// firstElement decodes a JSON array response and returns its first element
// (the TypeScript SDK's frequent `res[0]`). A non-array response is returned
// unchanged.
func firstElement(raw json.RawMessage, err error) (json.RawMessage, error) {
	if err != nil {
		return nil, err
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil {
		return raw, nil
	}
	if len(arr) == 0 {
		return nil, nil
	}
	return arr[0], nil
}

// RemoteDesktopDownloadProgress is called with status updates while a
// recording is prepared for download. percent is negative when unknown.
type RemoteDesktopDownloadProgress func(message string, percent float64)

// RemoteDesktopDownloadLink prepares a remote desktop recording for download
// using a token from [Client.GetRemoteDesktopDownloadToken] and returns the
// URL it can be fetched from.
func (c *Client) RemoteDesktopDownloadLink(ctx context.Context, token string, progress RemoteDesktopDownloadProgress) (string, error) {
	u := httpScheme.ReplaceAllString(c.BaseURL(), "ws") + "/rdp/tunnel?" + token
	conn, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: c.httpClient})
	if err != nil {
		return "", err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(-1)
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return "", err
		}
		msg, err := DecodeMessage(string(data))
		if err != nil {
			continue
		}
		switch msg.Command {
		case "_status":
			if progress != nil && len(msg.Params) > 0 {
				pct := -1.0
				if len(msg.Params) > 1 {
					if f, err := strconv.ParseFloat(msg.Params[1], 64); err == nil {
						pct = f
					}
				}
				progress(msg.Params[0], pct)
			}
		case "_download":
			if len(msg.Params) > 0 {
				return c.BaseURL() + "/rdp/stream/" + msg.Params[0], nil
			}
		case "error":
			if len(msg.Params) > 0 {
				return "", errors.New("mamori: " + msg.Params[0])
			}
			return "", errors.New("mamori: remote desktop download failed")
		}
	}
}
