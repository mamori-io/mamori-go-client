package mamori

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
)

// SearchRemoteDesktops searches remote desktop logins.
func (c *Client) SearchRemoteDesktops(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/rdp", options)
}

// GetRemoteDesktopDetails returns a remote desktop login's details.
func (c *Client) GetRemoteDesktopDetails(ctx context.Context, name string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/rdp/"+name, nil)
}

// CreateRemoteDesktop creates a remote desktop login.
func (c *Client) CreateRemoteDesktop(ctx context.Context, name string, details any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/rdp/", Params{"name": name, "details": details})
}

// UpdateRemoteDesktop updates a remote desktop login.
func (c *Client) UpdateRemoteDesktop(ctx context.Context, id int64, name string, details any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/rdp/"+strconv.FormatInt(id, 10), Params{"name": name, "details": details})
}

// GetRemoteDesktopToken returns a connection token for a remote desktop
// login.
func (c *Client) GetRemoteDesktopToken(ctx context.Context, name string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/rdp/"+name+"/token", nil)
}

// GetRemoteDesktopDownloadToken returns a token for downloading a session
// recording, for use with [Client.RemoteDesktopDownloadLink].
func (c *Client) GetRemoteDesktopDownloadToken(ctx context.Context, recordingID int64, tokenType string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/rdp/"+strconv.FormatInt(recordingID, 10)+"/download/"+tokenType, nil)
}

// DeleteRemoteDesktop deletes a remote desktop login.
func (c *Client) DeleteRemoteDesktop(ctx context.Context, name string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/rdp/"+name, nil)
}
