package mamori

import (
	"context"
	"encoding/json"
	"net/http"
)

// GetSecrets searches secrets.
func (c *Client) GetSecrets(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/secrets/", options)
}

// GetSecret returns a secret by id or name.
func (c *Client) GetSecret(ctx context.Context, id string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/secrets/"+id, nil)
}

// GetSecretParts returns the parts of a secret.
func (c *Client) GetSecretParts(ctx context.Context, id string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/secrets/"+id+"/parts", nil)
}

// RevealSecret returns a secret including its secret value.
func (c *Client) RevealSecret(ctx context.Context, id string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/secrets/"+id+"/reveal", nil)
}

// CreateSecret creates a secret.
func (c *Client) CreateSecret(ctx context.Context, secret any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/secrets/", Params{"secret": secret})
}

// RestoreSecret restores a secret exported with [Client.ExportSecret]. key is
// the export key, or "" if none was used.
func (c *Client) RestoreSecret(ctx context.Context, secret any, key string) (json.RawMessage, error) {
	p := Params{"restore": true, "secret": secret}
	if key != "" {
		p["key"] = key
	}
	return c.Call(ctx, http.MethodPost, "/v1/secrets/", p)
}

// ExportSecret exports a secret, optionally protected with key ("" for none).
func (c *Client) ExportSecret(ctx context.Context, name, key string) (json.RawMessage, error) {
	path := "/v1/secrets/" + pathEscape(name) + "/export"
	if key != "" {
		path += "?key=" + pathEscape(key)
	}
	return c.Call(ctx, http.MethodGet, path, nil)
}

// UpdateSecret updates a secret.
func (c *Client) UpdateSecret(ctx context.Context, id string, secret any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/secrets/"+id, Params{"secret": secret})
}

// DeleteSecret deletes a secret.
func (c *Client) DeleteSecret(ctx context.Context, id string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/secrets/"+id, nil)
}

// ResetSecretAlert resets the expiry alert time of a secret.
func (c *Client) ResetSecretAlert(ctx context.Context, id, alertAt string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/secrets/"+id+"/reset_alert", Params{"alert_at": alertAt})
}
