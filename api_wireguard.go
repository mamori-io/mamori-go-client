package mamori

import (
	"context"
	"encoding/json"
	"net/http"
)

// SearchWireguardPeers searches WireGuard peers.
func (c *Client) SearchWireguardPeers(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/wireguard", options)
}

// CreateWireguardPeer creates a WireGuard peer. peer is encoded as JSON (a
// map or struct with userid, device_name, public_key and
// allocated_ip_address). The response contains the created peer and, when
// the server generated the key pair, its private_key.
func (c *Client) CreateWireguardPeer(ctx context.Context, peer any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/wireguard", Params{"peer": peer})
}

// UpdateWireguardPeer updates a WireGuard peer. peer must have an "id" field
// when JSON encoded.
func (c *Client) UpdateWireguardPeer(ctx context.Context, peer any) (json.RawMessage, error) {
	id, err := policiesObjectID(peer)
	if err != nil {
		return nil, err
	}
	return c.Call(ctx, http.MethodPut, "/v1/wireguard/"+id, Params{"peer": peer})
}

// SendWireguardNotification emails a WireGuard configuration to a user.
func (c *Client) SendWireguardNotification(ctx context.Context, username, deviceName, config string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/wireguard/notify", Params{
		"username":    username,
		"device_name": deviceName,
		"config":      config,
	})
}

// LockWireguardPeer locks a WireGuard peer.
func (c *Client) LockWireguardPeer(ctx context.Context, id string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/wireguard/"+id+"/lock", nil)
}

// UnlockWireguardPeer unlocks a WireGuard peer.
func (c *Client) UnlockWireguardPeer(ctx context.Context, id string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/wireguard/"+id+"/unlock", nil)
}

// DeleteWireguardPeer deletes a WireGuard peer.
func (c *Client) DeleteWireguardPeer(ctx context.Context, id string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/wireguard/"+id, nil)
}

// WireguardDisconnectUser disconnects all of a user's WireGuard peers.
func (c *Client) WireguardDisconnectUser(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/wireguard/disconnect_user/"+username, nil)
}

// WireguardDisconnectPeer disconnects the WireGuard peer with the given
// public key.
func (c *Client) WireguardDisconnectPeer(ctx context.Context, peerPublicKey string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/wireguard/"+pathEscape(peerPublicKey)+"/disconnect", nil)
}

// GetWireguardLog returns the WireGuard log.
func (c *Client) GetWireguardLog(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/wireguard/log", nil)
}

// GetWireguardStatus returns the WireGuard interface status.
func (c *Client) GetWireguardStatus(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/wireguard/status", nil)
}

// GetWireguardPeers returns all WireGuard peers.
func (c *Client) GetWireguardPeers(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/wireguard/all", nil)
}

// ReloadWireguardConfig reloads the WireGuard configuration.
func (c *Client) ReloadWireguardConfig(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/wireguard/reload", nil)
}
