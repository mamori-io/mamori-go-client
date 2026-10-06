package mamori

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// WireguardPeer is a user's wireguard device.
type WireguardPeer struct {
	// ID is assigned by the server; it is required by update, delete, lock
	// and unlock.
	ID         string `json:"id"`
	UserID     string `json:"userid"`
	DeviceName string `json:"device_name"`
	// AllocatedIPAddress is the peer's address; empty lets the server
	// allocate one.
	AllocatedIPAddress string `json:"allocated_ip_address"`
	// PublicKey is the peer's public key; empty lets the server generate a
	// key pair.
	PublicKey string `json:"public_key"`
}

// NewWireguardPeer returns a peer for the given user and device name.
func NewWireguardPeer(userID, deviceName string) *WireguardPeer {
	return &WireguardPeer{UserID: userID, DeviceName: deviceName}
}

// UnmarshalJSON decodes a peer record, tolerating numeric ids and nulls.
func (p *WireguardPeer) UnmarshalJSON(b []byte) error {
	return looseUnmarshal(b, p)
}

// MarshalJSON encodes the peer, sending empty optional fields (id,
// allocated_ip_address, public_key) as null like the TypeScript SDK.
func (p WireguardPeer) MarshalJSON() ([]byte, error) {
	return json.Marshal(wireguardPeerParams(&p))
}

func wireguardNullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func wireguardPeerParams(p *WireguardPeer) Params {
	return Params{
		"device_name":          p.DeviceName,
		"userid":               p.UserID,
		"allocated_ip_address": wireguardNullable(p.AllocatedIPAddress),
		"public_key":           wireguardNullable(p.PublicKey),
		"id":                   wireguardNullable(p.ID),
	}
}

// WireguardPeerCreateResult is the response to creating a peer.
type WireguardPeerCreateResult struct {
	Peer WireguardPeer `json:"peer"`
	// PrivateKey is set when the server generated the key pair.
	PrivateKey string `json:"private_key"`
	// Config is the wireguard client configuration for the device.
	Config string `json:"config"`
}

var errWireguardNoID = errors.New("mamori: wireguard peer id not specified")

// List searches wireguard peers. Each returned row has its public_key
// converted from hex to base64 and a "name" field of "<userid>-<device_name>"
// added.
func (s *WireguardPeerService) List(ctx context.Context, opts SearchOptions) (*SearchResult[Params], error) {
	var res SearchResult[Params]
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/wireguard", ipResourceSearchParams(opts), &res); err != nil {
		return nil, err
	}
	for _, row := range res.Data {
		if k, ok := row["public_key"].(string); ok {
			if b, err := hex.DecodeString(k); err == nil {
				row["public_key"] = base64.StdEncoding.EncodeToString(b)
			}
		}
		row["name"] = fmt.Sprintf("%v-%v", row["userid"], row["device_name"])
	}
	return &res, nil
}

// DisconnectUser disconnects all of username's wireguard peers.
func (s *WireguardPeerService) DisconnectUser(ctx context.Context, username string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/wireguard/disconnect_user/"+pathEscape(username), nil)
}

// Create creates the peer. If p.PublicKey is empty the server generates a
// key pair and returns the private key.
func (s *WireguardPeerService) Create(ctx context.Context, p *WireguardPeer) (*WireguardPeerCreateResult, error) {
	var res WireguardPeerCreateResult
	if err := s.client.CallInto(ctx, http.MethodPost, "/v1/wireguard", Params{"peer": wireguardPeerParams(p)}, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Delete deletes the peer with the given id.
func (s *WireguardPeerService) Delete(ctx context.Context, id string) (json.RawMessage, error) {
	if id == "" {
		return nil, errWireguardNoID
	}
	return s.client.Call(ctx, http.MethodDelete, "/v1/wireguard/"+pathEscape(id), nil)
}

// Update updates the peer identified by p.ID.
func (s *WireguardPeerService) Update(ctx context.Context, p *WireguardPeer) (json.RawMessage, error) {
	if p.ID == "" {
		return nil, errWireguardNoID
	}
	return s.client.Call(ctx, http.MethodPut, "/v1/wireguard/"+pathEscape(p.ID), Params{"peer": wireguardPeerParams(p)})
}

// Reset regenerates the peer's keys and configuration. If notify is true the
// new configuration is sent to the user. The update response (which holds
// the new "config") is returned.
func (s *WireguardPeerService) Reset(ctx context.Context, p *WireguardPeer, notify bool) (json.RawMessage, error) {
	if p.ID == "" {
		return nil, errWireguardNoID
	}
	peer := Params{"id": p.ID, "userid": p.UserID, "device_name": p.DeviceName}
	raw, err := s.client.Call(ctx, http.MethodPut, "/v1/wireguard/"+pathEscape(p.ID), Params{"peer": peer})
	if err != nil {
		return nil, err
	}
	if notify {
		var res struct {
			Config string `json:"config"`
		}
		if err := decode(raw, &res); err != nil {
			return nil, err
		}
		if _, err := s.SendNotification(ctx, p.UserID, p.DeviceName, res.Config); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// SendNotification sends a wireguard configuration to a user's device.
func (s *WireguardPeerService) SendNotification(ctx context.Context, username, deviceName, config string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, "/v1/wireguard/notify", Params{
		"username":    username,
		"device_name": deviceName,
		"config":      config,
	})
}

// Lock locks the peer with the given id.
func (s *WireguardPeerService) Lock(ctx context.Context, id string) (json.RawMessage, error) {
	if id == "" {
		return nil, errWireguardNoID
	}
	return s.client.Call(ctx, http.MethodPut, "/v1/wireguard/"+pathEscape(id)+"/lock", nil)
}

// Unlock unlocks the peer with the given id.
func (s *WireguardPeerService) Unlock(ctx context.Context, id string) (json.RawMessage, error) {
	if id == "" {
		return nil, errWireguardNoID
	}
	return s.client.Call(ctx, http.MethodPut, "/v1/wireguard/"+pathEscape(id)+"/unlock", nil)
}

// Disconnect disconnects the peer with the given (base64) public key.
func (s *WireguardPeerService) Disconnect(ctx context.Context, publicKey string) (json.RawMessage, error) {
	if publicKey == "" {
		return nil, errors.New("mamori: wireguard public key not specified")
	}
	return s.client.Call(ctx, http.MethodDelete, "/v1/wireguard/"+pathEscape(publicKey)+"/disconnect", nil)
}
