package mamori

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// NetworkType identifies the kind of network.
type NetworkType string

// Network types.
const (
	NetworkTypeIPSec   NetworkType = "ipsec"
	NetworkTypeOpenVPN NetworkType = "openvpn"
	NetworkTypeSSH     NetworkType = "ssh"
)

// Network holds the settings common to every network type. It is embedded
// in [IPSecVPN], [OpenVPN] and [SSHTunnel].
type Network struct {
	// Name is the unique network name. Network names are lower case.
	Name string `json:"name"`
	// Type is the network type.
	Type NetworkType `json:"type"`
}

// NetworkBase returns the common network settings.
func (n *Network) NetworkBase() *Network { return n }

// NetworkSecret is a named secret value sent when creating a network.
type NetworkSecret struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// NetworkConfig is implemented by the concrete network types (*IPSecVPN,
// *OpenVPN, *SSHTunnel) and is what [NetworkService.Create] accepts.
type NetworkConfig interface {
	// NetworkBase returns the common network settings.
	NetworkBase() *Network
	// Config returns the network specific configuration.
	Config() Params
	// Secrets returns the network secrets.
	Secrets() []NetworkSecret
}

// networkSet adds v to p unless it is the zero value (the TypeScript SDK
// sends undefined fields, which JSON drops).
func networkSet[T comparable](p Params, key string, v T) {
	var zero T
	if v != zero {
		p[key] = v
	}
}

// IPSecVPN is a network connection over an IPSec VPN.
type IPSecVPN struct {
	Network
	// Host is the VPN server address.
	Host string `json:"host,omitempty"`
	// User and Password are the VPN credentials.
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	// PSK is the pre-shared key.
	PSK string `json:"psk,omitempty"`
}

// NewIPSecVPN returns an IPSec network with the given (lower cased) name.
func NewIPSecVPN(name string) *IPSecVPN {
	return &IPSecVPN{Network: Network{Name: strings.ToLower(name), Type: NetworkTypeIPSec}}
}

// Config implements [NetworkConfig].
func (v *IPSecVPN) Config() Params {
	p := Params{}
	networkSet(p, "username", v.User)
	networkSet(p, "host", v.Host)
	return p
}

// Secrets implements [NetworkConfig].
func (v *IPSecVPN) Secrets() []NetworkSecret {
	return []NetworkSecret{{Name: "password", Value: v.Password}, {Name: "psk", Value: v.PSK}}
}

// OpenVPN is a network connection over OpenVPN.
type OpenVPN struct {
	Network
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	// Transport is "udp" (default) or "tcp".
	Transport string `json:"transport,omitempty"`
	// NetworkDevice is "tun" (default) or "tap".
	NetworkDevice string `json:"network,omitempty"`
	// KeyDirection is "", "0" or "1".
	KeyDirection string `json:"keyDirection,omitempty"`
	// Compression is "yes" (default), "no" or "".
	Compression string `json:"compression,omitempty"`
	TLSClient   bool   `json:"tls_client,omitempty"`
	CACert      string `json:"ca_crt,omitempty"`
	TACert      string `json:"ta_crt,omitempty"`
	ClientCert  string `json:"client_crt,omitempty"`
	ClientKey   string `json:"client_key,omitempty"`
}

// NewOpenVPN returns an OpenVPN network with the given (lower cased) name
// and the default transport (udp), device (tun) and compression (yes).
func NewOpenVPN(name string) *OpenVPN {
	return &OpenVPN{
		Network:       Network{Name: strings.ToLower(name), Type: NetworkTypeOpenVPN},
		Transport:     "udp",
		NetworkDevice: "tun",
		Compression:   "yes",
	}
}

// Config implements [NetworkConfig].
func (v *OpenVPN) Config() Params {
	p := Params{"tls_client": v.TLSClient}
	networkSet(p, "host", v.Host)
	networkSet(p, "port", v.Port)
	networkSet(p, "transport", v.Transport)
	networkSet(p, "network", v.NetworkDevice)
	networkSet(p, "compression", v.Compression)
	networkSet(p, "key_direction", v.KeyDirection)
	return p
}

// Secrets implements [NetworkConfig].
func (v *OpenVPN) Secrets() []NetworkSecret {
	return []NetworkSecret{
		{Name: "vpn-user", Value: v.User},
		{Name: "vpn-password", Value: v.Password},
		{Name: "vpn-ca", Value: v.CACert},
		{Name: "vpn-ta", Value: v.TACert},
		{Name: "vpn-client-cert", Value: v.ClientCert},
		{Name: "vpn-client-key", Value: v.ClientKey},
	}
}

// SSHTunnel is a network connection through an SSH tunnel: connections to
// LocalPort on the mamori server are forwarded via the SSH server at
// Host:Port to RemoteHost:RemotePort.
type SSHTunnel struct {
	Network
	// Host and Port address the SSH server.
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	// User is the SSH login.
	User string `json:"user,omitempty"`
	// PrivateKeyID is the name of an existing SSH key used to log in.
	PrivateKeyID string `json:"privateKeyId,omitempty"`
	LocalPort    int    `json:"localPort,omitempty"`
	RemoteHost   string `json:"remoteHost,omitempty"`
	RemotePort   int    `json:"remotePort,omitempty"`
}

// NewSSHTunnel returns an SSH tunnel network with the given (lower cased)
// name.
func NewSSHTunnel(name string) *SSHTunnel {
	return &SSHTunnel{Network: Network{Name: strings.ToLower(name), Type: NetworkTypeSSH}}
}

// Config implements [NetworkConfig].
func (v *SSHTunnel) Config() Params {
	p := Params{}
	networkSet(p, "username", v.User)
	networkSet(p, "host", v.Host)
	networkSet(p, "port", v.Port)
	networkSet(p, "localPort", v.LocalPort)
	networkSet(p, "remoteHost", v.RemoteHost)
	networkSet(p, "remotePort", v.RemotePort)
	return p
}

// Secrets implements [NetworkConfig].
func (v *SSHTunnel) Secrets() []NetworkSecret {
	return []NetworkSecret{{Name: "privateKeyId", Value: v.PrivateKeyID}}
}

// GetAll returns all networks.
func (s *NetworkService) GetAll(ctx context.Context) ([]Row, error) {
	raw, err := s.client.Call(ctx, http.MethodGet, "/v1/vpns", nil)
	if err != nil {
		return nil, err
	}
	return decodeRows(raw)
}

// Create creates and starts the network. The server answers "started".
func (s *NetworkService) Create(ctx context.Context, n NetworkConfig) (json.RawMessage, error) {
	b := n.NetworkBase()
	return s.client.Call(ctx, http.MethodPost, "/v1/vpns", Params{
		"vpn": Params{
			"name":    b.Name,
			"type":    b.Type,
			"config":  n.Config(),
			"secrets": n.Secrets(),
		},
	})
}

func networkPath(name string) string {
	return "/v1/vpns/" + pathEscape(strings.ToLower(name))
}

// Delete deletes the named network. The server answers "ok".
func (s *NetworkService) Delete(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, networkPath(name), nil)
}

// Start starts the named network.
func (s *NetworkService) Start(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, networkPath(name)+"/start", nil)
}

// Stop stops the named network.
func (s *NetworkService) Stop(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, networkPath(name)+"/stop", nil)
}

// Status returns the status of the named network.
func (s *NetworkService) Status(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, networkPath(name)+"/status", nil)
}

// ConnectionLog returns the connection log of the named network.
func (s *NetworkService) ConnectionLog(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, networkPath(name)+"/logs", nil)
}
