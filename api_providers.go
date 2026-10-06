package mamori

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

//
// Authentication providers
//

// ListProviders lists the authentication providers. TS: providers().
func (c *Client) ListProviders(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/providers", nil)
}

// GetProvider returns the named provider (the name is lower-cased).
func (c *Client) GetProvider(ctx context.Context, name string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/providers/"+pathEscape(strings.ToLower(name)), nil)
}

// GetProviderOptions returns the provider configuration options.
func (c *Client) GetProviderOptions(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/providers?options=y", nil)
}

// AddProvider creates a provider.
func (c *Client) AddProvider(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/providers", options)
}

// UpdateProvider updates the named provider.
func (c *Client) UpdateProvider(ctx context.Context, name string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/providers/"+name, options)
}

// DropProvider deletes the named provider.
func (c *Client) DropProvider(ctx context.Context, name string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/providers/"+name, nil)
}

// ValidateProvider checks username/password against provider.
func (c *Client) ValidateProvider(ctx context.Context, provider, username, password string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/provider/validate", Params{
		"provider": provider,
		"username": username,
		"password": password,
	})
}

// SetDefaultProviderChain sets the default provider chain.
func (c *Client) SetDefaultProviderChain(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/defaults/provider", options)
}

// EnableProvider enables the named provider of the given type.
func (c *Client) EnableProvider(ctx context.Context, name, providerType string) (json.RawMessage, error) {
	return c.UpdateProvider(ctx, name, Params{"name": name, "type": providerType, "enabled": "true"})
}

// DisableProvider disables the named provider of the given type.
func (c *Client) DisableProvider(ctx context.Context, name, providerType string) (json.RawMessage, error) {
	return c.UpdateProvider(ctx, name, Params{"name": name, "type": providerType, "enabled": "false"})
}

//
// TOTP
//

// SetTOTPCacheTime sets the TOTP cache time.
func (c *Client) SetTOTPCacheTime(ctx context.Context, time int) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/defaults/totpcachetime/"+strconv.Itoa(time), nil)
}

// SetTOTPProperties sets the TOTP validity period in seconds and issuer URL.
func (c *Client) SetTOTPProperties(ctx context.Context, seconds int, url string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/defaults/totpproperties", Params{"seconds": seconds, "url": url})
}

//
// LDAP
//

// LDAPSearch searches an LDAP directory.
func (c *Client) LDAPSearch(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/ldap/search/", options)
}

//
// Agents
//

// Agents lists agents.
func (c *Client) Agents(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/agents", nil)
}

// AgentDrop deletes the named agent.
func (c *Client) AgentDrop(ctx context.Context, agentName string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/agents/"+pathEscape(agentName), nil)
}

// AgentCreate creates an agent from agentParams, which is sent as the JSON
// body.
func (c *Client) AgentCreate(ctx context.Context, agentParams any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/agents", agentParams)
}
