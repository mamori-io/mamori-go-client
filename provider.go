package mamori

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// Provider is an authentication provider record.
type Provider struct {
	ProviderName string `json:"provider_name"`
	ProviderType string `json:"provider_type"`
	IsWebBased   string `json:"is_web_based"`
	IsMFA        string `json:"is_mfa"`
	IsInternal   string `json:"is_internal"`
	IsDirectory  string `json:"is_directory"`
	IsDefault    string `json:"is_default"`
	Image        any    `json:"image"`
	Properties   Params `json:"properties"`
}

// DUOProvider is a Duo Security authentication provider.
type DUOProvider struct {
	Provider
}

// List returns all authentication providers.
func (s *ProviderService) List(ctx context.Context) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, "/v1/providers", nil)
}

// Get returns the named authentication provider.
func (s *ProviderService) Get(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, "/v1/providers/"+pathEscape(strings.ToLower(name)), nil)
}
