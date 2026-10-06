package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// AuthProvider names a built-in authentication provider.
type AuthProvider string

// Built-in authentication providers.
const (
	AuthProviderAdmin      AuthProvider = "admin"
	AuthProviderPushMobile AuthProvider = "pushmobile"
	AuthProviderPushTOTP   AuthProvider = "pushtotp"
	AuthProviderYubiKey    AuthProvider = "yubikey"
	AuthProviderTOTP       AuthProvider = "totp"
	AuthProviderPassword   AuthProvider = "password"
)

// SetServerDomain sets the server's domain (IP address or DNS name), updating
// the settings that embed the server URL.
func (s *ServerSettingsService) SetServerDomain(ctx context.Context, domain string) error {
	return s.client.SetServerDomain(ctx, domain)
}

// SetBootstrapAccount enables or disables the bootstrap (root) login. If
// password is not blank it also sets the bootstrap password.
func (s *ServerSettingsService) SetBootstrapAccount(ctx context.Context, enabled bool, password string) (json.RawMessage, error) {
	p := Params{
		"name":    AuthProviderAdmin,
		"type":    AuthProviderAdmin,
		"enabled": "false",
	}
	if enabled {
		p["enabled"] = "true"
	}
	if strings.TrimSpace(password) != "" {
		p["password"] = password
	}
	return s.client.Call(ctx, http.MethodPut, "/v1/providers/"+string(AuthProviderAdmin), p)
}

// SetPassthrough switches the current session to passthrough mode for the
// datasource.
func (s *ServerSettingsService) SetPassthrough(ctx context.Context, datasourceName string) ([]Row, error) {
	sql := "set " + string(DBPermissionPassthrough) + " " + sqlQuote(datasourceName) + " true"
	rows, err := s.client.Select(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("mamori: %s: %w", sql, err)
	}
	return rows, nil
}
