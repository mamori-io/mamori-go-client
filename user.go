package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// MFAProvider is a multi-factor authentication provider type.
type MFAProvider string

// MFA providers.
const (
	// MFAProviderNone removes the MFA provider.
	MFAProviderNone MFAProvider = "none"
	// MFAProviderPushTOTP is push-to-TOTP authentication.
	MFAProviderPushTOTP MFAProvider = "pushtotp"
	// MFAProviderPushMobile is push mobile authentication.
	MFAProviderPushMobile MFAProvider = "pushmobile"
	// MFAProviderTOTP is time-based one-time password authentication.
	MFAProviderTOTP MFAProvider = "totp"
	// MFAProviderYubiKey is YubiKey authentication.
	MFAProviderYubiKey MFAProvider = "yubikey"
	// MFAProviderOnlineYubiKey is online YubiKey authentication.
	MFAProviderOnlineYubiKey MFAProvider = "onlineyubikey"
	// MFAProviderService is service account (source IP) authentication.
	MFAProviderService MFAProvider = "service"
	// MFAProviderDUO is Duo Security authentication.
	MFAProviderDUO MFAProvider = "duo"
	// MFAProviderUnloq is Unloq authentication.
	MFAProviderUnloq MFAProvider = "unloq"
	// MFAProviderSaasPass is SaasPass authentication.
	MFAProviderSaasPass MFAProvider = "saaspass"
	// MFAProviderAzure is Azure AD authentication.
	MFAProviderAzure MFAProvider = "azure"
	// MFAProviderTechPass is TechPass authentication.
	MFAProviderTechPass MFAProvider = "techpass"
	// MFAProviderAzureOAuth is Azure OAuth authentication.
	MFAProviderAzureOAuth MFAProvider = "azureoauth"
	// MFAProviderOkta is Okta authentication.
	MFAProviderOkta MFAProvider = "okta"
	// MFAProviderPingID is PingID authentication.
	MFAProviderPingID MFAProvider = "pingid"
)

// MFAApply is a scope in which a user's MFA provider is challenged.
type MFAApply string

// MFA apply scopes.
const (
	MFAApplyPortalOAuth     MFAApply = "portal_oauth"
	MFAApplyPortalLocalAuth MFAApply = "portal_local_auth"
	MFAApplyResourceAccess  MFAApply = "resource_access"
)

// MFAScopes are the default scopes: portal local login and resource access
// (DB proxy, etc.). They are used when no scopes are passed to the scoped MFA
// methods of [UserService].
var MFAScopes = []MFAApply{MFAApplyPortalLocalAuth, MFAApplyResourceAccess}

// User is a mamori user.
type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"fullname"`
}

// DirectoryUser is a user authenticated by a directory provider.
type DirectoryUser struct {
	Provider string `json:"provider"`
	Username string `json:"username"`
	Email    string `json:"email"`
	FullName string `json:"fullname"`
}

// userPath returns /v1/users/{lower-cased, escaped username}.
func userPath(username string) string {
	return "/v1/users/" + pathEscape(strings.ToLower(username))
}

// userApplies returns applies as strings, defaulting to [MFAScopes].
func userApplies(applies []MFAApply) []string {
	if len(applies) == 0 {
		applies = MFAScopes
	}
	out := make([]string, len(applies))
	for i, a := range applies {
		out[i] = string(a)
	}
	return out
}

// userJoinApplies joins non-empty applies with commas.
func userJoinApplies(applies []MFAApply) string {
	var parts []string
	for _, a := range userApplies(applies) {
		if a != "" {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, ",")
}

// List searches users. Non-admins only see users they are permitted to.
func (s *UserService) List(ctx context.Context, opts SearchOptions) (*SearchResult[Row], error) {
	var res SearchResult[Row]
	if err := s.client.CallInto(ctx, http.MethodPut, "/v1/search/users", opts.params(), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Get returns the user's username, email and full name.
func (s *UserService) Get(ctx context.Context, username string) (*User, error) {
	var rec struct {
		Email    string `json:"email"`
		FullName string `json:"fullname"`
	}
	if err := s.client.CallInto(ctx, http.MethodGet, userPath(username), nil, &rec); err != nil {
		return nil, err
	}
	return &User{Username: username, Email: rec.Email, FullName: rec.FullName}, nil
}

// Create creates a password-authenticated user. password may be empty.
func (s *UserService) Create(ctx context.Context, u *User, password string) (json.RawMessage, error) {
	p := Params{
		"username":      u.Username,
		"fullname":      u.FullName,
		"identified_by": "password",
		"email":         u.Email,
	}
	if password != "" {
		p["password"] = password
	}
	return s.client.Call(ctx, http.MethodPost, "/v1/users", p)
}

// Delete deletes a user.
func (s *UserService) Delete(ctx context.Context, username string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, userPath(username), nil)
}

// Update updates the user's email and full name.
func (s *UserService) Update(ctx context.Context, u *User) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, userPath(u.Username), Params{
		"email":    u.Email,
		"fullname": u.FullName,
	})
}

// SetMFAProvider sets the user's primary MFA provider with optional
// provider-specific options. Use [MFAProviderNone] to remove it.
func (s *UserService) SetMFAProvider(ctx context.Context, username string, provider MFAProvider, options map[string]string) (json.RawMessage, error) {
	if options == nil {
		options = map[string]string{}
	}
	return s.client.Call(ctx, http.MethodPut, userPath(username), Params{
		"authenticated_by_primary": Params{
			"provider": provider,
			"options":  options,
		},
	})
}

// SetAsServiceAccount makes the user a service account that authenticates by
// the source IPv4 address allowedIP.
func (s *UserService) SetAsServiceAccount(ctx context.Context, username, allowedIP string) (json.RawMessage, error) {
	return s.SetMFAProvider(ctx, username, MFAProviderService, map[string]string{"ALLOWED_IP": allowedIP})
}

// SetScopedMFA assigns a scoped MFA provider for the given scopes (default
// [MFAScopes]) via SYSCS_UTIL.SET_USER_SCOPED_MFA.
func (s *UserService) SetScopedMFA(ctx context.Context, username string, provider MFAProvider, applies ...MFAApply) ([]Row, error) {
	return s.client.Select(ctx, "CALL SYSCS_UTIL.SET_USER_SCOPED_MFA("+
		sqlQuote(username)+", "+sqlQuote(string(provider))+", "+sqlQuote(userJoinApplies(applies))+")")
}

// ResetScopedMFA regenerates the enrollment secrets of the user's scoped MFA
// rows for the given scopes (default [MFAScopes]) via
// SYSCS_UTIL.RESET_USER_SCOPED_MFA.
func (s *UserService) ResetScopedMFA(ctx context.Context, username string, provider MFAProvider, applies ...MFAApply) ([]Row, error) {
	return s.client.Select(ctx, "CALL SYSCS_UTIL.RESET_USER_SCOPED_MFA("+
		sqlQuote(username)+", "+sqlQuote(string(provider))+", "+sqlQuote(userJoinApplies(applies))+")")
}

// DeleteScopedMFA deletes the user's scoped MFA rows for the given scopes
// (default [MFAScopes]) via SYSCS_UTIL.DELETE_USER_SCOPED_MFA.
func (s *UserService) DeleteScopedMFA(ctx context.Context, username string, applies ...MFAApply) ([]Row, error) {
	return s.client.Select(ctx, "CALL SYSCS_UTIL.DELETE_USER_SCOPED_MFA("+
		sqlQuote(username)+", "+sqlQuote(userJoinApplies(applies))+")")
}

// ListAuthenticationProviders returns the user's
// SYS.USER_AUTHENTICATION_PROVIDERS rows (including MFA_APPLY).
func (s *UserService) ListAuthenticationProviders(ctx context.Context, username string) ([]Row, error) {
	return s.client.Select(ctx,
		"SELECT * FROM SYS.USER_AUTHENTICATION_PROVIDERS WHERE lower(user_name) = lower("+sqlQuote(username)+")")
}

// ListMyMFAApply lists the logged-in user's MFA apply rows.
func (s *UserService) ListMyMFAApply(ctx context.Context) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, "/v1/my/mfa_apply", nil)
}

// EnrollScopedMFA starts self-service scoped MFA enrollment for the logged-in
// user. provider may be empty.
func (s *UserService) EnrollScopedMFA(ctx context.Context, provider string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, "/v1/my/mfa_apply/enroll", Params{"provider_name": provider})
}

// ListUserMFAApply lists a user's MFA apply rows (admin).
func (s *UserService) ListUserMFAApply(ctx context.Context, username string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, "/v1/users/"+pathEscape(username)+"/mfa_apply", nil)
}

// SetScopedMFAHTTP sets a user's scoped MFA provider for the given scopes
// (default [MFAScopes]) through the REST API (admin).
func (s *UserService) SetScopedMFAHTTP(ctx context.Context, username string, provider MFAProvider, applies ...MFAApply) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, "/v1/users/"+pathEscape(username)+"/mfa_apply", Params{
		"provider":    string(provider),
		"mfa_applies": userApplies(applies),
	})
}

// DeleteScopedMFAHTTP deletes a user's scoped MFA scopes (default
// [MFAScopes]) through the REST API (admin).
func (s *UserService) DeleteScopedMFAHTTP(ctx context.Context, username string, applies ...MFAApply) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/users/"+pathEscape(username)+"/mfa_apply", Params{
		"mfa_applies": userApplies(applies),
	})
}

// ResetScopedMFAHTTP resets a user's scoped MFA secrets for the given scopes
// (default [MFAScopes]) through the REST API (admin).
func (s *UserService) ResetScopedMFAHTTP(ctx context.Context, username string, provider MFAProvider, applies ...MFAApply) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, "/v1/users/"+pathEscape(username)+"/mfa_apply/reset", Params{
		"provider":    string(provider),
		"mfa_applies": userApplies(applies),
	})
}

// Disable disables a user account.
func (s *UserService) Disable(ctx context.Context, username string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, userPath(username)+"/disable", nil)
}

// Enable enables a user account.
func (s *UserService) Enable(ctx context.Context, username string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, userPath(username)+"/enable", nil)
}

// Unlock unlocks a locked user account.
func (s *UserService) Unlock(ctx context.Context, username string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, userPath(username)+"/unlock", nil)
}

// ExportPassword exports the user's password hash encrypted with the named
// AES key (hub procedure EXPORT_USER_PASSWORD_EX).
func (s *UserService) ExportPassword(ctx context.Context, username, aesKeyName string) (json.RawMessage, error) {
	return s.client.CallProcedure(ctx, "EXPORT_USER_PASSWORD_EX", username, aesKeyName)
}

// RestorePassword restores the user's password from a blob produced by
// [UserService.ExportPassword] (hub procedure RESTORE_USER_PASSWORD_EX).
func (s *UserService) RestorePassword(ctx context.Context, username string, encryptedValue any, aesKeyName string) (json.RawMessage, error) {
	return s.client.CallProcedure(ctx, "RESTORE_USER_PASSWORD_EX", username, encryptedValue, aesKeyName)
}

// ValidateLogin marks the user validated (ALTER USER ... SET VALIDATED =
// TRUE), then logs in as the user on a separate session, logs that session
// out and returns the login result. otp may be empty.
func (s *UserService) ValidateLogin(ctx context.Context, username, password, otp string) (*LoginResponse, error) {
	if err := checkSQLIdentifier(username); err != nil {
		return nil, err
	}
	if _, err := s.client.Select(ctx, "ALTER USER "+username+" SET VALIDATED = TRUE"); err != nil {
		return nil, err
	}
	nc := s.client.NewSession()
	var opts []LoginOption
	if otp != "" {
		opts = append(opts, WithOTP(otp))
	}
	res, err := nc.Login(ctx, username, password, opts...)
	if err != nil {
		return nil, err
	}
	_ = nc.Logout(ctx)
	return res, nil
}

// GetAllGrantedRoles returns all roles granted to user, directly or
// indirectly (rows of uuid, roleid, grantee, valid_from, valid_until). If
// user is empty the logged-in user is used.
func (s *UserService) GetAllGrantedRoles(ctx context.Context, user string) (json.RawMessage, error) {
	if user == "" {
		user = s.client.Username()
	}
	var res struct {
		Rows json.RawMessage `json:"rows"`
	}
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/roles?recursive=Y&grantee="+pathEscape(strings.ToLower(user)), nil, &res); err != nil {
		return nil, err
	}
	return res.Rows, nil
}

// GetGrantedRoles returns the roles directly granted to user. If user is
// empty the logged-in user is used.
func (s *UserService) GetGrantedRoles(ctx context.Context, user string) (json.RawMessage, error) {
	if user == "" {
		user = s.client.Username()
	}
	return s.client.Call(ctx, http.MethodGet, "/v1/roles?isdef=N&grantee="+pathEscape(strings.ToLower(user)), nil)
}

// ClearMFARequests clears the user's multi-factor cache and pending
// authentication requests, then disconnects the user's wireguard peers. If
// peerPublicKey is non-empty only that peer is disconnected.
func (s *UserService) ClearMFARequests(ctx context.Context, username, peerPublicKey string) error {
	sql := strings.Replace("CALL CLEAR_AUTHENTICATION_REQUESTS(':USERNAME')", ":USERNAME", SQLEscape(username), 1)
	if _, err := s.client.Select(ctx, sql); err != nil {
		return fmt.Errorf("mamori: clearing authentication requests: %w", err)
	}
	var err error
	if peerPublicKey != "" {
		_, err = s.client.Call(ctx, http.MethodDelete, "/v1/wireguard/"+pathEscape(peerPublicKey)+"/disconnect", nil)
	} else {
		_, err = s.client.Call(ctx, http.MethodDelete, "/v1/wireguard/disconnect_user/"+username, nil)
	}
	if err != nil {
		return fmt.Errorf("mamori: disconnecting wireguard: %w", err)
	}
	return nil
}

// ListDirectoryUsers searches directory users.
func (s *UserService) ListDirectoryUsers(ctx context.Context, opts SearchOptions) (*SearchResult[Row], error) {
	var res SearchResult[Row]
	if err := s.client.CallInto(ctx, http.MethodPut, "/v1/search/directory_users", opts.params(), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// CreateDirectoryUser registers a user from a directory provider.
func (s *UserService) CreateDirectoryUser(ctx context.Context, u *DirectoryUser) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, "/v1/directory_users", Params{
		"provider": u.Provider,
		"username": u.Username,
	})
}

// DeleteDirectoryUser deletes a directory (external) user.
func (s *UserService) DeleteDirectoryUser(ctx context.Context, username string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, userPath(username)+"/external", nil)
}
