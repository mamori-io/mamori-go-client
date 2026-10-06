package mamori

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// apiUsersPath returns "/v1/users/{username}" with the name lower-cased and
// escaped.
func apiUsersPath(username string) string {
	return "/v1/users/" + pathEscape(strings.ToLower(username))
}

//
// Users
//

// ListUsers lists users. query is appended verbatim to the path and may be ""
// or a query string such as "?external=y".
func (c *Client) ListUsers(ctx context.Context, query string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/users"+query, nil)
}

// UserHasPendingValidation reports whether the current user has a pending
// validation.
func (c *Client) UserHasPendingValidation(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/my/validation", nil)
}

// GetMyPendingSessions returns the pending MFA challenge sessions of the
// current login.
func (c *Client) GetMyPendingSessions(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/my/sessions", nil)
}

// UsersSearch searches users.
func (c *Client) UsersSearch(ctx context.Context, query any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/search/users", query)
}

// UsersCount returns the number of users.
func (c *Client) UsersCount(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/count/users", nil)
}

// UsersExternal lists externally authenticated users.
func (c *Client) UsersExternal(ctx context.Context) (json.RawMessage, error) {
	return c.ListUsers(ctx, "?external=y")
}

// UsersConnected lists currently connected users.
func (c *Client) UsersConnected(ctx context.Context) (json.RawMessage, error) {
	return c.ListUsers(ctx, "?connected=y")
}

// UsersReloadAll reloads all users on the server.
func (c *Client) UsersReloadAll(ctx context.Context) (json.RawMessage, error) {
	return c.ListUsers(ctx, "?reload_all=y")
}

// UsersClearAuthenticationRequests clears pending authentication requests.
func (c *Client) UsersClearAuthenticationRequests(ctx context.Context) (json.RawMessage, error) {
	return c.ListUsers(ctx, "?clear_authentication_requests=y")
}

// User returns a user's details.
func (c *Client) User(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, apiUsersPath(username), nil)
}

// CreateUser creates a user.
func (c *Client) CreateUser(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/users", options)
}

// DeleteUser deletes a user.
func (c *Client) DeleteUser(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, apiUsersPath(username), nil)
}

// UpdateUser updates a user.
func (c *Client) UpdateUser(ctx context.Context, username string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, apiUsersPath(username), options)
}

// UserUpdate updates a user.
//
// Deprecated: identical to [Client.UpdateUser].
func (c *Client) UserUpdate(ctx context.Context, username string, options any) (json.RawMessage, error) {
	return c.UpdateUser(ctx, username, options)
}

// NotifyUser sends the user a notification email.
func (c *Client) NotifyUser(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, apiUsersPath(username)+"/notify", nil)
}

// GeneratePassword generates a new password for a user.
func (c *Client) GeneratePassword(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, apiUsersPath(username)+"/generate_password", nil)
}

// ResetUserPassword resets a user's password.
func (c *Client) ResetUserPassword(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, apiUsersPath(username)+"/reset_password", nil)
}

// ResetExternalUser resets an externally authenticated user.
func (c *Client) ResetExternalUser(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, apiUsersPath(username)+"/reset_external", nil)
}

// DeleteExternalUser deletes an externally authenticated user.
func (c *Client) DeleteExternalUser(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, apiUsersPath(username)+"/external", nil)
}

// DisableUser disables a user.
func (c *Client) DisableUser(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, apiUsersPath(username)+"/disable", nil)
}

// EnableUser enables a user.
func (c *Client) EnableUser(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, apiUsersPath(username)+"/enable", nil)
}

// UnlockUser unlocks a locked user.
func (c *Client) UnlockUser(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, apiUsersPath(username)+"/unlock", nil)
}

// UserOptions returns a user's options.
func (c *Client) UserOptions(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, apiUsersPath(username)+"/options", nil)
}

// GetPendingUserSessions returns a user's pending authentication sessions.
func (c *Client) GetPendingUserSessions(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/ua/sessions/"+pathEscape(strings.ToLower(username)), nil)
}

//
// Scoped MFA apply
//

// ListMyMFAApply lists the current user's MFA apply rows.
func (c *Client) ListMyMFAApply(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/my/mfa_apply", nil)
}

// EnrollScopedMFA starts self-service scoped MFA enrollment with the named
// provider ("" for the default). The response carries the QR guid when an
// enrollment is created.
func (c *Client) EnrollScopedMFA(ctx context.Context, providerName string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/my/mfa_apply/enroll", Params{"provider_name": providerName})
}

// ListUserMFAApply lists a user's MFA apply rows (admin).
func (c *Client) ListUserMFAApply(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/users/"+pathEscape(username)+"/mfa_apply", nil)
}

// SetUserScopedMFA sets a user's scoped MFA provider and applies (admin).
func (c *Client) SetUserScopedMFA(ctx context.Context, username, provider string, mfaApplies []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/users/"+pathEscape(username)+"/mfa_apply", Params{
		"provider":    provider,
		"mfa_applies": mfaApplies,
	})
}

// DeleteUserScopedMFA deletes a user's scoped MFA applies (admin).
func (c *Client) DeleteUserScopedMFA(ctx context.Context, username string, mfaApplies []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/users/"+pathEscape(username)+"/mfa_apply", Params{
		"mfa_applies": mfaApplies,
	})
}

// ResetUserScopedMFA resets a user's scoped MFA secrets / QR codes (admin).
func (c *Client) ResetUserScopedMFA(ctx context.Context, username, provider string, mfaApplies []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/users/"+pathEscape(username)+"/mfa_apply/reset", Params{
		"provider":    provider,
		"mfa_applies": mfaApplies,
	})
}

//
// Role grants
//

// GetRoleAuthorizationBySystem returns all users/roles and the systems they
// are authorized to access. params may be nil.
func (c *Client) GetRoleAuthorizationBySystem(ctx context.Context, params any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles/auth/systems", params)
}

// RevokeRoleFromUsers revokes a role from several users.
func (c *Client) RevokeRoleFromUsers(ctx context.Context, roleID string, users []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/roles/"+roleID+"/users", Params{"selected_users": users})
}

// RevokeRoleFromGrantee revokes a role from a single user or role.
func (c *Client) RevokeRoleFromGrantee(ctx context.Context, roleID, grantee string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/roles/"+roleID+"/user", Params{"selected_user": grantee})
}

// GrantRoleToUsers grants a role to several users.
func (c *Client) GrantRoleToUsers(ctx context.Context, roleID string, users []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/roles/"+roleID+"/users", Params{"selected_users": users})
}

// GrantRoleToGrantee grants a role to a single user or role.
func (c *Client) GrantRoleToGrantee(ctx context.Context, roleID, grantee string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/roles/"+roleID+"/user", Params{"selected_user": grantee})
}

// UpdateRoleUsers revokes a role from the deleted users and grants it to the
// added users, in a single request when both lists are non-empty.
func (c *Client) UpdateRoleUsers(ctx context.Context, roleID string, deleted, added []string) (json.RawMessage, error) {
	switch {
	case len(deleted) > 0 && len(added) > 0:
		return c.Call(ctx, http.MethodPut, "/v1/roles/"+roleID+"/users", Params{
			"selected_users": added,
			"deleted_users":  deleted,
		})
	case len(deleted) > 0:
		return c.RevokeRoleFromUsers(ctx, roleID, deleted)
	default:
		return c.GrantRoleToUsers(ctx, roleID, added)
	}
}

//
// Grantee policies
//

// GetGranteePolicies returns the policies granted to a user or role.
func (c *Client) GetGranteePolicies(ctx context.Context, grantee string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/grantee/"+pathEscape(strings.ToLower(grantee))+"/policies", nil)
}

// SearchGranteePolicies searches the policies granted to a user or role.
func (c *Client) SearchGranteePolicies(ctx context.Context, grantee string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/grantee/"+grantee+"/policies", options)
}

//
// User database credentials
//

// GetUserDBCreds returns a user's datasource credentials.
func (c *Client) GetUserDBCreds(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, apiUsersPath(username)+"/credentials", nil)
}

// UpdateUserDBCreds drops deletedCreds and adds newCreds for a user, in a
// single request when both lists are non-empty.
func (c *Client) UpdateUserDBCreds(ctx context.Context, username string, deletedCreds, newCreds []any) (json.RawMessage, error) {
	switch {
	case len(deletedCreds) > 0 && len(newCreds) > 0:
		return c.Call(ctx, http.MethodPut, apiUsersPath(username)+"/credentials", Params{
			"db_credentials":      newCreds,
			"deleted_credentials": deletedCreds,
		})
	case len(deletedCreds) > 0:
		return c.DropUserDBCreds(ctx, username, deletedCreds)
	default:
		return c.AddUserDBCreds(ctx, username, newCreds)
	}
}

// DropUserDBCreds removes datasource credentials from a user.
func (c *Client) DropUserDBCreds(ctx context.Context, username string, credentials any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, apiUsersPath(username)+"/credentials", Params{"db_credentials": credentials})
}

// AddUserDBCreds adds datasource credentials to a user.
func (c *Client) AddUserDBCreds(ctx context.Context, username string, credentials any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, apiUsersPath(username)+"/credentials", Params{"db_credentials": credentials})
}

//
// Permission log
//

// SearchPermissionLog searches the permission change log.
func (c *Client) SearchPermissionLog(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/search/permission_log", options)
}

// SearchPermissionLogSysview searches the permission log system view.
func (c *Client) SearchPermissionLogSysview(ctx context.Context, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/search/permission_log_sysview", options)
}
