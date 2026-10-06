package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

//
// Roles
//

// GetGranteeRoles returns the roles granted to roleID.
func (c *Client) GetGranteeRoles(ctx context.Context, roleID string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles/"+roleID+"/grantee", nil)
}

// GetGranteeRolesRecursive returns the roles granted to roleID, recursively.
func (c *Client) GetGranteeRolesRecursive(ctx context.Context, roleID string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles/"+roleID+"/grantee?recursive=Y", nil)
}

// GetGrantedRoles returns the grantees roleID has been granted to.
func (c *Client) GetGrantedRoles(ctx context.Context, roleID string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles/"+roleID+"/granted", nil)
}

// GetGrantedRolesRecursive is [Client.GetGrantedRoles], recursively.
func (c *Client) GetGrantedRolesRecursive(ctx context.Context, roleID string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles/"+roleID+"/granted?recursive=Y", nil)
}

// GetGranteeGrantableRoles returns the roles roleID may grant.
func (c *Client) GetGranteeGrantableRoles(ctx context.Context, roleID string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles/"+roleID+"/grantee/grantable", nil)
}

// GetRolesWithGrantable returns roles with their grantable flag for roleID.
func (c *Client) GetRolesWithGrantable(ctx context.Context, roleID string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles/"+roleID+"/roles", nil)
}

// AttachRoles attaches roles to the role name.
func (c *Client) AttachRoles(ctx context.Context, name string, roles []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/roles/"+name+"/attach", roles)
}

// UserRoles returns the non-default roles directly granted to username.
func (c *Client) UserRoles(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles?isdef=N&grantee="+pathEscape(strings.ToLower(username)), nil)
}

// UserRolesRecursive returns all roles granted to username, recursively.
func (c *Client) UserRolesRecursive(ctx context.Context, username string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles?recursive=Y&grantee="+pathEscape(strings.ToLower(username)), nil)
}

// UsersRolesRecursive returns all roles granted to each user, recursively.
func (c *Client) UsersRolesRecursive(ctx context.Context, users []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles?recursive=Y", Params{"grantee": users})
}

func rolesUserPath(username string) string {
	return "/v1/users/" + pathEscape(strings.ToLower(username)) + "/roles"
}

// GrantRolesToUser grants roles to username.
func (c *Client) GrantRolesToUser(ctx context.Context, username string, roles []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, rolesUserPath(username), Params{"selected_roles": roles})
}

// RevokeRolesFromUser revokes roles from username.
func (c *Client) RevokeRolesFromUser(ctx context.Context, username string, roles []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, rolesUserPath(username), Params{"selected_roles": roles})
}

// UpdateUserRoles revokes deleted and grants added roles for username in a
// single call when both are non-empty, otherwise via
// [Client.RevokeRolesFromUser] or [Client.GrantRolesToUser]. When both are
// empty nothing is sent and (nil, nil) is returned.
func (c *Client) UpdateUserRoles(ctx context.Context, username string, deleted, added []string) (json.RawMessage, error) {
	switch {
	case len(deleted) > 0 && len(added) > 0:
		return c.Call(ctx, http.MethodPut, rolesUserPath(username), Params{
			"selected_roles": added,
			"deleted_roles":  deleted,
		})
	case len(deleted) > 0:
		return c.RevokeRolesFromUser(ctx, username, deleted)
	case len(added) > 0:
		return c.GrantRolesToUser(ctx, username, added)
	default:
		return nil, nil
	}
}

// GetRoleUserCount returns the number of users holding roleID.
func (c *Client) GetRoleUserCount(ctx context.Context, roleID string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles/"+roleID+"/usercount", nil)
}

// SearchUsersWithRole searches the users holding roleID.
func (c *Client) SearchUsersWithRole(ctx context.Context, roleID string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/search/roles/"+roleID+"/users", options)
}

//
// Role credentials
//

// GetRoleCredentials returns the datasource credentials attached to role.
func (c *Client) GetRoleCredentials(ctx context.Context, role string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/roles/"+role+"/credentials", nil)
}

// UpdateRoleCredentials removes deletedCreds and adds newCreds in a single
// call when both are non-empty, otherwise via [Client.DropRoleCredentials] or
// [Client.AddRoleCredentials]. When both are empty nothing is sent and
// (nil, nil) is returned.
func (c *Client) UpdateRoleCredentials(ctx context.Context, role string, deletedCreds, newCreds []string) (json.RawMessage, error) {
	switch {
	case len(deletedCreds) > 0 && len(newCreds) > 0:
		return c.Call(ctx, http.MethodPut, "/v1/roles/"+role+"/credentials", Params{
			"db_credentials":      newCreds,
			"deleted_credentials": deletedCreds,
		})
	case len(deletedCreds) > 0:
		return c.DropRoleCredentials(ctx, role, deletedCreds)
	case len(newCreds) > 0:
		return c.AddRoleCredentials(ctx, role, newCreds)
	default:
		return nil, nil
	}
}

// DropRoleCredentials detaches credentials from role.
func (c *Client) DropRoleCredentials(ctx context.Context, role string, credentials []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/roles/"+role+"/credentials", Params{"db_credentials": credentials})
}

// AddRoleCredentials attaches credentials to role.
func (c *Client) AddRoleCredentials(ctx context.Context, role string, credentials []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/roles/"+role+"/credentials", Params{"db_credentials": credentials})
}

//
// Grants
//

// GrantTo grants grantables (privileges or role names) to grantee, which is
// lower-cased. objectName is sent only when non-empty. Entries of options are
// merged into the request payload, overriding the standard fields. An error
// is returned (together with the result) unless the server answers with a
// result whose first element is "ok".
func (c *Client) GrantTo(ctx context.Context, grantee string, grantables []string, objectName string, withGrantOption bool, options Params) (*GrantResult, error) {
	payload := Params{
		"grantables":        grantables,
		"with_grant_option": withGrantOption,
	}
	if objectName != "" {
		payload["object_name"] = objectName
	}
	return c.rolesGrantCall(ctx, http.MethodPost, grantee, payload, options)
}

// RevokeFrom revokes grantables from grantee, which is lower-cased.
// objectName is sent only when non-empty, and entries of options are merged
// into the payload. Errors are reported as for [Client.GrantTo].
func (c *Client) RevokeFrom(ctx context.Context, grantee string, grantables []string, objectName string, options Params) (*GrantResult, error) {
	payload := Params{"grantables": grantables}
	if objectName != "" {
		payload["object_name"] = objectName
	}
	return c.rolesGrantCall(ctx, http.MethodDelete, grantee, payload, options)
}

func (c *Client) rolesGrantCall(ctx context.Context, method, grantee string, payload, options Params) (*GrantResult, error) {
	for k, v := range options {
		payload[k] = v
	}
	raw, err := c.Call(ctx, method, "/v1/grantee/"+pathEscape(strings.ToLower(grantee)), payload)
	if err != nil {
		return nil, err
	}
	var result []string
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("mamori: unexpected grant response %s: %w", raw, err)
	}
	res := &GrantResult{Result: result}
	if len(result) == 0 || result[0] != "ok" {
		if len(result) == 0 {
			return res, fmt.Errorf("mamori: grant to %q returned no result", grantee)
		}
		return res, fmt.Errorf("mamori: %s", strings.Join(result, "; "))
	}
	return res, nil
}

//
// Global and object permissions
//

// UpdateGlobalPermission revokes deleted and grants added global
// permissions for rolename in a single call when both are non-empty,
// otherwise via [Client.RevokeGlobalPermission] or
// [Client.GrantGlobalPermission]. When both are empty nothing is sent and
// (nil, nil) is returned.
func (c *Client) UpdateGlobalPermission(ctx context.Context, rolename string, deleted, added []string) (json.RawMessage, error) {
	switch {
	case len(deleted) > 0 && len(added) > 0:
		return c.Call(ctx, http.MethodPut, "/v1/roles/"+rolename+"/global/permissions", Params{
			"selected_permission": added,
			"deleted_permission":  deleted,
		})
	case len(deleted) > 0:
		return c.RevokeGlobalPermission(ctx, rolename, Params{"deleted_permission": deleted})
	case len(added) > 0:
		return c.GrantGlobalPermission(ctx, rolename, Params{"selected_permissions_cirro": added})
	default:
		return nil, nil
	}
}

// UpdateObjectPermission revokes deleted and grants added object
// permissions for rolename in a single call when both are non-empty,
// otherwise via [Client.RevokeObjectPermission] or
// [Client.GrantObjectPermission]. When both are empty nothing is sent and
// (nil, nil) is returned.
func (c *Client) UpdateObjectPermission(ctx context.Context, rolename string, deleted, added []string) (json.RawMessage, error) {
	switch {
	case len(deleted) > 0 && len(added) > 0:
		return c.Call(ctx, http.MethodPut, "/v1/roles/"+rolename+"/object/permissions", Params{
			"selected_permissions_object": added,
			"deleted_permission":          deleted,
		})
	case len(deleted) > 0:
		return c.RevokeObjectPermission(ctx, rolename, Params{"deleted_permission_object": deleted})
	case len(added) > 0:
		return c.GrantObjectPermission(ctx, rolename, Params{"selected_permissions_object": added})
	default:
		return nil, nil
	}
}

// GranteeObjectGrants returns grantee's grants of permissionType on
// objectName.
func (c *Client) GranteeObjectGrants(ctx context.Context, grantee, permissionType, objectName string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/grantee/"+grantee+"/grants", Params{
		"permission":  permissionType,
		"object_name": objectName,
	})
}

// GrantGlobalPermission grants global permissions to role.
func (c *Client) GrantGlobalPermission(ctx context.Context, role string, permissions any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/roles/"+role+"/grant/global/permissions", permissions)
}

// RevokeGlobalPermission revokes global permissions from role. permissions
// are sent as query parameters.
func (c *Client) RevokeGlobalPermission(ctx context.Context, role string, permissions any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/roles/"+role+"/grant/global/permissions", permissions)
}

// RevokeObjectPermission revokes object permissions from role. permissions
// are sent as query parameters.
func (c *Client) RevokeObjectPermission(ctx context.Context, role string, permissions any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodDelete, "/v1/roles/"+role+"/grant/object/permissions", permissions)
}

// GrantObjectPermission grants object permissions to role.
func (c *Client) GrantObjectPermission(ctx context.Context, role string, permissions any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPost, "/v1/roles/"+role+"/grant/object/permissions", permissions)
}

// PermissionsByRole returns the permissions of roleID, optionally limited to
// scopes (nil for all).
func (c *Client) PermissionsByRole(ctx context.Context, roleID string, scopes []string) (json.RawMessage, error) {
	var p any
	if scopes != nil {
		p = Params{"scope": scopes}
	}
	return c.Call(ctx, http.MethodGet, "/v1/roles/"+roleID+"/permissions", p)
}

//
// Privileges and permissions
//

// Privileges returns privileges. query is appended verbatim to
// "/v1/privileges", so it should carry its own leading "?".
func (c *Client) Privileges(ctx context.Context, query string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/privileges"+query, nil)
}

// GranteePrivilegesRecursive returns the privileges of each grantee,
// recursively.
func (c *Client) GranteePrivilegesRecursive(ctx context.Context, grantees []string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/privileges?recursive=Y", Params{"grantee": grantees})
}

// Grantees lists all grantees (users and roles).
func (c *Client) Grantees(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/grantees", nil)
}

// ListPermissions lists the available permissions, optionally limited to
// scopes (nil for all). TS: permissions().
func (c *Client) ListPermissions(ctx context.Context, scopes []string) (json.RawMessage, error) {
	var p any
	if scopes != nil {
		p = Params{"scope": scopes}
	}
	return c.Call(ctx, http.MethodGet, "/v1/permissions", p)
}

// ListPermissionsFiltered lists the available permissions limited to scopes
// (if non-nil) and permissionType (if non-empty). TS: permissionsFiltered().
func (c *Client) ListPermissionsFiltered(ctx context.Context, scopes []string, permissionType string) (json.RawMessage, error) {
	p := Params{}
	if scopes != nil {
		p["scope"] = scopes
	}
	if permissionType != "" {
		p["permissiontype"] = permissionType
	}
	return c.Call(ctx, http.MethodGet, "/v1/permissions", p)
}
