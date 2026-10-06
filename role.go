package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Role is a mamori role.
type Role struct {
	RoleID          string `json:"roleid"`
	ExternalName    string `json:"externalname,omitempty"`
	Position        string `json:"position,omitempty"`
	WithAdminOption string `json:"withadminoption"`
}

// NewRole returns a role with the given id and no admin option.
func NewRole(roleID string) *Role {
	return &Role{RoleID: roleID, WithAdminOption: "N"}
}

// RoleGrant is a role record, including grant details.
type RoleGrant struct {
	RoleID          string `json:"roleid"`
	ExternalName    string `json:"externalname,omitempty"`
	Position        string `json:"position,omitempty"`
	WithAdminOption string `json:"withadminoption"`

	UUID       string `json:"uuid"`
	IsDef      string `json:"isdef"`
	Grantable  string `json:"grantable,omitempty"`
	Grantee    string `json:"grantee"`
	Grantor    string `json:"grantor"`
	LastUpdate string `json:"lastupdate"`
	ValidFrom  string `json:"valid_from,omitempty"`
	ValidUntil string `json:"valid_until,omitempty"`
}

// RoleDependencies lists the references that would block deleting a role.
type RoleDependencies struct {
	Grantees []string `json:"grantees"`
	Policies []struct {
		Name   string   `json:"name"`
		Fields []string `json:"fields"`
	} `json:"policies"`
	Jobs         []string `json:"jobs"`
	Requestables []struct {
		ID            int64  `json:"id"`
		ResourceType  string `json:"resource_type"`
		ResourceName  string `json:"resource_name"`
		ResourceLogin string `json:"resource_login,omitempty"`
	} `json:"requestables"`
	Alerts []string `json:"alerts"`
}

// RoleOptionValidFor returns grant options making a role grant valid for
// value units.
func RoleOptionValidFor(unit TimeUnit, value int) Params {
	return Params{"valid_unit": unit, "valid_duration": value}
}

// RoleOptionValidFrom returns grant options making a role grant valid from
// from ("YYYY-MM-DD HH:mm").
func RoleOptionValidFrom(from string) Params { return Params{"valid_from": from} }

// RoleOptionValidUntil returns grant options making a role grant valid until
// until ("YYYY-MM-DD HH:mm").
func RoleOptionValidUntil(until string) Params { return Params{"valid_until": until} }

// RoleOptionValidBetween returns grant options making a role grant valid
// between from and until.
func RoleOptionValidBetween(from, until string) Params {
	return Params{"valid_from": from, "valid_until": until}
}

// GetAll returns all role definitions (excluding PUBLIC).
func (s *RoleService) GetAll(ctx context.Context) ([]Row, error) {
	return s.client.Select(ctx,
		"SELECT uuid,roleid,position,externalname,withadminoption,valid_from,valid_until,granted_by_request_id,revoked_by_request_id,grant_provider,lastupdate FROM (select * from SYS.SYSROLES WHERE lower(isDef) = 'y' AND roleid <> 'public') a ")
}

// Create creates a role.
func (s *RoleService) Create(ctx context.Context, r *Role) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, "/v1/roles", roleParams(r))
}

// Update updates a role's external name and position.
func (s *RoleService) Update(ctx context.Context, r *Role) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, "/v1/roles/"+r.RoleID, roleParams(r))
}

func roleParams(r *Role) Params {
	p := Params{"roleid": r.RoleID, "externalname": r.ExternalName}
	if r.Position != "" {
		p["position"] = r.Position
	}
	return p
}

// Get returns a role's configuration.
func (s *RoleService) Get(ctx context.Context, roleID string) (*RoleGrant, error) {
	var g *RoleGrant
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/roles/"+roleID, nil, &g); err != nil {
		return nil, err
	}
	if g == nil {
		return nil, fmt.Errorf("mamori: role %q: %w", roleID, ErrNotFound)
	}
	return g, nil
}

// Dependencies returns the references (grantees, policies, jobs,
// requestables, alerts) that would block deleting the role.
func (s *RoleService) Dependencies(ctx context.Context, roleID string) (*RoleDependencies, error) {
	var d RoleDependencies
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/roles/"+pathEscape(roleID)+"/dependencies", nil, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Delete deletes a role. With cascade, the role's grants, policies, jobs,
// requestables and alerts are cleared first.
func (s *RoleService) Delete(ctx context.Context, roleID string, cascade bool) (json.RawMessage, error) {
	path := "/v1/roles/" + pathEscape(roleID)
	if cascade {
		path += "?cascade=true"
	}
	return s.client.Call(ctx, http.MethodDelete, path, nil)
}

// Grant grants privileges (e.g. "ROLE") to the role. objectName is optional,
// e.g. a table "<datasource>.<database>.<schema>.<table>". options may carry
// validity settings (see [RoleOptionValidFor]).
func (s *RoleService) Grant(ctx context.Context, roleID string, grantables []string, objectName string, withGrantOption bool, options Params) (*GrantResult, error) {
	return s.grantTo(ctx, roleID, grantables, objectName, withGrantOption, options)
}

// GrantTo grants the role to a user or role.
func (s *RoleService) GrantTo(ctx context.Context, roleID, userOrRole string, grantable bool, options Params) (*GrantResult, error) {
	return s.grantTo(ctx, userOrRole, []string{roleID}, "", grantable, options)
}

// Revoke revokes privileges from the role. objectName is optional.
func (s *RoleService) Revoke(ctx context.Context, roleID string, grantables []string, objectName string, options Params) (*GrantResult, error) {
	return s.revokeFrom(ctx, roleID, grantables, objectName, options)
}

// RevokeFrom revokes the role from a user or role.
func (s *RoleService) RevokeFrom(ctx context.Context, roleID, userOrRole string, options Params) (*GrantResult, error) {
	return s.revokeFrom(ctx, userOrRole, []string{roleID}, "", options)
}

func (s *RoleService) grantTo(ctx context.Context, grantee string, grantables []string, objectName string, withGrantOption bool, options Params) (*GrantResult, error) {
	p := Params{
		"grantables":        grantables,
		"object_name":       nil,
		"with_grant_option": withGrantOption,
	}
	if objectName != "" {
		p["object_name"] = objectName
	}
	for k, v := range options {
		p[k] = v
	}
	return roleGrantResult(s.client.Call(ctx, http.MethodPost, "/v1/grantee/"+pathEscape(strings.ToLower(grantee)), p))
}

func (s *RoleService) revokeFrom(ctx context.Context, grantee string, grantables []string, objectName string, options Params) (*GrantResult, error) {
	p := Params{"grantables": grantables}
	if objectName != "" {
		p["object_name"] = objectName
	}
	for k, v := range options {
		p[k] = v
	}
	return roleGrantResult(s.client.Call(ctx, http.MethodDelete, "/v1/grantee/"+pathEscape(strings.ToLower(grantee)), p))
}

// roleGrantResult decodes a grant/revoke response; it succeeds only when the
// first element is "ok".
func roleGrantResult(raw json.RawMessage, err error) (*GrantResult, error) {
	if err != nil {
		return nil, err
	}
	var result []string
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("mamori: unexpected grant response %s: %w", raw, err)
	}
	res := &GrantResult{Result: result}
	if len(result) == 0 || result[0] != "ok" {
		return res, fmt.Errorf("mamori: grant failed: %s", strings.Join(result, "; "))
	}
	return res, nil
}

// GetGrantees returns the users and roles the role is directly granted to.
// Each row is a role grant with an extra "type" of "role" or "user".
func (s *RoleService) GetGrantees(ctx context.Context, roleID string) ([]Row, error) {
	var rows []Row
	err := s.client.CallInto(ctx, http.MethodGet, "/v1/roles/"+strings.ToLower(roleID)+"/granted", nil, &rows)
	return rows, err
}

// GetGranteesRecursive returns the users and roles the role is granted to,
// directly or indirectly.
func (s *RoleService) GetGranteesRecursive(ctx context.Context, roleID string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, "/v1/roles/"+strings.ToLower(roleID)+"/granted?recursive=Y", nil)
}

// GetAllGrantedRoles returns all roles granted to the role, directly or
// indirectly.
func (s *RoleService) GetAllGrantedRoles(ctx context.Context, roleID string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, "/v1/roles/"+strings.ToLower(roleID)+"/grantee?recursive=Y", nil)
}

// GetGrantedRoles returns the roles directly granted to the role.
func (s *RoleService) GetGrantedRoles(ctx context.Context, roleID string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodGet, "/v1/roles/"+strings.ToLower(roleID)+"/grantee", nil)
}
