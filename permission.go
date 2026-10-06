package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// PermissionType identifies a family of grantable permissions.
type PermissionType string

// Permission types.
const (
	PermissionTypeMamori        PermissionType = "mamori"
	PermissionTypeDatasource    PermissionType = "datasource"
	PermissionTypePolicy        PermissionType = "policy"
	PermissionTypeKey           PermissionType = "encryptionkey"
	PermissionTypeRole          PermissionType = "role"
	PermissionTypeSSH           PermissionType = "ssh"
	PermissionTypeRemoteDesktop PermissionType = "remotedesktop"
	PermissionTypeIPResource    PermissionType = "ip_resource"
	PermissionTypeHTTPResource  PermissionType = "http_resource"
	PermissionTypeSecret        PermissionType = "secret"
	PermissionTypeCredential    PermissionType = "credential"
	PermissionTypeScript        PermissionType = "script"
	PermissionTypeScriptFlow    PermissionType = "script_flow"
)

// TimeUnit is the unit of a [ValidFor] duration.
type TimeUnit string

// Time units.
const (
	Seconds TimeUnit = "seconds"
	Minutes TimeUnit = "minutes"
	Hours   TimeUnit = "hours"
)

// ValidRangeType describes when a granted permission is valid.
type ValidRangeType string

// Validity range types.
const (
	ValidAlways  ValidRangeType = "always"
	ValidBetween ValidRangeType = "between"
	ValidFrom    ValidRangeType = "from"
	ValidUntil   ValidRangeType = "until"
	ValidForType ValidRangeType = "for"
)

// PermissionDateTimeFormat is the layout for validity dates ("YYYY-MM-DD HH:mm").
const PermissionDateTimeFormat = "2006-01-02 15:04"

// PermissionDateFormat is the layout for validity dates ("YYYY-MM-DD").
const PermissionDateFormat = "2006-01-02"

// Validity limits when a granted permission applies. The zero value means
// always.
type Validity struct {
	Type     ValidRangeType
	From     string // "YYYY-MM-DD HH:mm"
	Until    string // "YYYY-MM-DD HH:mm"
	Duration int
	Unit     TimeUnit
}

// ValidFor returns a validity lasting duration units from the grant.
func ValidFor(duration int, unit TimeUnit) Validity {
	return Validity{Type: ValidForType, Duration: duration, Unit: unit}
}

// ValidFromTime returns a validity starting at from ("YYYY-MM-DD HH:mm").
func ValidFromTime(from string) Validity { return Validity{Type: ValidFrom, From: from} }

// ValidUntilTime returns a validity ending at until ("YYYY-MM-DD HH:mm").
func ValidUntilTime(until string) Validity { return Validity{Type: ValidUntil, Until: until} }

// ValidBetweenTimes returns a validity for the range [from, until].
func ValidBetweenTimes(from, until string) Validity {
	return Validity{Type: ValidBetween, From: from, Until: until}
}

// PermissionBase holds the settings common to every permission. It is
// embedded in each concrete permission type.
type PermissionBase struct {
	// Grantee is the user or role receiving (or losing) the permission.
	Grantee string
	// Validity restricts when the grant applies.
	Validity Validity
	// WithGrantOption allows the grantee to grant the permission on.
	WithGrantOption bool
	// Cascade, for revokes, removes all permissions of the same type and
	// object when true. nil leaves the server default.
	Cascade *bool
}

// Base returns the common permission settings.
func (b *PermissionBase) Base() *PermissionBase { return b }

// options returns the common grant options.
func (b *PermissionBase) options() Params {
	o := Params{}
	switch b.Validity.Type {
	case ValidBetween:
		o["valid_from"] = b.Validity.From
		o["valid_until"] = b.Validity.Until
	case ValidFrom:
		o["valid_from"] = b.Validity.From
	case ValidUntil:
		o["valid_until"] = b.Validity.Until
	case ValidForType:
		o["valid_duration"] = b.Validity.Duration
		o["valid_unit"] = b.Validity.Unit
	}
	if b.WithGrantOption {
		o["with_grant_option"] = "true"
	}
	if b.Cascade != nil {
		if *b.Cascade {
			o["cascade"] = "true"
		} else {
			o["cascade"] = "false"
		}
	}
	return o
}

// applyRecord sets the common fields from a permission search record.
func (b *PermissionBase) applyRecord(rec Params) {
	if g, ok := rec["grantee"].(string); ok && g != "" {
		b.Grantee = g
	}
}

// Permission is implemented by every concrete permission type
// (*DatasourcePermission, *SecretPermission, ...).
type Permission interface {
	// Base returns the common permission settings.
	Base() *PermissionBase
	// GrantOptions returns the complete request payload for a grant or
	// revoke: the common options plus type specific ones such as
	// "grantables" and "object_name".
	GrantOptions() Params
}

// GrantResult is the server response to a grant or revoke.
type GrantResult struct {
	Result []string
}

// Grant grants p to p.Base().Grantee.
func (s *PermissionService) Grant(ctx context.Context, p Permission) (*GrantResult, error) {
	return s.send(ctx, http.MethodPost, p)
}

// Revoke revokes p from p.Base().Grantee.
func (s *PermissionService) Revoke(ctx context.Context, p Permission) (*GrantResult, error) {
	return s.send(ctx, http.MethodDelete, p)
}

func (s *PermissionService) send(ctx context.Context, method string, p Permission) (*GrantResult, error) {
	grantee := p.Base().Grantee
	if grantee == "" {
		return nil, fmt.Errorf("mamori: permission has no grantee")
	}
	raw, err := s.client.Call(ctx, method, "/v1/grantee/"+pathEscape(strings.ToLower(grantee)), p.GrantOptions())
	if err != nil {
		return nil, err
	}
	var result []string
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("mamori: unexpected grant response %s: %w", raw, err)
	}
	for _, r := range result {
		if strings.Contains(strings.ToLower(r), "error") {
			return &GrantResult{Result: result}, fmt.Errorf("mamori: %s", strings.Join(result, "; "))
		}
	}
	return &GrantResult{Result: result}, nil
}

// RevokeByID revokes a granted permission by its id.
func (s *PermissionService) RevokeByID(ctx context.Context, id int64) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, fmt.Sprintf("/v1/permissions/granted/%d", id), nil)
}

// List searches granted permissions. If grantee is non-empty only that
// grantee's permissions are returned. Non-admins only see their own
// permissions.
func (s *PermissionService) List(ctx context.Context, grantee string, filter Filters) (*SearchResult[Params], error) {
	path := "/v1/search/grantee_permissions"
	if grantee != "" {
		path += "?grantee=" + pathEscape(strings.ToLower(grantee))
	}
	payload := Params{}
	if f := filter.encode(); f != nil {
		payload["filter"] = f
	}
	var res SearchResult[Params]
	if err := s.client.CallInto(ctx, http.MethodPut, path, payload, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListPermissions searches granted permissions and converts each record into
// its concrete [Permission] type (see [PermissionFromRecord]).
func (s *PermissionService) ListPermissions(ctx context.Context, grantee string, filter Filters) ([]Permission, error) {
	res, err := s.List(ctx, grantee, filter)
	if err != nil {
		return nil, err
	}
	out := make([]Permission, 0, len(res.Data))
	for _, rec := range res.Data {
		p, err := PermissionFromRecord(rec)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
