package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// RequestableResourceType is the kind of resource that can be requested
// through an on-demand policy.
type RequestableResourceType string

// Requestable resource types.
const (
	RequestableResourceTypeDatasource    RequestableResourceType = "DATASOURCE"
	RequestableResourceTypeHTTPResource  RequestableResourceType = "HTTP RESOURCE"
	RequestableResourceTypeRemoteDesktop RequestableResourceType = "REMOTE DESKTOP"
	RequestableResourceTypeSecret        RequestableResourceType = "SECRET"
	RequestableResourceTypeIPResource    RequestableResourceType = "IP RESOURCE"
	RequestableResourceTypeSSHLogin      RequestableResourceType = "SSH LOGIN"
	RequestableResourceTypeEncryptionKey RequestableResourceType = "ENCRYPTION KEY"
	RequestableResourceTypeResourceGroup RequestableResourceType = "RESOURCE GROUP"
	RequestableResourceTypeScript        RequestableResourceType = "SCRIPT"
	RequestableResourceTypeScriptFlow    RequestableResourceType = "SCRIPT FLOW"
)

// DefaultPrivileges returns the privileges granted by default when a
// resource of this type is requested.
func (t RequestableResourceType) DefaultPrivileges() string {
	switch t {
	case RequestableResourceTypeDatasource:
		return "CREDENTIAL USAGE"
	case RequestableResourceTypeHTTPResource:
		return "HTTP ACCESS"
	case RequestableResourceTypeRemoteDesktop:
		return "RDP"
	case RequestableResourceTypeSecret:
		return "REVEAL SECRET"
	case RequestableResourceTypeIPResource:
		return "IP USAGE"
	case RequestableResourceTypeSSHLogin:
		return "SSH,SFTP"
	case RequestableResourceTypeEncryptionKey:
		return "KEY USAGE"
	case RequestableResourceTypeScript:
		return "EXECUTE SCRIPT"
	case RequestableResourceTypeScriptFlow:
		return "EXECUTE SCRIPT FLOW"
	}
	return ""
}

// RequestableResource makes a resource requestable by a grantee through an
// on-demand policy.
type RequestableResource struct {
	ID            string                  `json:"id,omitempty"`
	ResourceType  RequestableResourceType `json:"resource_type"`
	ResourceLogin string                  `json:"resource_login"`
	ResourceName  string                  `json:"resource_name"`
	Grantee       string                  `json:"grantee"`
	Privileges    string                  `json:"privileges"`
	PolicyName    string                  `json:"policy_name"`
	Description   string                  `json:"description"`
}

// NewRequestableResource returns an empty requestable resource of the given
// type.
func NewRequestableResource(typ RequestableResourceType) *RequestableResource {
	return &RequestableResource{ResourceType: typ}
}

// UnmarshalJSON decodes a record whose id may be a number or a string.
func (r *RequestableResource) UnmarshalJSON(data []byte) error {
	type plain RequestableResource
	var rec struct {
		plain
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return err
	}
	*r = RequestableResource(rec.plain)
	r.ID = ""
	if len(rec.ID) > 0 && string(rec.ID) != "null" {
		var s string
		if json.Unmarshal(rec.ID, &s) == nil {
			r.ID = s
		} else {
			r.ID = strings.TrimSpace(string(rec.ID))
		}
	}
	return nil
}

func (r *RequestableResource) payload() Params {
	return Params{
		"resource_type":  r.ResourceType,
		"resource_login": r.ResourceLogin,
		"resource_name":  r.ResourceName,
		"grantee":        r.Grantee,
		"privileges":     r.Privileges,
		"policy_name":    r.PolicyName,
		"description":    r.Description,
	}
}

// RequestableResourceQuery selects requestable resources by exact match;
// empty fields are ignored.
type RequestableResourceQuery struct {
	Type     RequestableResourceType
	Grantee  string
	Resource string
	Policy   string
	Login    string
}

func (q RequestableResourceQuery) filters() Filters {
	var fs Filters
	add := func(col, v string) {
		if v != "" {
			fs = append(fs, F(col, FilterEqualsString, v))
		}
	}
	add("resource_type", string(q.Type))
	add("grantee", q.Grantee)
	add("resource_name", q.Resource)
	add("policy_name", q.Policy)
	add("resource_login", q.Login)
	return fs
}

// List searches requestable resources.
func (s *RequestableResourceService) List(ctx context.Context, opts SearchOptions) (*SearchResult[RequestableResource], error) {
	var res SearchResult[RequestableResource]
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/requestable_resources", opts.params(), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListFor searches requestable resources matching q.
func (s *RequestableResourceService) ListFor(ctx context.Context, skip, take int, q RequestableResourceQuery) (*SearchResult[RequestableResource], error) {
	p := Params{"skip": skip, "take": take}
	if f := q.filters().GridFilter(); f != nil {
		p["filter"] = f
	}
	var res SearchResult[RequestableResource]
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/requestable_resources", p, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetByName returns the first requestable resource matching q, or
// [ErrNotFound].
func (s *RequestableResourceService) GetByName(ctx context.Context, q RequestableResourceQuery) (*RequestableResource, error) {
	res, err := s.ListFor(ctx, 0, 5, q)
	if err != nil {
		return nil, err
	}
	if len(res.Data) == 0 {
		return nil, fmt.Errorf("mamori: requestable resource %q: %w", q.Resource, ErrNotFound)
	}
	return &res.Data[0], nil
}

// DeleteByName deletes the first requestable resource matching q and returns
// it, or returns [ErrNotFound].
func (s *RequestableResourceService) DeleteByName(ctx context.Context, q RequestableResourceQuery) (*RequestableResource, error) {
	r, err := s.GetByName(ctx, q)
	if err != nil {
		return nil, err
	}
	if _, err := s.Delete(ctx, r.ID); err != nil {
		return nil, err
	}
	return r, nil
}

// Create creates the requestable resource. If r.Privileges is empty it is
// set to the type's default privileges first.
func (s *RequestableResourceService) Create(ctx context.Context, r *RequestableResource) (json.RawMessage, error) {
	if r.Privileges == "" {
		r.Privileges = r.ResourceType.DefaultPrivileges()
	}
	return s.client.Call(ctx, http.MethodPost, "/v1/requestable_resources", r.payload())
}

// Update saves the requestable resource r.ID.
func (s *RequestableResourceService) Update(ctx context.Context, r *RequestableResource) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPut, "/v1/requestable_resources/"+pathEscape(r.ID), r.payload())
}

// Delete deletes the requestable resource with the given id.
func (s *RequestableResourceService) Delete(ctx context.Context, id string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/requestable_resources/"+pathEscape(id), nil)
}
