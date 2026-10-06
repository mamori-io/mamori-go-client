package mamori

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
)

// HTTPResource is a web resource proxied by mamori.
//
// A Port of 0 means any port (the TypeScript SDK's "*").
type HTTPResource struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Description    string `json:"description"`
	UpdatedAt      string `json:"updated_at"`
	CreatedAt      string `json:"created_at"`
	ActiveAccess   string `json:"active_access"`
	RequestVia     any    `json:"request_via"`
	ExcludeFromPAC bool   `json:"exclude_from_pac"`
	RecordSession  bool   `json:"record_session"`
}

// UnmarshalJSON decodes an HTTP resource record, tolerating numeric ids and
// string ports ("*" decodes as 0).
func (r *HTTPResource) UnmarshalJSON(b []byte) error {
	return looseUnmarshal(b, r)
}

var httpResourceURLPattern = regexp.MustCompile(`(https?)://([^:/]+):?([0-9]*).*`)

// SetURL sets the resource URL and derives Host and Port from it (port 80
// or 443 by default, depending on the scheme).
func (r *HTTPResource) SetURL(u string) {
	r.URL = u
	m := httpResourceURLPattern.FindStringSubmatch(u)
	if m == nil {
		return
	}
	r.Host = m[2]
	switch {
	case m[3] != "":
		r.Port, _ = strconv.Atoi(m[3])
	case m[1] == "http":
		r.Port = 80
	default:
		r.Port = 443
	}
}

// queryParams returns the SQL argument list for add/update_http_resource.
func (r *HTTPResource) queryParams() string {
	return sqlQuote(r.Name) + ", " + sqlQuote(r.Host) + ", " + strconv.Itoa(r.Port) + ", " +
		sqlQuote(r.URL) + ", " + sqlQuote(r.Description) + "," +
		strconv.FormatBool(r.ExcludeFromPAC) + ", " + strconv.FormatBool(r.RecordSession)
}

// List searches HTTP resources.
func (s *HTTPResourceService) List(ctx context.Context, opts SearchOptions) (*SearchResult[HTTPResource], error) {
	var res SearchResult[HTTPResource]
	if err := s.client.CallInto(ctx, http.MethodPut, "/v1/search/web_resources", opts.params(), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetByName returns the named HTTP resource, or ErrNotFound.
func (s *HTTPResourceService) GetByName(ctx context.Context, name string) (*HTTPResource, error) {
	res, err := s.List(ctx, SearchOptions{Skip: 0, Take: 5, Filter: Filters{F("name", FilterEquals, name)}})
	if err != nil {
		return nil, err
	}
	if len(res.Data) == 0 {
		return nil, fmt.Errorf("mamori: http resource %q: %w", name, ErrNotFound)
	}
	return &res.Data[0], nil
}

// Create creates the HTTP resource and returns the first result row.
func (s *HTTPResourceService) Create(ctx context.Context, r *HTTPResource) (Row, error) {
	return firstRow(s.client.Select(ctx, "call add_http_resource("+r.queryParams()+")"))
}

// Delete deletes the named HTTP resource and returns the first result row.
func (s *HTTPResourceService) Delete(ctx context.Context, name string) (Row, error) {
	return firstRow(s.client.Select(ctx, "call delete_http_resource("+sqlQuote(name)+")"))
}

// Update updates the HTTP resource identified by r.ID and returns the first
// result row.
func (s *HTTPResourceService) Update(ctx context.Context, r *HTTPResource) (Row, error) {
	if r.ID == "" {
		return nil, fmt.Errorf("mamori: http resource %q has no id", r.Name)
	}
	if err := checkSQLNumber(r.ID); err != nil {
		return nil, err
	}
	return firstRow(s.client.Select(ctx, "call update_http_resource("+r.ID+", "+r.queryParams()+")"))
}

// GrantTo grants access to the named HTTP resource to grantee.
func (s *HTTPResourceService) GrantTo(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Grant(ctx, NewHTTPResourcePermission(name, grantee))
	return err
}

// RevokeFrom revokes access to the named HTTP resource from grantee.
func (s *HTTPResourceService) RevokeFrom(ctx context.Context, name, grantee string) error {
	_, err := s.client.Permissions.Revoke(ctx, NewHTTPResourcePermission(name, grantee))
	return err
}
