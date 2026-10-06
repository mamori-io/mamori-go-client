package mamori

import (
	"context"
	"encoding/json"
	"net/http"
)

// IPResource is a named network range (CIDR and ports) that can be granted.
type IPResource struct {
	Name string `json:"name"`
	// CIDR is the address range, e.g. "10.0.200.0/24".
	CIDR string `json:"cidr"`
	// Ports is a comma separated port list, e.g. "443,80".
	Ports string `json:"ports"`
}

// ipResourceSearchParams builds the paging payload used by the
// /v1/ip_resources and /v1/wireguard endpoints: several filters are sent in
// indexed form, a single filter as a one element list.
func ipResourceSearchParams(opts SearchOptions) Params {
	p := Params{"skip": opts.Skip, "take": opts.Take}
	switch {
	case len(opts.Filter) > 1:
		p["filter"] = opts.Filter.encode()
	case len(opts.Filter) == 1:
		p["filter"] = []any{opts.Filter[0].toArray()}
	}
	return p
}

// List searches IP resources.
func (s *IPResourceService) List(ctx context.Context, opts SearchOptions) (*SearchResult[IPResource], error) {
	var res SearchResult[IPResource]
	if err := s.client.CallInto(ctx, http.MethodGet, "/v1/ip_resources", ipResourceSearchParams(opts), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Create creates the IP resource.
func (s *IPResourceService) Create(ctx context.Context, r *IPResource) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, "/v1/ip_resources", Params{"resource": r})
}

// Delete deletes the named IP resource.
func (s *IPResourceService) Delete(ctx context.Context, name string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodDelete, "/v1/ip_resources/"+pathEscape(name), nil)
}

// Update updates the IP resource currently named name with the CIDR and
// ports of data, renaming it if data.Name differs from name.
func (s *IPResourceService) Update(ctx context.Context, name string, data *IPResource) (json.RawMessage, error) {
	rec := Params{"cidr": data.CIDR, "ports": data.Ports}
	if data.Name != name {
		rec["name"] = data.Name
	}
	return s.client.Call(ctx, http.MethodPut, "/v1/ip_resources/"+pathEscape(name), Params{"resource": rec})
}
