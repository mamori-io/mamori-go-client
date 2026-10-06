package mamori

import (
	"context"
	"encoding/json"
	"net/http"
)

//
// Datasources, databases, catalogs, schemas and tables
//

// DatabasesFiltered lists databases. conditions is a pre-built query string
// (without the leading "?") appended verbatim.
func (c *Client) DatabasesFiltered(ctx context.Context, conditions string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/objects/databases?"+conditions, nil)
}

// DatabasesPrivileges returns database privileges. params (may be nil) are
// sent as query parameters.
func (c *Client) DatabasesPrivileges(ctx context.Context, params any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/objects/databases/privileges", params)
}

// Databases lists the databases of all datasources.
func (c *Client) Databases(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/objects/databases", nil)
}

// GetCatalogs lists catalogs.
func (c *Client) GetCatalogs(ctx context.Context) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/catalogs", nil)
}

// DatabaseValidateLogin validates login options against a datasource.
func (c *Client) DatabaseValidateLogin(ctx context.Context, systemName string, options any) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodPut, "/v1/objects/databases/"+pathEscape(systemName)+"/validate", options)
}

// Schemas lists the schemas of a datasource.
func (c *Client) Schemas(ctx context.Context, systemName string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/objects/databases/"+pathEscape(systemName), nil)
}

// DatabaseSchemas lists the schemas of one database of a datasource.
func (c *Client) DatabaseSchemas(ctx context.Context, systemName, databaseName string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/objects/databases/"+pathEscape(systemName)+"?database="+pathEscape(databaseName), nil)
}

// GetTablesBySystemSchema lists the tables of a datasource schema.
func (c *Client) GetTablesBySystemSchema(ctx context.Context, systemName, schema string) (json.RawMessage, error) {
	return c.Call(ctx, http.MethodGet, "/v1/objects/system/"+pathEscape(systemName)+"/schemas/"+pathEscape(schema)+"/tables", nil)
}
