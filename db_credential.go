package mamori

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// DBCredential is a database credential (login) stored for a datasource and
// granted to a user, a role or everyone ("@").
type DBCredential struct {
	// Datasource is the datasource (system) name.
	Datasource string `json:"systemname"`
	// Username is the database login name.
	Username            string `json:"accessname"`
	ValidFrom           any    `json:"valid_from"`
	ValidUntil          any    `json:"valid_until"`
	CredentialResetDays any    `json:"credential_reset_days"`
	NextCredentialReset any    `json:"next_credential_reset"`
	IsManaged           any    `json:"is_managed"`
	RequestVia          any    `json:"request_via"`
	AuthID              any    `json:"auth_id"`
	AuthStatus          any    `json:"auth_status"`
	UID                 any    `json:"uid"`
	// Grantee is the user or role holding the credential; "@" for everyone.
	Grantee     string `json:"grantee"`
	GranteeType any    `json:"granteetype"`
	AccessType  any    `json:"accesstype"`
	// Password is only set by [DBCredentialService.ExportByName] (the
	// encrypted export blob) or by the caller before Restore.
	Password string `json:"password,omitempty"`
}

// NewDBCredential returns a credential for datasource/username granted to
// everyone ("@").
func NewDBCredential(datasource, username string) *DBCredential {
	return &DBCredential{Datasource: datasource, Username: username, Grantee: "@", IsManaged: false, CredentialResetDays: ""}
}

// UnmarshalJSON decodes a credential record, accepting the search aliases
// "datasource" and "remoteusername" for systemname and accessname.
func (c *DBCredential) UnmarshalJSON(b []byte) error {
	type plain DBCredential
	aux := struct {
		*plain
		AltDatasource *string `json:"datasource"`
		AltUsername   *string `json:"remoteusername"`
		Password      any     `json:"password"`
	}{plain: (*plain)(c)}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		return err
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	missing := func(k string) bool { v, ok := probe[k]; return !ok || string(v) == "null" }
	if missing("systemname") && aux.AltDatasource != nil {
		c.Datasource = *aux.AltDatasource
	}
	if missing("accessname") && aux.AltUsername != nil {
		c.Username = *aux.AltUsername
	}
	if p, ok := aux.Password.(string); ok {
		c.Password = p
	}
	return nil
}

func dbCredentialResetDays(v any) any {
	if v == nil {
		return ""
	}
	return v
}

// List searches datasource credentials.
func (s *DBCredentialService) List(ctx context.Context, opts SearchOptions) ([]*DBCredential, error) {
	var res SearchResult[*DBCredential]
	if err := s.client.CallInto(ctx, http.MethodPut, "/v1/search/datasource-credentials", opts.params(), &res); err != nil {
		return nil, err
	}
	return res.Data, nil
}

// ListFor searches credentials by datasource, login name and grantee. Empty
// arguments are not filtered on.
func (s *DBCredentialService) ListFor(ctx context.Context, skip, take int, datasource, username, grantee string) ([]*DBCredential, error) {
	var f Filters
	if datasource != "" {
		f = append(f, F("datasource", FilterEqualsString, datasource))
	}
	if grantee != "" {
		f = append(f, F("grantee", FilterEqualsString, grantee))
	}
	if username != "" {
		f = append(f, F("remoteusername", FilterEqualsString, username))
	}
	return s.List(ctx, SearchOptions{Skip: skip, Take: take, Filter: f})
}

// GetByName returns the credential for datasource/username/grantee, or
// ErrNotFound.
func (s *DBCredentialService) GetByName(ctx context.Context, datasource, username, grantee string) (*DBCredential, error) {
	list, err := s.ListFor(ctx, 0, 5, datasource, username, grantee)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("mamori: datasource credential %s@%s for %s: %w", username, datasource, grantee, ErrNotFound)
	}
	return list[0], nil
}

// ExportByName looks up a credential and exports its password encrypted
// with the AES key keyName into the returned credential's Password field.
func (s *DBCredentialService) ExportByName(ctx context.Context, datasource, username, grantee, keyName string) (*DBCredential, error) {
	cred, err := s.GetByName(ctx, datasource, username, grantee)
	if err != nil {
		return nil, err
	}
	pw, err := s.ExportPassword(ctx, cred, keyName)
	if err != nil {
		return nil, err
	}
	cred.Password = pw
	return cred, nil
}

// DeleteByName deletes the credential for datasource/username/grantee and
// returns it, or ErrNotFound.
func (s *DBCredentialService) DeleteByName(ctx context.Context, datasource, username, grantee string) (*DBCredential, error) {
	cred, err := s.GetByName(ctx, datasource, username, grantee)
	if err != nil {
		return nil, err
	}
	if _, err := s.Delete(ctx, cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// Create stores the credential with the given database password.
func (s *DBCredentialService) Create(ctx context.Context, c *DBCredential, password string) (json.RawMessage, error) {
	return s.client.Call(ctx, http.MethodPost, "/v1/grantee/"+pathEscape(c.Grantee)+"/datasource_authorization", Params{
		"datasource": c.Datasource,
		"username":   c.Username,
		"password":   password,
		"reset_days": dbCredentialResetDays(c.CredentialResetDays),
	})
}

// Restore restores the credential from the encrypted export blob in
// c.Password (see [DBCredentialService.ExportByName]) using the AES key
// keyName. Reset days and validity are not restored.
func (s *DBCredentialService) Restore(ctx context.Context, c *DBCredential, keyName string) (json.RawMessage, error) {
	return s.client.CallProcedure(ctx, "RESTORE_DATASOURCE_CREDENTIAL_EX", c.Datasource, c.Username, c.Grantee, c.Password, keyName)
}

// Delete deletes the credential.
func (s *DBCredentialService) Delete(ctx context.Context, c *DBCredential) (json.RawMessage, error) {
	g := c.Grantee
	if g == "@" {
		g = `"@"`
	}
	return s.client.Call(ctx, http.MethodDelete, "/v1/grantee/"+pathEscape(g)+"/datasource_authorization", Params{
		"datasource": c.Datasource,
		"username":   c.Username,
	})
}

// ExportPassword returns the credential's password encrypted with the AES
// key keyName, or "" if the server returned none.
func (s *DBCredentialService) ExportPassword(ctx context.Context, c *DBCredential, keyName string) (string, error) {
	sql := "call export_credential('__DATASOURCE__', '__LOGINNAME__', '__GRANTEE__', '__KEY__')"
	sql = strings.Replace(sql, "__DATASOURCE__", SQLEscape(c.Datasource), 1)
	sql = strings.Replace(sql, "__LOGINNAME__", SQLEscape(c.Username), 1)
	sql = strings.Replace(sql, "__GRANTEE__", SQLEscape(c.Grantee), 1)
	sql = strings.Replace(sql, "__KEY__", SQLEscape(keyName), 1)
	row, err := firstRow(s.client.Select(ctx, sql))
	if err != nil || row == nil {
		return "", err
	}
	if v, ok := row["value"].(string); ok {
		return v, nil
	}
	return "", nil
}
